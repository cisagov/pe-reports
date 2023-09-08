"""Link sub-domains and IPs from IP lookups."""
# Standard Python Libraries
import datetime
import hashlib
import ipaddress
import logging
import threading
import time

# Third-Party Libraries
import numpy as np
import pandas as pd
import requests

# cisagov Libraries
from pe_asm.data.cyhy_db_query import (
    execute_ips,
    pe_db_connect,
    pe_db_staging_connect,
    query_cidrs_by_org,
    query_pe_report_on_orgs,
)
from pe_reports.data.config import whois_xml_api_key

LOGGER = logging.getLogger(__name__)
WHOIS_KEY = whois_xml_api_key()
DATE = datetime.datetime.today().date()


def reverseLookup(ip_obj, failed_ips, conn, thread):
    """Take an ip and find all associated subdomains."""
    # Query WHOisXML
    url = f"https://dns-history.whoisxmlapi.com/api/v1?apiKey={WHOIS_KEY}&ip={ip_obj['ip']}"
    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload).json()
    if response.get("code") == 429:
        response = requests.request("GET", url, headers=headers, data=payload).json()
        if response.get("code") == 429:
            response = requests.request(
                "GET", url, headers=headers, data=payload
            ).json()
            if response.get("code") == 429:
                failed_ips.append(ip_obj["ip"])

    found_domains = []
    try:
        # If there is a response, save domain
        if response["size"] > 0:
            # Insert or update IP
            execute_ips(conn, ip_obj)

            result = response["result"]
            for domain in result:
                print(domain)
                try:
                    found_domains.append(
                        {
                            "sub_domain": domain["name"],
                            "root": ".".join(domain["name"].rsplit(".")[-2:]),
                        }
                    )
                except KeyError:
                    continue

    except Exception as e:
        LOGGER.error(f"{thread}: Failed to return WHOIsXML response")
        LOGGER.error(f"{thread}: {response}")
        LOGGER.error(f"{thread}: {e}")
    return found_domains, failed_ips


def link_domain_from_ip(ip_obj, org_uid, data_source, failed_ips, conn, thread):
    """From a provided ip find domains and link them in the db."""
    # Lookup domains from IP
    found_domains, failed_ips = reverseLookup(ip_obj, failed_ips, conn, thread)
    for domain in found_domains:
        cur = conn.cursor()
        cur.callproc(
            "link_ips_and_subs",
            (
                DATE,
                ip_obj["ip_hash"],
                ip_obj["ip"],
                org_uid,
                domain["sub_domain"],
                data_source,
                None,
                domain["root"],
            ),
        )
        row = cur.fetchone()
        print("Row after procedure")
        print(row)
        conn.commit()
        cur.close()
    return found_domains


def run_ip_chunk(org_uid, ips_df, thread, conn):
    """Run the provided chunk through the linking process."""
    count = 0
    last_100 = time.time()
    failed_ips = []
    for ip_index, ip in ips_df.iterrows():
        # Set up logging for every 100 IPs
        count += 1
        if count % 10000 == 0:
            LOGGER.info(f"{thread}: Currently Running ips: {count}/{len(ips_df)}")
            LOGGER.info(
                f"{thread}: {time.time() - last_100} seconds for the last 50 IPs"
            )
            last_100 = time.time()

        # Link domain from IP
        try:
            link_domain_from_ip(ip, org_uid, "WhoisXML", failed_ips, conn, thread)
        except requests.exceptions.SSLError as e:
            LOGGER.error(e)
            time.sleep(1)
            continue
    # LOGGER.info(f"{thread} Ips took {time.time() - start_time} to link to subs")


def connect_subs_from_ips(staging, orgs_df=None):
    """For each org find all domains that are associated to an ip and create link in the ip_subs table."""
    # Connect to database
    if staging:
        conn = pe_db_staging_connect()
    else:
        conn = pe_db_connect()

    # Get P&E organizations DataFrame
    if not isinstance(orgs_df, pd.DataFrame):
        orgs_df = query_pe_report_on_orgs(conn)
    num_orgs = len(orgs_df.index)

    # Close database connection
    conn.close()

    # Loop through orgs
    org_count = 0
    for org_index, org in orgs_df.iloc[::-1].iterrows():
        # Connect to database
        if staging:
            conn = pe_db_staging_connect()
        else:
            conn = pe_db_connect()
        LOGGER.info(
            "Running on %s. %d/%d complete.", org["cyhy_db_name"], org_count, num_orgs
        )
        # Query IPs
        org_uid = org["organizations_uid"]
        print(org_uid)
        # ips_df = query_ips(org_uid, conn)
        cidrs = query_cidrs_by_org(conn, org_uid)
        ips_list = []
        for cidr_index, cidr in cidrs.itterows():
            for ip in list(ipaddress.IPv4Network(cidr).hosts()):
                hash_object = hashlib.sha256(str(ip).encode("utf-8"))
                ip_obj = {
                    "ip_hash": hash_object.hexdigest(),
                    "ip": str(ip),
                    "origin_cidr": cidr["cidr_uid"],
                    "first_seen": DATE,
                    "last_seen": DATE,
                    "current": True,
                    "from_cidr": True,
                    "last_reverse_lookup": DATE,
                    "organizations_uid": org_uid,
                }
                ips_list.append(ip_obj)
        ips_df = pd.DataFrame(ips_list)

        LOGGER.info("Number of Cidrs: %d", cidrs.index)

        # if no IPS, continue to next org
        if len(ips_df.index) == 0:
            conn.close()
            org_count += 1
            continue

        # Split IPs into 8 threads, then call run_ip_chunk function
        num_chunks = 8
        ips_split = np.array_split(ips_df, num_chunks)
        thread_num = 0
        thread_list = []
        while thread_num < len(ips_split):
            thread_name = f"Thread {thread_num + 1}: "
            # Start thread
            t = threading.Thread(
                target=run_ip_chunk,
                args=(org_uid, ips_split[thread_num], thread_name, conn),
            )
            t.start()
            thread_list.append(t)
            thread_num += 1

        for thread in thread_list:
            thread.join()

        LOGGER.info("All threads have finished.")

        org_count += 1

        conn.close()
