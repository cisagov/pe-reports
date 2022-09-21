"""Link sub-domains and IPs from IP lookups."""
# Standard Python Libraries
import datetime
import threading
import time
import logging

# Third-Party Libraries
import numpy as np
import pandas as pd
import requests

# cisagov Libraries
from pe_reports.data.db_query import connect
from pe_reports.data.config import whois_xml_api_key


def reverseLookup(ip, failed_ips):
    """Take an ip and find all associated subdomains."""
    # TODO: Add API key
    api = whois_xml_api_key()
    url = f"https://dns-history.whoisxmlapi.com/api/v1?apiKey={api}&ip={ip}"
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
                failed_ips.append(ip)
    found_domains = []
    try:
        try:
            # Update last_reverse_lookup field
            conn = connect()
            cur = conn.cursor()
            date = datetime.datetime.today().strftime("%Y-%m-%d")
            sql = """update ips set last_reverse_lookup = %s
            where ip = %s;"""
            cur.execute(sql, (date, str(ip)))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print("failed to update timestamp field")
            print(e)
        if response["size"] > 0:

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
        print(response)
        print("failed to return response")
        print(e)
    return found_domains


def query_ips(org_uid):
    """Query all ips that link to a cidr related to a specific org."""
    print(org_uid)
    conn = connect()
    sql = """SELECT i.ip_hash, i.ip, ct.network FROM ips i
            JOIN cidrs ct on ct.cidr_uid = i.origin_cidr
            where ct.organizations_uid = %(org_uid)s
            and i.origin_cidr is not null
            and (i.last_reverse_lookup < current_date - interval '7 days' or i.last_reverse_lookup is null)
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


def link_domain_from_ip(ip_hash, ip, org_uid, data_source, failed_ips):
    """From a provided ip find domains and link them in the db."""
    conn = connect()
    found_domains = reverseLookup(ip, failed_ips)
    for domain in found_domains:
        cur = conn.cursor()
        cur.callproc(
            "link_ips_and_subs",
            (
                ip_hash,
                ip,
                org_uid,
                domain["sub_domain"],
                data_source,
                None,
                domain["root"],
            ),
        )
        row = cur.fetchone()
        print(row)
        conn.commit()
        cur.close()
    return 1


def run_ip_chunk(org, ips, thread):
    """Run the provided chunk through the linking process."""
    org_uid = org["organizations_uid"]
    count = 0
    start_time = time.time()
    last_50 = time.time()
    failed_ips = []
    for ip_index, ip in ips.iterrows():
        count += 1
        if count % 50 == 0:
            logging.info(f"{thread} Currently Running ips: {count}/{len(ips)}")
            logging.info(
                f"{thread} {time.time() - last_50} seconds for the last 50 IPs"
            )
            last_50 = time.time()
        try:
            link_domain_from_ip(
                ip["ip_hash"], ip["ip"], org_uid, "WhoisXML", failed_ips
            )
        except requests.exceptions.SSLError as e:
            logging.error(e)
            time.sleep(1)
            continue
    logging.info(f"{thread} Ips took {time.time() - start_time} to link to subs")


def connect_subs_from_ips(orgs):
    """For each org find all domains that are associated to an ip and create link in the ip_subs table."""
    for org_index, org in orgs.iterrows():
        print(f"Running on {org['name']}")
        org_uid = org["organizations_uid"]
        ips = query_ips(org_uid)
        print(ips)
        # run_ip_chunk(org,ips,"")
        num_chunks = 8
        ips_split = np.array_split(ips, num_chunks)

        x = 0
        thread_list = []
        while x < len(ips_split):
            thread_name = f"Thread {x+1}: "
            # Start thread
            t = threading.Thread(
                target=run_ip_chunk, args=(org, ips_split[x], thread_name)
            )
            t.start()
            thread_list.append(t)
            x += 1

        for thread in thread_list:
            thread.join()

        print("All threads have finished.")
