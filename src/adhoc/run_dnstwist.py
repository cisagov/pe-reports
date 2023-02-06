# Standard Python Libraries
import datetime
import json
from json.decoder import JSONDecodeError
import logging
import os
import socket
import subprocess
import time
import traceback

# Third-Party Libraries
from data.run import query_orgs_rev, connect
import dshield
import pandas as pd
import psycopg2
import psycopg2.extras as extras
import requests

date = datetime.datetime.now().strftime("%Y-%m-%d")
CENTRAL_LOGGING_FILE = "pe_reports_logging.log"
DEBUG = False
# Setup Logging
"""Set up logging and call the run_pe_script function."""
if DEBUG is True:
    level = "DEBUG"
else:
    level = "INFO"

logging.basicConfig(
    filename=CENTRAL_LOGGING_FILE,
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=level,
)
LOGGER = logging.getLogger(__name__)


def query_db(conn, query, args=(), one=False):
    cur = conn.cursor()
    cur.execute(query, args)
    r = [
        {cur.description[i][0]: value for i, value in enumerate(row)}
        for row in cur.fetchall()
    ]

    return (r[0] if r else None) if one else r


def getSubdomain(conn, domain):
    cur = conn.cursor()
    sql = f"""SELECT * FROM sub_domains sd
        WHERE sd.sub_domain = '{domain}'"""
    cur.execute(sql)
    sub = cur.fetchone()
    cur.close()
    return sub


def getRootdomain(conn, domain):
    cur = conn.cursor()
    sql = f"""SELECT * FROM root_domains rd
        WHERE rd.root_domain = '{domain}'"""
    cur.execute(sql)
    root = cur.fetchone()
    cur.close()
    return root


def addRootdomain(conn, root_domain, pe_org_uid, source_uid, org_name):
    ip_address = str(socket.gethostbyname(root_domain))
    sql = f"""insert into root_domains(root_domain, organizations_uid, organization_name, data_source_uid, ip_address)
            values ('{root_domain}', '{pe_org_uid}', '{org_name}', '{source_uid}', '{ip_address}');"""
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    cur.close()
    LOGGER.info(f"Success adding root domain, {root_domain}, to root domain table.")


def addSubdomain(conn, domain, pe_org_uid, org_name):
    root_domain = domain.split(".")[-2:]
    root_domain = ".".join(root_domain)
    cur = conn.cursor()
    cur.callproc(
        "insert_sub_domain", (domain, pe_org_uid, "findomain", root_domain, None)
    )
    LOGGER.info(f"Success adding domain, {domain}, to subdomains table.")


def getDataSource(conn, source):
    cur = conn.cursor()
    sql = f"""SELECT * FROM data_source WHERE name='{source}'"""
    cur.execute(sql)
    source = cur.fetchone()
    cur.close()
    return source


def org_root_domains(conn, org_uid):
    sql = """
        select * from root_domains rd
        where rd.organizations_uid = %(org_id)s;
    """
    df = pd.read_sql_query(sql, conn, params={"org_id": org_uid})
    return df


"""Connect to PE Database"""
try:
    PE_conn = connect("")
except:
    LOGGER.error("Failed connecting to PE database.")


# Get data source
source_uid = getDataSource(PE_conn, "DNSTwist")[0]


""" Get P&E Orgs """

orgs = query_orgs_rev()
LOGGER.info(orgs["name"])
for org_index, org_row in orgs.iterrows():
    pe_org_uid = org_row["organizations_uid"]
    org_name = org_row["name"]

    # if org_name not in ["Federal Aviation Administration"]:
    #     continue

    LOGGER.info(pe_org_uid)
    LOGGER.info(org_name)

    """Collect DNSTwist data from Crossfeed"""
    try:
        # Get root domains
        rd_df = org_root_domains(PE_conn, pe_org_uid)
        LOGGER.info(rd_df)
        domain_list = []
        perm_list = []
        for rd_index, rd_row in rd_df.iterrows():
            root_domain = rd_row["root_domain"]
            if root_domain == "Null_Root":
                continue
            LOGGER.info(rd_row["root_domain"])

            if not root_domain:
                continue

            # Run dnstwist on each root domain
            cmd = f"dnstwist -r --tld /var/www/pe-reports/src/adhoc/common_tlds.dict -f json {root_domain}"
            dnstwist_result = json.loads(subprocess.check_output(cmd, shell=True))
            # LOGGER.info(dnstwist_result)

            # Get subdomain uid
            sub_domain = root_domain
            LOGGER.info(sub_domain)
            try:
                sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]
                LOGGER.info(sub_domain_uid)
            except:
                # Add and then get it
                addSubdomain(PE_conn, sub_domain, pe_org_uid, org_name)
                sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]

            for dom in dnstwist_result:
                malicious = False
                attacks = 0
                reports = 0
                if "original" in dom["fuzzer"]:
                    continue
                if "dns_a" not in dom:
                    continue
                else:
                    LOGGER.info(str(dom["dns_a"][0]))
                    # check IP in Blocklist API
                    response = requests.get(
                        "http://api.blocklist.de/api.php?ip=" + str(dom["dns_a"][0])
                    ).content

                    if str(response) != "b'attacks: 0<br />reports: 0<br />'":
                        malicious = True
                        attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                        reports = int(str(response).split("reports: ")[1].split("<")[0])

                    # check dns-a record in DSheild API
                    if str(dom["dns_a"][0]) == "!ServFail":
                        continue

                    if str(dom["dns_a"][0]) == "0.0.0.0":
                        continue

                    results = dshield.ip(
                        str(dom["dns_a"][0]), return_format=dshield.JSON
                    )
                    try:
                        results = json.loads(results)
                        threats = results["ip"]["threatfeeds"]
                        attacks = results["ip"]["attacks"]
                        attacks = int(0 if attacks is None else attacks)
                        malicious = True
                        dshield_attacks = attacks
                        dshield_count = len(threats)
                    except KeyError:
                        dshield_attacks = 0
                        dshield_count = 0
                    except JSONDecodeError:
                        dshield_attacks = 0
                        dshield_count = 0

                if "ssdeep_score" not in dom:
                    dom["ssdeep_score"] = ""
                if "dns_mx" not in dom:
                    dom["dns_mx"] = [""]
                if "dns_ns" not in dom:
                    dom["dns_ns"] = [""]
                if "dns_aaaa" not in dom:
                    dom["dns_aaaa"] = [""]
                else:
                    LOGGER.info(str(dom["dns_aaaa"][0]))
                    # check IP in Blocklist API
                    response = requests.get(
                        "http://api.blocklist.de/api.php?ip=" + str(dom["dns_aaaa"][0])
                    ).content
                    if str(response) != "b'attacks: 0<br />reports: 0<br />'":
                        malicious = True
                        attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                        reports = int(str(response).split("reports: ")[1].split("<")[0])

                    # check dns-a record in DSheild API
                    if str(dom["dns_aaaa"][0]) == "!ServFail":
                        continue
                    if str(dom["dns_aaaa"][0]) == "0.0.0.0":
                        continue
                    results = dshield.ip(
                        str(dom["dns_aaaa"][0]), return_format=dshield.JSON
                    )
                    try:
                        results = json.loads(results)
                        threats = results["ip"]["threatfeeds"]
                        attacks = results["ip"]["attacks"]
                        attacks = int(0 if attacks is None else attacks)
                        malicious = True
                        dshield_attacks = attacks
                        dshield_count = len(threats)
                    except KeyError:
                        dshield_attacks = 0
                        dshield_count = 0

                # Ignore duplicates
                permutation = dom["domain"]
                LOGGER.info(permutation)
                if permutation in perm_list:
                    continue
                else:
                    perm_list.append(permutation)

                domain_dict = {
                    "organizations_uid": pe_org_uid,
                    "data_source_uid": source_uid,
                    "sub_domain_uid": sub_domain_uid,
                    "domain_permutation": dom["domain"],
                    "ipv4": dom["dns_a"][0],
                    "ipv6": dom["dns_aaaa"][0],
                    "mail_server": dom["dns_mx"][0],
                    "name_server": dom["dns_ns"][0],
                    "fuzzer": dom["fuzzer"],
                    "date_active": date,
                    "ssdeep_score": dom["ssdeep_score"],
                    "malicious": malicious,
                    "blocklist_attack_count": attacks,
                    "blocklist_report_count": reports,
                    "dshield_record_count": dshield_count,
                    "dshield_attack_count": dshield_attacks,
                }
                domain_list.append(domain_dict)

    except:
        LOGGER.error("Failed selecting DNSTwist data.")
        LOGGER.error(traceback.format_exc())

    """Insert cleaned data into PE database."""
    try:
        cursor = PE_conn.cursor()
        try:
            columns = domain_list[0].keys()
        except Exception as e:
            LOGGER.info(e)
            LOGGER.info("No data")
            continue
        table = "domain_permutations"
        sql = """INSERT INTO {}({}) VALUES %s
        ON CONFLICT (domain_permutation,organizations_uid)
        DO UPDATE SET malicious = EXCLUDED.malicious,
            blocklist_attack_count = EXCLUDED.blocklist_attack_count,
            blocklist_report_count = EXCLUDED.blocklist_report_count,
            dshield_record_count = EXCLUDED.dshield_record_count,
            dshield_attack_count = EXCLUDED.dshield_attack_count,
            data_source_uid = EXCLUDED.data_source_uid,
            date_active = EXCLUDED.date_active;""".format(
            table,
            ",".join(columns),
        )
        values = [[value for value in dict.values()] for dict in domain_list]
        extras.execute_values(cursor, sql, values)
        PE_conn.commit()
        LOGGER.info("Data inserted using execute_values() successfully..")

    except:
        LOGGER.error("Failure inserting data into database.")
        LOGGER.error(traceback.format_exc())

PE_conn.close()
