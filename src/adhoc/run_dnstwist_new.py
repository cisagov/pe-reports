from copy import copy
import os
import traceback
import psycopg2
import psycopg2.extras as extras
import requests
import socket
from data.run import query_orgs_rev
import pandas as pd
import dshield
import json
import datetime
import time
import subprocess


date = datetime.datetime.now().strftime("%Y-%m-%d")


def query_db(conn, query, args=(), one=False):
    cur = conn.cursor()
    cur.execute(query, args)
    r = [
        dict((cur.description[i][0], value) for i, value in enumerate(row))
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
    print(f"Success adding root domain, {root_domain}, to root domain table.")


def addSubdomain(conn, domain, pe_org_uid, org_name):
    root_domain = domain.split(".")[-2:]
    root_domain = ".".join(root_domain)
    cur = conn.cursor()
    cur.callproc(
        "insert_sub_domain", (domain, pe_org_uid, "findomain", root_domain, None)
    )
    print(f"Success adding domain, {domain}, to subdomains table.")


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


# TODO: Add creds
DB_HOST = ""
PE_DB_NAME = ""
PE_DB_USERNAME = ""
PE_DB_PASSWORD = ""

"""Connect to PE Database"""
try:
    PE_conn = psycopg2.connect(
        host=DB_HOST,
        database=PE_DB_NAME,
        user=PE_DB_USERNAME,
        password=PE_DB_PASSWORD,
    )
    print("Connected to PE database.")
except:
    print("Failed connecting to PE database.")


# Get data source
source_uid = getDataSource(PE_conn, "DNSTwist")[0]
# source_uid = '7ad1b168-981d-11ec-a102-02589a36c9d7'
print("source_uid")
print(source_uid)

""" Get P&E Orgs """
orgs = query_orgs_rev()
print(orgs["name"])

for org_index, org_row in orgs.iterrows():
    pe_org_uid = org_row["organizations_uid"]
    org_name = org_row["name"]

    # if org_name not in ["National Institute of Standards and Technology"]:
    #     continue

    print(pe_org_uid)
    print(org_name)
    if org_name != "Department of Homeland Security":
        continue

    """Collect DNSTwist data from Crossfeed"""
    try:
        # Get root domains
        rd_df = org_root_domains(PE_conn, pe_org_uid)
        print(rd_df)
        domain_list = []
        perm_list = []
        for rd_index, rd_row in rd_df.iterrows():
            root_domain = rd_row["root_domain"]
            if root_domain != "dhs.gov":
                continue
            if root_domain == "Null_Root":
                continue
            print(rd_row["root_domain"])

            # Run dnstwist on each root domain
            cmd = f"dnstwist -r --tld common_tlds.dict -f json {root_domain} -t 8"
            dnstwist_result = json.loads(subprocess.check_output(cmd, shell=True))
            finalorglist = dnstwist_result + []
            for dom in dnstwist_result:
                if ("tld-swap" not in dom["fuzzer"]) and (
                    "original" not in dom["fuzzer"]
                ):
                    print(dom["domain"])
                    cmd = f'dnstwist -r --tld common_tlds.dict -f json {dom["domain"]} -t 8'
                    secondlist = json.loads(subprocess.check_output(cmd, shell=True))
                    finalorglist += secondlist

            print(dnstwist_result)

            # Get subdomain uid
            sub_domain = root_domain
            print(sub_domain)
            try:
                sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]
                print(sub_domain_uid)
            except:
                # Add and then get it
                addSubdomain(PE_conn, sub_domain, pe_org_uid, org_name)
                sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]

            for dom in dnstwist_result:
                malicious = False
                attacks = 0
                reports = 0
                if "original" in dom["fuzzer"]:
                    print("original")
                    print(dom["fuzzer"])
                    continue
                if "dns_a" not in dom:
                    continue
                else:
                    print(str(dom["dns_a"][0]))
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

                    results = dshield.ip(
                        str(dom["dns_a"][0]), return_format=dshield.JSON
                    )
                    results = json.loads(results)
                    try:
                        threats = results["ip"]["threatfeeds"]
                        attacks = results["ip"]["attacks"]
                        attacks = int(0 if attacks is None else attacks)
                        malicious = True
                        dshield_attacks = attacks
                        dshield_count = len(threats)
                    except KeyError:
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
                    print(str(dom["dns_aaaa"][0]))
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
                    results = dshield.ip(
                        str(dom["dns_aaaa"][0]), return_format=dshield.JSON
                    )
                    results = json.loads(results)

                    try:
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
                print(permutation)
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
        print("Failed selecting DNSTwist data.")
        print(traceback.format_exc())
    """Insert cleaned data into PE database."""
    try:
        cursor = PE_conn.cursor()
        columns = domain_list[0].keys()
        table = "domain_permutations"
        sql = """INSERT INTO %s(%s) VALUES %%s 
        ON CONFLICT (domain_permutation,organizations_uid) 
        DO UPDATE SET malicious = EXCLUDED.malicious,
            blocklist_attack_count = EXCLUDED.blocklist_attack_count,
            blocklist_report_count = EXCLUDED.blocklist_report_count,
            dshield_record_count = EXCLUDED.dshield_record_count,
            dshield_attack_count = EXCLUDED.dshield_attack_count,
            data_source_uid = EXCLUDED.data_source_uid,
            date_active = EXCLUDED.date_active;""" % (
            table,
            ",".join(columns),
        )
        values = [[value for value in dict.values()] for dict in domain_list]
        extras.execute_values(cursor, sql, values)
        PE_conn.commit()
        print("Data inserted using execute_values() successfully..")

    except:
        print("Failure inserting data into database.")
        print(traceback.format_exc())


PE_conn.close()
