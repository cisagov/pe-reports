"""Run domain masquerading scan."""
# Standard Python Libraries
import datetime
import json
import socket
import traceback

# Third-Party Libraries
from data.run import query_orgs
import dshield
import pandas as pd
import psycopg2
import psycopg2.extras as extras
import requests

date = datetime.datetime.now().strftime("%Y-%m-%d")


def query_db(conn, query, args=(), one=False):
    """Query the database."""
    cur = conn.cursor()
    cur.execute(query, args)
    r = [
        {cur.description[i][0]: value for i, value in enumerate(row)}
        for row in cur.fetchall()
    ]

    return (r[0] if r else None) if one else r


def getSubdomain(conn, domain):
    """Get subdomain."""
    cur = conn.cursor()
    sql = """SELECT * FROM sub_domains sd
        WHERE sd.sub_domain = '{}'"""
    cur.execute(sql.format(domain))
    sub = cur.fetchone()
    cur.close()
    return sub


def getRootdomain(conn, domain):
    """Get root domain."""
    cur = conn.cursor()
    sql = """SELECT * FROM root_domains rd
        WHERE rd.root_domain = '{}'"""
    cur.execute(sql.format(domain))
    root = cur.fetchone()
    cur.close()
    return root


def addRootdomain(conn, root_domain, pe_org_uid, source_uid, org_name):
    """Add root domain."""
    ip_address = str(socket.gethostbyname(root_domain))
    sql = """insert into root_domains(root_domain, organizations_uid, organization_name, data_source_uid, ip_address)
            values ('{}', '{}', '{}', '{}', '{});"""
    cur = conn.cursor()
    cur.execute(sql.format(root_domain, pe_org_uid, org_name, source_uid, ip_address))
    conn.commit()
    cur.close()
    print(f"Success adding root domain, {root_domain}, to root domain table.")


def addSubdomain(conn, domain, pe_org_uid, org_name):
    """Add subdomain."""
    source_uid = getDataSource(conn, "findomain")[0]
    root_domain = domain.split(".")[-2:]
    root_domain = ".".join(root_domain)
    print(root_domain)
    try:
        root_domain_uid = getRootdomain(conn, root_domain)[0]
        print(root_domain_uid)
    except Exception:
        addRootdomain(conn, domain, pe_org_uid, source_uid, org_name)
        root_domain_uid = getRootdomain(conn, root_domain)[0]
    sql = """insert into sub_domains(sub_domain, root_domain_uid, root_domain, data_source_uid)
            values ('{}', '{}', '{}', '{}');"""
    print(sql.format(domain, root_domain_uid, root_domain, source_uid))
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    cur.close()
    print(f"Success adding domain, {domain}, to subdomains table.")


def getDataSource(conn, source):
    """Get data source."""
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name='{}'"""
    cur.execute(sql.format(source))
    source = cur.fetchone()
    cur.close()
    return source


def query_CF_orgs(conn):
    """Query Crossfeed orgs."""
    sql = """select o.name, o.id
            from organization o
            join organization_tag_organizations_organization otoo on otoo."organizationId" = o."id"
            join organization_tag ot on ot.id = otoo."organizationTagId"
            WHERE ot.name = 'P&E'"""
    df = pd.read_sql_query(sql, conn)
    print(df)
    return df


# DB_HOST = ""

# CF_DB_NAME = ""
# CF_DB_USERNAME = ""
# CF_DB_PASSWORD = ""

# PE_DB_NAME = ""
# PE_DB_USERNAME = ""
# PE_DB_PASSWORD = ""

"""Connect to PE Database"""
# TODO: Insert actual db creds
try:
    PE_conn = psycopg2.connect(
        host="DB_HOST",
        database="PE_DB_NAME",
        user="PE_DB_USERNAME",
    )
    print("Connected to PE database.")
except Exception:
    print("Failed connecting to PE database.")

"""Connect to Crossfeed's Database"""
try:
    CF_conn = psycopg2.connect(
        host="DB_HOST",
        database="CF_DB_NAME",
        user="CF_DB_USERNAME",
    )
    print("Connected to Crossfeed's database.")
except Exception:
    print("Failed connecting to Crossfeed's database.")

"""Get Crossfeed orgs"""
cf_orgs_df = query_CF_orgs(CF_conn)
cf_orgs_dict = cf_orgs_df.set_index("name").agg(list, axis=1).to_dict()

""" Get P&E Orgs """
orgs = query_orgs("")
for i, row in orgs.iterrows():
    pe_org_uid = row["organizations_uid"]
    org_name = row["name"]
    # if org_name not in ["Department of Housing and Urban Development"]:
    #     continue
    print(pe_org_uid)
    print(org_name)
    cf_org_id = cf_orgs_dict[org_name][0]
    print(cf_org_id)
    """Collect DNSTwist data from Crossfeed"""
    try:
        sql = """SELECT vuln."structuredData", vuln."domainId", dom."name"
                    FROM domain as dom
                    JOIN vulnerability as vuln
                    ON vuln."domainId" = dom.id
                    WHERE dom."organizationId" ='{}'
                    AND vuln."source" = 'dnstwist'"""
        dnstwist_resp = query_db(CF_conn, sql.format(cf_org_id))

        # Get data source
        source_uid = getDataSource(PE_conn, "DNSTwist")[0]

        domain_list = []
        perm_list = []
        if dnstwist_resp is None:
            print("empty response. Continueing to next org")
            continue
        for row in dnstwist_resp:
            # Get subdomain uid
            sub_domain = row["name"]
            print(sub_domain)
            row = row["structuredData"]["domains"]
            try:
                sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]
            except Exception:
                # Add and then get it
                addSubdomain(PE_conn, sub_domain, pe_org_uid, org_name)
                sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]

            for dom in row:
                malicious = False
                attacks = 0
                reports = 0
                if "original" in dom["fuzzer"]:
                    continue
                if "dns-a" not in dom:
                    continue
                else:
                    print(str(dom["dns-a"][0]))
                    # check IP in Blocklist API
                    response = requests.get(
                        "http://api.blocklist.de/api.php?ip=" + str(dom["dns-a"][0])
                    ).content

                    if str(response) != "b'attacks: 0<br />reports: 0<br />'":
                        malicious = True
                        attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                        reports = int(str(response).split("reports: ")[1].split("<")[0])

                    # check dns-a record in DSheild API
                    if str(dom["dns-a"][0]) == "!ServFail":
                        continue

                    results = dshield.ip(
                        str(dom["dns-a"][0]), return_format=dshield.JSON
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

                if "ssdeep-score" not in dom:
                    dom["ssdeep-score"] = ""
                if "dns-mx" not in dom:
                    dom["dns-mx"] = [""]
                if "dns-ns" not in dom:
                    dom["dns-ns"] = [""]
                if "dns-aaaa" not in dom:
                    dom["dns-aaaa"] = [""]
                else:
                    print(str(dom["dns-aaaa"][0]))
                    # check IP in Blocklist API
                    response = requests.get(
                        "http://api.blocklist.de/api.php?ip=" + str(dom["dns-aaaa"][0])
                    ).content
                    if str(response) != "b'attacks: 0<br />reports: 0<br />'":
                        malicious = True
                        attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                        reports = int(str(response).split("reports: ")[1].split("<")[0])

                    # check dns-a record in DSheild API
                    if str(dom["dns-aaaa"][0]) == "!ServFail":
                        continue
                    results = dshield.ip(
                        str(dom["dns-aaaa"][0]), return_format=dshield.JSON
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
                permutation = dom["domain-name"]
                if permutation in perm_list:
                    continue
                else:
                    perm_list.append(permutation)

                domain_dict = {
                    "organizations_uid": pe_org_uid,
                    "data_source_uid": source_uid,
                    "sub_domain_uid": sub_domain_uid,
                    "domain_permutation": dom["domain-name"],
                    "ipv4": dom["dns-a"][0],
                    "ipv6": dom["dns-aaaa"][0],
                    "mail_server": dom["dns-mx"][0],
                    "name_server": dom["dns-ns"][0],
                    "fuzzer": dom["fuzzer"],
                    "date_observed": dom["date-first-observed"],
                    "date_active": date,
                    "ssdeep_score": dom["ssdeep-score"],
                    "malicious": malicious,
                    "blocklist_attack_count": attacks,
                    "blocklist_report_count": reports,
                    "dshield_record_count": dshield_count,
                    "dshield_attack_count": dshield_attacks,
                }
                domain_list.append(domain_dict)

    except Exception:
        print("Failed selecting DNSTwist data.")
        print(traceback.format_exc())

    """Insert cleaned data into PE database."""
    try:
        cursor = PE_conn.cursor()
        columns = domain_list[0].keys()
        table = "domain_permutations"
        sql = """INSERT INTO {}({}) VALUES %s
        ON CONFLICT (domain_permutation,organizations_uid)
        DO UPDATE SET malicious = EXCLUDED.malicious,
            blocklist_attack_count = EXCLUDED.blocklist_attack_count,
            blocklist_report_count = EXCLUDED.blocklist_report_count,
            dshield_record_count = EXCLUDED.dshield_record_count,
            dshield_attack_count = EXCLUDED.dshield_attack_count,
            data_source_uid = EXCLUDED.data_source_uid,
            date_active = EXCLUDED.date_active;"""
        values = [[value for value in dict.values()] for dict in domain_list]
        extras.execute_values(
            cursor,
            sql.format(
                table,
                ",".join(columns),
            ),
            values,
        )
        PE_conn.commit()
        print("Data inserted using execute_values() successfully..")

    except Exception:
        print("Failure inserting data into database.")
        print(traceback.format_exc())


CF_conn.close()
PE_conn.close()
