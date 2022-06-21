"""Link sub-domains and IPs from IP lookups."""
# Third-Party Libraries
import pandas as pd
import requests

# cisagov Libraries
from pe_reports.data.db_query import connect


def reverseLookup(ip):
    """Take an ip and find all associated subdomains."""
    # TODO: Add API key
    api = ""
    url = f"https://dns-history.whoisxmlapi.com/api/v1?apiKey={api}&ip={ip}"
    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload).json()
    found_domains = []
    try:
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

    except Exception:
        print("failed to return response")
    return found_domains


def query_ips(org_uid):
    """Query all ips that link to a cidr related to a specific org."""
    print(org_uid)
    conn = connect()
    sql = """SELECT i.ip_hash, i.ip, ct.network FROM ips i
            JOIN cidrs ct on ct.cidr_uid = i.origin_cidr
            where ct.organizations_uid = %(org_uid)s
            and i.origin_cidr is not null
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


def link_domain_from_ip(ip_hash, ip, org_uid, data_source):
    """From a provided ip find domains and link them in the db."""
    conn = connect()
    found_domains = reverseLookup(ip)
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


def connect_subs_from_ips(orgs):
    """For each org find all domains that are associated to an ip and create link in the ip_subs table."""
    for i, org in orgs.iterrows():
        org_uid = org["organizations_uid"]
        ips = query_ips(org_uid)
        print(ips)
        for j, ip in ips.iterrows():
            link_domain_from_ip(ip["ip_hash"], ip["ip"], org_uid, "WhoisXML")
        print("Success connecting subs from IPs")
