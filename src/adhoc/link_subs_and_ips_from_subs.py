"""Link sub-domains and IPs from sub-domain lookups."""
# Standard Python Libraries
import hashlib
import socket

# Third-Party Libraries
import pandas as pd

# cisagov Libraries
from pe_reports.data.db_query import connect


def find_ips(domain):
    """Find the ip for a provided domain."""
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = None
    print(ip)
    return ip


def query_subs(org_uid):
    """Query all subs for an organization."""
    conn = connect()
    sql = """SELECT sd.* FROM sub_domains sd
            JOIN root_domains rd on rd.root_domain_uid = sd.root_domain_uid
            where rd.organizations_uid = %(org_uid)s
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


def link_ip_from_domain(sub, root_uid, org_uid, data_source):
    """Link IP from domain."""
    conn = connect()
    ip = find_ips(sub)
    if not ip:
        return 0
    hash_object = hashlib.sha256(str(ip).encode("utf-8"))
    ip_hash = hash_object.hexdigest()
    cur = conn.cursor()
    cur.callproc(
        "link_ips_and_subs", (ip_hash, ip, org_uid, sub, data_source, root_uid, None)
    )
    row = cur.fetchone()
    print(row)
    conn.commit()
    cur.close()
    return 1


def connect_ips_from_subs(orgs):
    """For each org, find all ips associated with its sub_domains and link them in the ips_subs table."""
    for i, org in orgs.iterrows():
        org_uid = org["organizations_uid"]
        subs = query_subs(str(org_uid))
        for i, sub in subs.iterrows():
            sub_domain = sub["sub_domain"]
            root_uid = sub["root_domain_uid"]
            if sub_domain == "Null_Sub":
                continue
            link_ip_from_domain(sub_domain, root_uid, org_uid, "unknown")
        print("Finished connecting ips from subs")
