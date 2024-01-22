"""Link sub-domains and IPs from sub-domain lookups."""
# Standard Python Libraries
import datetime
import hashlib
import logging
import socket

# Third-Party Libraries
import pandas as pd

# cisagov Libraries
from pe_asm.data.cyhy_db_query import (
    pe_db_connect,
    pe_db_staging_connect,
    query_pe_report_on_orgs,
    query_subs,
)

LOGGER = logging.getLogger(__name__)
DATE = datetime.datetime.today().date()


def find_ips(domain):
    """Find the ip for a provided domain."""
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = None
    LOGGER.info(ip)
    return ip


def link_ip_from_domain(sub, root_uid, org_uid, data_source, conn):
    """Link IP from domain."""
    ip = find_ips(sub)
    if not ip:
        return 0
    hash_object = hashlib.sha256(str(ip).encode("utf-8"))
    ip_hash = hash_object.hexdigest()
    cur = conn.cursor()
    cur.callproc(
        "link_ips_and_subs",
        (DATE, ip_hash, ip, org_uid, sub, data_source, root_uid, None),
    )
    row = cur.fetchone()
    print(row)
    conn.commit()
    cur.close()
    return 1


def connect_ips_from_subs(staging, orgs_df=None):
    """For each org, find all ips associated with its sub_domains and link them in the ips_subs table."""
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
    for org_index, org_row in orgs_df.iterrows():
        # Connect to database
        if staging:
            conn = pe_db_staging_connect()
        else:
            conn = pe_db_connect()
        LOGGER.info(
            "Running on %s. %d/%d complete.",
            org_row["cyhy_db_name"],
            org_count,
            num_orgs,
        )
        org_uid = org_row["organizations_uid"]
        print(org_uid)

        # Query sub-domains
        subs_df = query_subs(str(org_uid), conn)
        LOGGER.info("Number of Sub-domains: %d", len(subs_df.index))

        for sub_index, sub_row in subs_df.iterrows():
            sub_domain = sub_row["sub_domain"]
            root_uid = sub_row["root_domain_uid"]
            if sub_domain == "Null_Sub":
                continue
            link_ip_from_domain(sub_domain, root_uid, org_uid, "unknown", conn)

        org_count += 1
        conn.close()
