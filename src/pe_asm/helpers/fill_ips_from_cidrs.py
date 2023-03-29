#!/usr/bin/env python
"""Fill IPs table from CIDR blocks."""
# Standard Python Libraries
import hashlib
import ipaddress
import logging
import datetime

# Third-Party Libraries
import pandas as pd

# cisagov Libraries
from pe_asm.data.cyhy_db_query import (
    query_cidrs,
    execute_ips,
    identify_ip_changes,
    pe_db_connect,
    pe_db_staging_connect,
)

LOGGER = logging.getLogger(__name__)
DATE = datetime.datetime.today().date()


def enumerate_ips(cidr, cidr_uid):
    """Enumerate all ips for a provided cidr."""
    ips_from_cidrs = []
    print(cidr)
    for ip in ipaddress.IPv4Network(cidr):
        hash_object = hashlib.sha256(str(ip).encode("utf-8"))
        ip_obj = {
            "ip_hash": hash_object.hexdigest(),
            "ip": str(ip),
            "origin_cidr": cidr_uid,
            "first_seen": DATE,
            "last_seen": DATE,
        }
        ips_from_cidrs.append(ip_obj)
    return ips_from_cidrs


def fill_ips_from_cidrs(staging):
    """For each CIDR, enumerate all IPs and add them to the ips table."""

    # Connect to database
    if staging:
        conn = pe_db_staging_connect()
    else:
        conn = pe_db_connect()

    cidrs = query_cidrs(conn)

    # Loop through each CIDR in order of greatest length and enumerate
    LOGGER.info("Enumerating IPs:")
    num_of_cidrs = len(cidrs.index)
    cidr_count = 0
    ips_from_cidrs = []
    for cidr_index, cidr in cidrs.iterrows():

        cidr_count += 1
        if cidr["insert_alert"] is not None:
            continue

        # Enumerate IPs
        ips_from_cidrs = ips_from_cidrs + enumerate_ips(
            cidr["network"], cidr["cidr_uid"]
        )
        if cidr_count % 500 == 0 or cidr_count == num_of_cidrs:
            LOGGER.info("\t\t%d/%d complete.", cidr_count, num_of_cidrs)

    # Make DataFrame from json
    ips_from_cidrs = pd.DataFrame(ips_from_cidrs)

    # Insert into the ips table
    LOGGER.info("Starting IP insert.")
    execute_ips(conn, ips_from_cidrs)
    LOGGER.info("Success.")

    # Identify which IPs are current
    LOGGER.info("Identify changes.")
    identify_ip_changes(conn)
    print("Success adding IPS to Cidrs")

    # Close database connection
    conn.close()


def main():
    """Fill ips from the cidrs in new orgs."""
    fill_ips_from_cidrs()


if __name__ == "__main__":
    main()
