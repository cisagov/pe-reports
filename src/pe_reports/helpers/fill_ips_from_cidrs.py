"""Fill IPs table from CIDR blocks."""
# Standard Python Libraries
import hashlib
import ipaddress
import logging

# Third-Party Libraries
import pandas as pd

# cisagov Libraries
from pe_reports.data.db_query import connect, execute_ips, query_cidrs


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
        }
        ips_from_cidrs.append(ip_obj)
    return ips_from_cidrs


def fill_ips_from_cidrs():
    """For each cidr enumerate all ips and add them to the ips table."""
    cidrs = query_cidrs()
    ips_from_cidrs = []
    for i, cidr in cidrs.iterrows():

        if cidr["insert_alert"] is not None:
            continue
        ips_from_cidrs = ips_from_cidrs + enumerate_ips(
            cidr["network"], cidr["cidr_uid"]
        )
    ips_from_cidrs = pd.DataFrame(ips_from_cidrs)
    logging.info(ips_from_cidrs)
    logging.info(ips_from_cidrs.drop_duplicates(subset=["ip"]))
    conn = connect()
    execute_ips(conn, ips_from_cidrs)
    print("Succuss adding IPS to Cidrs")


def main():
    """Run fill IPs."""
    fill_ips_from_cidrs()


if __name__ == "__main__":
    main()
