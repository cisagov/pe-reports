"""Fill IPs table from CIDR blocks."""
# Standard Python Libraries
import hashlib
import ipaddress

# Third-Party Libraries
import pandas as pd
import psycopg2
import logging

# cisagov Libraries
from pe_reports.data.db_query import connect, show_psycopg2_exception


def execute_ips(conn, dataframe):
    """Insert the ips into the ips table in the database and link them to the associated cidr."""
    for ip_index, ip_row in dataframe.iterrows():
        try:
            cur = conn.cursor()
            sql = """
            INSERT INTO ips(ip_hash, ip, origin_cidr) VALUES (%s, %s, %s)
            ON CONFLICT (ip)
                    DO
                    UPDATE SET origin_cidr = UUID(EXCLUDED.origin_cidr); """
            cur.execute(sql, (ip_row["ip_hash"], ip_row["ip"], ip_row["origin_cidr"]))
            conn.commit()
        except (Exception, psycopg2.DatabaseError) as err:
            show_psycopg2_exception(err)
            cur.close()
            continue
    print("IPs inserted using execute_values() successfully..")


def query_cidrs():
    """Query all cidrs ordered by length."""
    conn = connect()
    sql = """SELECT tc.cidr_uid, tc.network, tc.organizations_uid, tc.insert_alert
            FROM cidrs tc
            ORDER BY masklen(tc.network)
            """
    df = pd.read_sql(sql, conn)
    conn.close()
    return df


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
    for cidr_index, cidr in cidrs.iterrows():

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
    fill_ips_from_cidrs()


if __name__ == "__main__":
    main()
