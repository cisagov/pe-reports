"""Fill IPs table from CIDR blocks."""
# Standard Python Libraries
import hashlib
import ipaddress

# Third-Party Libraries
import pandas as pd
import psycopg2

# cisagov Libraries
from pe_reports.data.db_query import connect, show_psycopg2_exception, get_orgs_df


def execute_ips(conn, dataframe):
    """Insert the ips into the ips table in the database and link them to the associated cidr."""
    for row_index, row in dataframe.iterrows():
        try:
            cur = conn.cursor()
            sql = """
            INSERT INTO ips(ip_hash, ip, origin_cidr) VALUES (%s, %s, %s)
            ON CONFLICT (ip)
                    DO
                    UPDATE SET origin_cidr = UUID(EXCLUDED.origin_cidr); """
            print((row["ip_hash"], row["ip"], row["origin_cidr"]))
            cur.execute(sql, (row["ip_hash"], row["ip"], row["origin_cidr"]))
            conn.commit()
        except (Exception, psycopg2.DatabaseError) as err:
            show_psycopg2_exception(err)
            cur.close()
            continue
    print("IPs inserted using execute_values() successfully..")


def query_cidrs(org_id):
    """Query Cidr."""
    conn = connect()
    print(org_id)
    sql = """
    SELECT ct.cidr_uid, ct.network, ct.organizations_uid, ct.insert_alert
    FROM cidrs ct
    WHERE ct.organizations_uid = %(org_id)s;
    """
    df = pd.read_sql(sql, conn, params={"org_id": org_id})
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


def fill_ips_from_cidrs(org_id):
    """For each cidr enumerate all ips and add them to the ips table."""
    cidrs = query_cidrs(org_id)
    ips_from_cidrs = []
    for row_index, cidr in cidrs.iterrows():
        if cidr["insert_alert"] is not None:
            continue
        ips_from_cidrs = ips_from_cidrs + enumerate_ips(
            cidr["network"], cidr["cidr_uid"]
        )
    ips_from_cidrs = pd.DataFrame(ips_from_cidrs)
    print(ips_from_cidrs)
    print(ips_from_cidrs.drop_duplicates(subset=["ip"]))
    conn = connect()
    execute_ips(conn, ips_from_cidrs)
    print("Succuss adding IPS to Cidrs")


def main():
    orgs = get_orgs_df()
    # orgs = orgs[orgs['cyhy_db_name'] == 'DOI_OS-OAS']
    orgs = orgs[orgs["cyhy_db_name"].isin(["DHS", "TREASURY", "TREASURY_AUC", "HHS"])]
    print(orgs)
    # if len(orgs == 1):
    for org_index, org in orgs.iterrows():
        fill_ips_from_cidrs(org["organizations_uid"])


if __name__ == "__main__":
    main()
