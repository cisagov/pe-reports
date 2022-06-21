"""Fill CIDRs table from cyhy assets."""

# Third-Party Libraries
import pandas as pd

# cisagov Libraries
from pe_reports.data.db_query import connect


def query_cyhy_assets(cyhy_db_id):
    """Query cyhy assets."""
    sql = """
    SELECT *
    FROM cyhy_db_assets ca
    where ca.org_id = %(org_id)s
    """
    conn = connect()
    df = pd.read_sql_query(sql, conn, params={"org_id": cyhy_db_id})
    conn.close()
    return df


def fill_cidrs(orgs):
    """Fill CIDRs."""
    network_count = 0
    conn = connect()
    for i, org in orgs.iterrows():
        # if org['cyhy_db_name'] not in ['DOC', 'DOC_CENSUS']:
        #     continue
        org_id = org["organizations_uid"]
        print(org)
        networks = query_cyhy_assets(org["cyhy_db_name"])
        print(networks)
        for j, network in networks.iterrows():
            network_count += 1
            net = network["network"]
            print(net)
            cur = conn.cursor()
            try:
                cur.callproc("insert_cidr", (network["network"], org_id, "cyhy_db"))
            except Exception as e:
                print(e)
                continue

            row = cur.fetchone()
            print(row)
            conn.commit()
            cur.close()

    print(network_count)
