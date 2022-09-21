"""Fill CIDRs table from cyhy assets."""

# Standard Python Libraries
import logging

# cisagov Libraries
from pe_reports.data.db_query import connect, query_cyhy_assets


def fill_cidrs(orgs):
    """Fill CIDRs."""
    network_count = 0

    for org_index, org_row in orgs.iterrows():
        conn = connect()
        org_id = org_row["organizations_uid"]
        logging.info(org_row)
        networks = query_cyhy_assets(org_row["cyhy_db_name"], conn)
        logging.info(networks)
        for network_index, network in networks.iterrows():
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
        conn.close()

    logging.info(network_count)
