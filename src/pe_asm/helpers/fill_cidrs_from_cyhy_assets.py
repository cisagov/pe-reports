"""Fill CIDRs table from cyhy assets."""

# Standard Python Libraries
import logging
import datetime

# cisagov Libraries
from pe_reports.data.db_query import connect, query_cyhy_assets, get_orgs_df
from pe_asm.data.cyhy_db_query import identify_cidr_changes

LOGGER = logging.getLogger(__name__)


def fill_cidrs(orgs):
    """Fill CIDRs."""

    # Fetch all orgs if not specified
    if orgs == "all_orgs":
        orgs = get_orgs_df()

    network_count = 0
    first_seen = datetime.datetime.today().date()
    last_seen = datetime.datetime.today().date()
    conn = connect()
    for org_index, org_row in orgs.iterrows():
        org_id = org_row["organizations_uid"]
        LOGGER.info(org_row["cyhy_db_name"])
        networks = query_cyhy_assets(org_row["cyhy_db_name"], conn)
        for network_index, network in networks.iterrows():
            network_count += 1
            net = network["network"]
            print(net)
            cur = conn.cursor()
            try:
                cur.callproc(
                    "insert_cidr",
                    (network["network"], org_id, "cyhy_db", first_seen, last_seen),
                )
            except Exception as e:
                print(e)
                continue

            row = cur.fetchone()
            print(row)
            conn.commit()
            cur.close()
        LOGGER.info(network_count)

    # Identify which CIDRs are current
    identify_cidr_changes(conn)
    conn.close()
