#!/usr/bin/python3
"""Query CyHy database to update P&E data with CyHy port_scans data."""

import subprocess
import json
import re
import datetime
import logging
import pandas as pd

# cisagov Libraries
from ..data.cyhy_db_query import (
    pe_db_connect,
    pe_db_staging_connect,
    query_pe_orgs,
    insert_cyhy_scorecard_data,
)

DATE = datetime.datetime.today()
LOGGER = logging.getLogger(__name__)


def get_cyhy_port_scans(staging):
    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get P&E orgs for org_uidi
    pe_orgs = query_pe_orgs(pe_db_conn)

    # Build the Go program
    build_result = subprocess.run(
        [
            "go",
            "build",
            "-o",
            "src/pe_asm/port_scans/cyhybatcher",
            "src/pe_asm/port_scans/cyhybatcher.go",
        ]
    )

    print("Go program built successfully.")

    # Call the Go program with the number of start and end days as arguments
    result = subprocess.run(
        ["./src/pe_asm/port_scans/cyhybatcher", "7", "0", "DOE"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Parse the JSON output
    try:
        # Filter out non-JSON content
        json_string = re.search(r"\[.*\]", result.stdout).group(0)
        batches = json.loads(json_string)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        batches = []

    if len(batches) == 0:
        print("The JSON object is empty.")
    else:
        # Access and print the returned batches
        # TODO: Multiprocess each batch
        print(len(batches))
        for batch in batches:
            port_scans_count = 0
            port_scans_list = []
            skip_count = 0
            port_scans_total = len(batch)
            for port_scans in batch:
                # Get P&E organization UID
                try:
                    pe_org_uid = pe_orgs.loc[
                        pe_orgs["cyhy_db_name"] == port_scans["owner"],
                        "organizations_uid",
                    ].item()
                except Exception as e:
                    print(e)
                    print(
                        "%s probably isn't in the P&E organizations table.",
                        port_scans["owner"],
                    )
                    skip_count += 1
                    continue

                # Create port_scans object
                port_scans_dict = {
                    "organizations_uid": pe_org_uid,
                    "cyhy_id": str(port_scans["_id"]),
                    "cyhy_time": port_scans["time"],
                    "service_name": port_scans["service"].get("name"),
                    "port": port_scans["port"],
                    "product": port_scans["service"].get("product"),
                    "cpe": str(port_scans["service"].get("cpe")),
                    "first_seen": DATE,
                    "last_seen": DATE,
                    "ip": port_scans["ip"],
                    "state": port_scans["state"],
                }
                port_scans_count += 1
                port_scans_list.append(port_scans_dict)
                port_scans_list.append(port_scans_dict)

                if (port_scans_count % 100000 == 0) or (
                    port_scans_count == (port_scans_total - skip_count)
                ):
                    # Insert port_scans data into the P&E database
                    LOGGER.info("Inserting port_scans data")
                    port_scans_df = pd.DataFrame(port_scans_list)
                    table_name = "cyhy_port_scans"
                    on_conflict = """
                                ON CONFLICT (cyhy_id)
                                DO UPDATE SET
                                    last_seen = EXCLUDED.last_seen,
                                    organizations_uid = EXCLUDED.organizations_uid,
                                    cyhy_time = EXCLUDED.cyhy_time,
                                    service_name = EXCLUDED.service_name,
                                    port = EXCLUDED.port,
                                    product = EXCLUDED.product,
                                    ip = EXCLUDED.ip,
                                    state = EXCLUDED.state,
                                    cpe = EXCLUDED.cpe;
                                """

                    # Connect to P&E postgres database
                    if staging:
                        pe_db_conn = pe_db_staging_connect()
                    else:
                        pe_db_conn = pe_db_connect()
                    insert_cyhy_scorecard_data(
                        pe_db_conn, port_scans_df, table_name, on_conflict
                    )
                    LOGGER.info(
                        "%d/%d complete",
                        port_scans_count,
                        port_scans_total - skip_count,
                    )
                    port_scans_list = []

            pe_db_conn.close()
