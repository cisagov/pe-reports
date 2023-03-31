#!/usr/bin/python3
"""Query CyHy database to update P&E data with CyHy ASM data."""

# Standard Python Libraries
import datetime
import logging
import requests

# Third-Party Libraries
from bs4 import BeautifulSoup
import pandas as pd

# cisagov Libraries
from ..data.cyhy_db_query import (
    mongo_connect,
    mongo_scan_connect,
    pe_db_connect,
    pe_db_staging_connect,
    get_pe_org_map,
    query_pe_orgs,
    insert_cyhy_scorecard_data,
)
import multiprocessing
import pymongo
import psycopg2
import json
from functools import partial

LOGGER = logging.getLogger(__name__)
DATE = datetime.datetime.today()
DAYS_BACK = datetime.timedelta(days=7)
ONE_MONTH_AGO = DATE - DAYS_BACK


# Define a function to process a chunk of documents
def process_batch(batch, staging):
    """Process batch."""
    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get the P&E org mapping table
    pe_org_map = get_pe_org_map(pe_db_conn)

    # Get P&E orgs for org_uid
    pe_orgs = query_pe_orgs(pe_db_conn)

    port_scans_list = []
    port_scans_count = 0
    small_list = []
    skip_count = 0
    port_scans_total = 1000000
    for port_scans in batch:
        # Replace mismatching cyhy org ids. For example, Treasury should be TREASURY
        if port_scans["owner"] in pe_org_map["cyhy_id"].values:
            new_org_id = pe_org_map.loc[
                pe_org_map["cyhy_id"] == port_scans["owner"], "pe_org_id"
            ].item()
            port_scans["owner"] = new_org_id

        # Get P&E organization UID
        try:
            pe_org_uid = pe_orgs.loc[
                pe_orgs["cyhy_db_name"] == port_scans["owner"], "organizations_uid"
            ].item()
        except Exception as e:
            print(e)
            print(
                "%s probably isn't in the P&E organizations table.", port_scans["owner"]
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
        small_list.append(port_scans_dict)

        if (port_scans_count % 100000 == 0) or (
            port_scans_count == (port_scans_total - skip_count)
        ):

            # Insert port_scans data into the P&E database
            with multiprocessing.Lock():
                LOGGER.info("Inserting port_scans data")
            port_scans_df = pd.DataFrame(small_list)
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
            insert_cyhy_scorecard_data(
                pe_db_conn, port_scans_df, table_name, on_conflict
            )
            with multiprocessing.Lock():
                LOGGER.info(
                    "%s%d/%d complete",
                    port_scans_count,
                    port_scans_total - skip_count,
                )
            small_list = []


def get_cyhy_port_scans(staging=False):
    """Get CyHy Ports and Scans."""

    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["port_scans"]

    # Only query documents that are a year old
    query = {"time": {"$gt": ONE_MONTH_AGO}}
    # port_scans_data = collection.find(query, no_cursor_timeout=True)

    # Split the cursor into chunks and process each chunk in a separate worker process
    port_scans_total = collection.count_documents(query)
    LOGGER.info("%s total documents.", port_scans_total)
    chunk_size = 1000000
    num_processes = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(num_processes)  # Use 4 worker processes

    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    port_scans_data = collection.find(query)
    LOGGER.info("Find complete. Now breaking into batches.")
    # batches = []
    # batch_count = 0
    # while True:
    #     documents = list(cursor.limit(chunk_size))
    #     batch_count += 1
    #     LOGGER.info("%s batches created.", batch_count)
    #     if not documents:
    #         break
    #     batches.append(documents)
    batches = [
        list(
            collection.aggregate(
                [
                    {"$match": query},
                    {"$sort": {"_id": 1}},
                    {"$skip": i},
                    {"$limit": chunk_size},
                ]
            )
        )
        for i in range(0, collection.count_documents(query), chunk_size)
    ]
    LOGGER.info("%s batches will be run.", len(batches))

    function = partial(process_batch, staging)
    # Process batches in parallel
    pool.map(function, batches)

    # Close the database connections
    pe_db_conn.close()
    port_scans_data.close()
