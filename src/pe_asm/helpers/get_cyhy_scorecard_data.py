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

LOGGER = logging.getLogger(__name__)
DATE = datetime.datetime.today()
DAYS_BACK = datetime.timedelta(days=30)
ONE_MONTH_AGO = DATE - DAYS_BACK


def get_cyhy_port_scans(staging=False):
    """Get CyHy Ports and Scans."""

    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get the P&E org mapping table
    pe_org_map = get_pe_org_map(pe_db_conn)

    # Get P&E orgs for org_uid
    pe_orgs = query_pe_orgs(pe_db_conn)

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["port_scans"]

    # Only query documents that are a year old
    query = {"time": {"$gt": ONE_MONTH_AGO}}
    port_scans_data = collection.find(query, no_cursor_timeout=True)

    # Loop through cyhy port_scans collection
    port_scans_list = []
    port_scans_count = 0
    small_list = []
    skip_count = 0
    port_scans_total = collection.count_documents(query)
    LOGGER.info("%d total documents", port_scans_total)
    for port_scans in port_scans_data:
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
            LOGGER.info(
                "%d/%d complete", port_scans_count, port_scans_total - skip_count
            )
            small_list = []

    pe_db_conn.close()
    port_scans_data.close()


def get_cyhy_snapshots(staging=False):
    """Get CyHy Snapshots."""

    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get the P&E org mapping table
    pe_org_map = get_pe_org_map(pe_db_conn)

    # Get P&E orgs for org_uid
    pe_orgs = query_pe_orgs(pe_db_conn)

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["snapshots"]
    query = {}
    snapshots_data = collection.find(query, no_cursor_timeout=True)

    # Loop through cyhy snapshots collection
    snapshots_list = []
    small_list = []
    snapshots_count = 0
    skip_count = 0
    snapshots_total = collection.count_documents(query)
    LOGGER.info("%d total documents", snapshots_total)
    for snapshot in snapshots_data:
        # Replace mismatching cyhy org ids. For example, Treasury should be TREASURY
        if snapshot["owner"] in pe_org_map["cyhy_id"].values:
            new_org_id = pe_org_map.loc[
                pe_org_map["cyhy_id"] == snapshot["owner"], "pe_org_id"
            ].item()
            snapshot["owner"] = new_org_id

        # Get P&E organization UID
        try:
            pe_org_uid = pe_orgs.loc[
                pe_orgs["cyhy_db_name"] == snapshot["owner"], "organizations_uid"
            ].item()
        except Exception as e:
            print(e)
            print(
                "%s probably isn't in the P&E organizations table.", snapshot["owner"]
            )
            skip_count += 1
            continue

        # Create snapshot object
        snapshot_dict = {
            "organizations_uid": pe_org_uid,
            "cyhy_id": str(snapshot["_id"]),
            "cyhy_last_change": snapshot["last_change"],
            "host_count": snapshot["host_count"],
            "vulnerable_host_count": snapshot["vulnerable_host_count"],
            "first_seen": DATE,
            "last_seen": DATE,
        }
        snapshots_count += 1
        small_list.append(snapshot_dict)
        snapshots_list.append(snapshot_dict)

        if (snapshots_count % 10000 == 0) or (
            snapshots_count == (snapshots_total - skip_count)
        ):
            # Insert snapshot data into the P&E database
            LOGGER.info("Inserting snapshot data")
            snapshot_df = pd.DataFrame(small_list)
            table_name = "cyhy_snapshots"
            on_conflict = """
                        ON CONFLICT (cyhy_id)
                        DO UPDATE SET
                            last_seen = EXCLUDED.last_seen,
                            organizations_uid = EXCLUDED.organizations_uid,
                            cyhy_last_change = EXCLUDED.cyhy_last_change,
                            host_count = EXCLUDED.host_count,
                            vulnerable_host_count = EXCLUDED.vulnerable_host_count;
                        """
            insert_cyhy_scorecard_data(pe_db_conn, snapshot_df, table_name, on_conflict)
            LOGGER.info("%d/%d complete", snapshots_count, snapshots_total - skip_count)
            small_list = []

    pe_db_conn.close()
    snapshots_data.close()


def get_cyhy_tickets(staging=False):
    """Get CyHy Tickets."""

    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get the P&E org mapping table
    pe_org_map = get_pe_org_map(pe_db_conn)

    # Get P&E orgs for org_uid
    pe_orgs = query_pe_orgs(pe_db_conn)

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["tickets"]
    query = {"owner": "DOE"}
    tickets_data = collection.find(query, no_cursor_timeout=True)

    # Loop through cyhy tickets collection
    ticket_list = []
    tickets_count = 0
    skip_count = 0
    tickets_total = collection.count_documents(query)
    LOGGER.info("%d total documents", tickets_total)
    for ticket in tickets_data:
        # Replace mismatching cyhy org ids. For example, Treasury should be TREASURY
        if ticket["owner"] in pe_org_map["cyhy_id"].values:
            new_org_id = pe_org_map.loc[
                pe_org_map["cyhy_id"] == ticket["owner"], "pe_org_id"
            ].item()
            ticket["owner"] = new_org_id

        # Get P&E organization UID
        try:
            pe_org_uid = pe_orgs.loc[
                pe_orgs["cyhy_db_name"] == ticket["owner"], "organizations_uid"
            ].item()
        except Exception as e:
            print(e)
            print("%s probably isn't in the P&E organizations table.", ticket["owner"])
            skip_count += 1
            continue

        # Create ticket object
        ticket_dict = {
            "organizations_uid": pe_org_uid,
            "cyhy_id": str(ticket["_id"]),
            "false_positive": ticket["false_positive"],
            "time_opened": ticket["time_opened"],
            "time_closed": ticket["time_closed"],
            "cvss_base_score": ticket["details"].get("cvss_base_score"),
            "cve": ticket["details"].get("cve"),
            "first_seen": DATE,
            "last_seen": DATE,
            "source": ticket.get("source"),
        }
        tickets_count += 1
        ticket_list.append(ticket_dict)
        if (tickets_count % 100000 == 0) or (
            tickets_count == (tickets_total - skip_count)
        ):
            # Insert vulns_scans data into the P&E database
            LOGGER.info("Inserting ticket data")
            tickets_df = pd.DataFrame(ticket_list)
            table_name = "cyhy_tickets"
            on_conflict = """
                        ON CONFLICT (cyhy_id)
                        DO UPDATE SET
                            last_seen = EXCLUDED.last_seen,
                            organizations_uid = EXCLUDED.organizations_uid,
                            false_positive = EXCLUDED.false_positive,
                            time_opened = EXCLUDED.time_opened,
                            time_closed = EXCLUDED.time_closed,
                            cvss_base_score = EXCLUDED.cvss_base_score,
                            source = EXCLUDED.source,
                            cve = EXCLUDED.cve;
                        """
            insert_cyhy_scorecard_data(pe_db_conn, tickets_df, table_name, on_conflict)
            ticket_list = []
            LOGGER.info("%d/%d complete", tickets_count, tickets_total - skip_count)

    pe_db_conn.close()
    tickets_data.close()


def get_cyhy_vuln_scans(staging=False):
    """Get CyHy Vulnerability Scans."""

    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get the P&E org mapping table
    pe_org_map = get_pe_org_map(pe_db_conn)

    # Get P&E orgs for org_uid
    pe_orgs = query_pe_orgs(pe_db_conn)

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["vuln_scans"]
    query = {"time": {"$gt": ONE_MONTH_AGO}}
    vuln_scans_data = collection.find(query, no_cursor_timeout=True)

    # Loop through cyhy vuln_scans collection
    vuln_scans_list = []
    small_list = []
    vuln_scans_count = 0
    skip_count = 0
    vuln_scans_total = collection.count_documents(query)
    LOGGER.info("%d total documents", vuln_scans_total)
    for vuln_scan in vuln_scans_data:
        # Replace mismatching cyhy org ids. For example, Treasury should be TREASURY
        if vuln_scan["owner"] in pe_org_map["cyhy_id"].values:
            new_org_id = pe_org_map.loc[
                pe_org_map["cyhy_id"] == vuln_scan["owner"], "pe_org_id"
            ].item()
            vuln_scan["owner"] = new_org_id

        # Get P&E organization UID
        try:
            pe_org_uid = pe_orgs.loc[
                pe_orgs["cyhy_db_name"] == vuln_scan["owner"], "organizations_uid"
            ].item()
        except Exception as e:
            print(e)
            print(
                "%s probably isn't in the P&E organizations table.", vuln_scan["owner"]
            )
            skip_count += 1
            continue

        # Create vuln_scans object
        vuln_scans_dict = {
            "organizations_uid": pe_org_uid,
            "cyhy_id": str(vuln_scan["_id"]),
            "cyhy_time": vuln_scan["time"],
            "plugin_name": vuln_scan["plugin_name"],
            "cvss_base_score": vuln_scan["cvss_base_score"],
            "cve": vuln_scan.get("cve"),
            "first_seen": DATE,
            "last_seen": DATE,
            "ip": vuln_scan.get("ip"),
        }
        vuln_scans_count += 1
        vuln_scans_list.append(vuln_scans_dict)
        small_list.append(vuln_scans_dict)

        if (vuln_scans_count % 100000 == 0) or (
            vuln_scans_count == (vuln_scans_total - skip_count)
        ):
            LOGGER.info(
                "%d/%d complete", vuln_scans_count, vuln_scans_total - skip_count
            )

            # Insert vuln_scans data into the P&E database
            LOGGER.info("Inserting vuln_scans data")
            vuln_scans_df = pd.DataFrame(small_list)
            table_name = "cyhy_vuln_scans"
            on_conflict = """
                        ON CONFLICT (cyhy_id)
                        DO UPDATE SET
                            last_seen = EXCLUDED.last_seen,
                            organizations_uid = EXCLUDED.organizations_uid,
                            cyhy_time = EXCLUDED.cyhy_time,
                            plugin_name = EXCLUDED.plugin_name,
                            cvss_base_score = EXCLUDED.cvss_base_score,
                            ip = EXCLUDED.ip,
                            cve = EXCLUDED.cve;
                        """
            insert_cyhy_scorecard_data(
                pe_db_conn, vuln_scans_df, table_name, on_conflict
            )
            small_list = []

    pe_db_conn.close()
    vuln_scans_data.close()


def get_cyhy_kevs(staging=False):
    """Get CyHy Kevs."""

    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["kevs"]
    query = {}
    kev_data = collection.find(query, no_cursor_timeout=True)

    # Loop through cyhy kev collection
    kev_list = []
    kev_count = 0
    kev_total = collection.count_documents(query)
    LOGGER.info("%d total documents", kev_total)
    for kev in kev_data:
        # Create kev object
        kev_dict = {
            "kev": kev["_id"],
            "first_seen": DATE,
            "last_seen": DATE,
        }
        kev_count += 1
        kev_list.append(kev_dict)

        if (kev_count % 100 == 0) or (kev_count == kev_total):
            LOGGER.info("%d/%d complete", kev_count, kev_total)

    LOGGER.info(len(kev_list))

    # Insert kev data into the P&E database
    LOGGER.info("Inserting KEV data.")
    kevs_df = pd.DataFrame(kev_list)
    table_name = "cyhy_kevs"
    on_conflict = """
                ON CONFLICT (kev)
                DO UPDATE SET
                    last_seen = EXCLUDED.last_seen;
                """
    insert_cyhy_scorecard_data(pe_db_conn, kevs_df, table_name, on_conflict)

    pe_db_conn.close()
    kev_data.close()


def get_cyhy_https_scan(staging=False):
    """Get CyHy https scan."""

    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get the P&E org mapping table
    pe_org_map = get_pe_org_map(pe_db_conn)

    # Get P&E orgs for org_uid
    pe_orgs = query_pe_orgs(pe_db_conn)

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_scan_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["https_scan"]
    query = {}
    https_scan_data = collection.find(query, no_cursor_timeout=True)

    # Loop through cyhy https_scan collection
    https_scan_list = []
    small_list = []
    https_scan_count = 0
    skip_count = 0
    https_scan_total = collection.count_documents(query)
    LOGGER.info("%d total documents", https_scan_total)
    for https_scan in https_scan_data:
        # Replace mismatching cyhy org ids. For example, Treasury should be TREASURY
        if https_scan["agency"]["id"] in pe_org_map["cyhy_id"].values:
            new_org_id = pe_org_map.loc[
                pe_org_map["cyhy_id"] == https_scan["agency"]["id"], "pe_org_id"
            ].item()
            https_scan["agency"]["id"] = new_org_id

        # Get P&E organization UID
        try:
            pe_org_uid = pe_orgs.loc[
                pe_orgs["cyhy_db_name"] == https_scan["agency"]["id"],
                "organizations_uid",
            ].item()
        except Exception as e:
            print(e)
            print(
                "%s probably isn't in the P&E organizations table.",
                https_scan["agency"]["id"],
            )
            skip_count += 1
            continue

        # Create https_scan object
        https_scan_dict = {
            "organizations_uid": pe_org_uid,
            "cyhy_id": str(https_scan["_id"]),
            "cyhy_latest": https_scan["latest"],
            "domain_supports_https": https_scan["domain_supports_https"],
            "domain_enforces_https": https_scan["domain_enforces_https"],
            "domain_uses_strong_hsts": https_scan["domain_uses_strong_hsts"],
            "live": https_scan["live"],
            "scan_date": https_scan["scan_date"],
            "hsts_base_domain_preloaded": https_scan["hsts_base_domain_preloaded"],
            "domain": https_scan["domain"],
            "base_domain": https_scan["base_domain"],
            "is_base_domain": https_scan["is_base_domain"],
            "first_seen": DATE,
            "last_seen": DATE,
            "https_full_connection": https_scan.get("https_full_connection"),
            "https_client_auth_required": https_scan.get("https_client_auth_required"),
        }
        https_scan_count += 1
        https_scan_list.append(https_scan_dict)
        small_list.append(https_scan_dict)

        if (https_scan_count % 100000 == 0) or (
            https_scan_count == (https_scan_total - skip_count)
        ):
            LOGGER.info(
                "%d/%d complete", https_scan_count, https_scan_total - skip_count
            )

            # Insert https_scan data into the P&E database
            LOGGER.info("Inserting https_scan data.")
            https_scan_df = pd.DataFrame(small_list)
            table_name = "cyhy_https_scan"
            on_conflict = """
                        ON CONFLICT (cyhy_id)
                        DO UPDATE SET
                            last_seen = EXCLUDED.last_seen,
                            organizations_uid = EXCLUDED.organizations_uid,
                            cyhy_latest = EXCLUDED.cyhy_latest,
                            domain_supports_https = EXCLUDED.domain_supports_https,
                            domain_enforces_https = EXCLUDED.domain_enforces_https,
                            domain_uses_strong_hsts = EXCLUDED.domain_uses_strong_hsts,
                            live = EXCLUDED.live,
                            scan_date = EXCLUDED.scan_date,
                            hsts_base_domain_preloaded = EXCLUDED.hsts_base_domain_preloaded,
                            domain = EXCLUDED.domain,
                            base_domain = EXCLUDED.base_domain,
                            is_base_domain = EXCLUDED.is_base_domain,
                            https_full_connection = EXCLUDED.https_full_connection,
                            https_client_auth_required = EXCLUDED.https_client_auth_required;
                        """
            insert_cyhy_scorecard_data(
                pe_db_conn, https_scan_df, table_name, on_conflict
            )
            small_list = []

    pe_db_conn.close()
    https_scan_data.close()


def get_cyhy_trustymail(staging=False):
    """Get CyHy trustymail."""

    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get the P&E org mapping table
    pe_org_map = get_pe_org_map(pe_db_conn)

    # Get P&E orgs for org_uid
    pe_orgs = query_pe_orgs(pe_db_conn)

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_scan_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["trustymail"]
    query = {}
    trustymail_data = collection.find(query, no_cursor_timeout=True)

    # Loop through cyhy trustymail collection
    trustymail_list = []
    small_list = []
    trustymail_count = 0
    skip_count = 0
    trustymail_total = collection.count_documents(query)
    LOGGER.info("%d total documents", trustymail_total)
    for trustymail in trustymail_data:
        # Replace mismatching cyhy org ids. For example, Treasury should be TREASURY
        if trustymail["agency"]["id"] in pe_org_map["cyhy_id"].values:
            new_org_id = pe_org_map.loc[
                pe_org_map["cyhy_id"] == trustymail["agency"]["id"], "pe_org_id"
            ].item()
            trustymail["agency"]["id"] = new_org_id

        # Get P&E organization UID
        try:
            pe_org_uid = pe_orgs.loc[
                pe_orgs["cyhy_db_name"] == trustymail["agency"]["id"],
                "organizations_uid",
            ].item()
        except Exception as e:
            print(e)
            print(
                "%s probably isn't in the P&E organizations table.",
                trustymail["agency"]["id"],
            )
            skip_count += 1
            continue

        # Create trustymail object
        trustymail_dict = {
            "organizations_uid": pe_org_uid,
            "cyhy_id": str(trustymail["_id"]),
            "cyhy_latest": trustymail["latest"],
            "base_domain": trustymail["base_domain"],
            "is_base_domain": trustymail["is_base_domain"],
            "domain": trustymail["domain"],
            "dmarc_record": trustymail["dmarc_record"],
            "valid_spf": trustymail["valid_spf"],
            "scan_date": trustymail["scan_date"],
            "live": trustymail["live"],
            "spf_record": trustymail["spf_record"],
            "valid_dmarc": trustymail["valid_dmarc"],
            "valid_dmarc_base_domain": trustymail["valid_dmarc_base_domain"],
            "dmarc_policy": trustymail["dmarc_policy"],
            "dmarc_policy_percentage": trustymail.get("dmarc_policy_percentage"),
            "aggregate_report_uris": str(trustymail["aggregate_report_uris"]),
            "domain_supports_smtp": trustymail.get("domain_supports_smtp"),
            "first_seen": DATE,
            "last_seen": DATE,
            "dmarc_subdomain_policy": trustymail.get("dmarc_subdomain_policy"),
        }
        trustymail_count += 1
        trustymail_list.append(trustymail_dict)
        small_list.append(trustymail_dict)

        if (trustymail_count % 100000 == 0) or (
            trustymail_count == (trustymail_total - skip_count)
        ):
            LOGGER.info(
                "%d/%d complete", trustymail_count, trustymail_total - skip_count
            )

            # Insert trustymail data into the P&E database
            LOGGER.info("Inserting trustymail data.")
            trustymail_df = pd.DataFrame(small_list)
            table_name = "cyhy_trustymail"
            on_conflict = """
                        ON CONFLICT (cyhy_id)
                        DO UPDATE SET
                            last_seen = EXCLUDED.last_seen,
                            organizations_uid = EXCLUDED.organizations_uid,
                            cyhy_latest = EXCLUDED.cyhy_latest,
                            base_domain = EXCLUDED.base_domain,
                            is_base_domain = EXCLUDED.is_base_domain,
                            domain = EXCLUDED.domain,
                            dmarc_record = EXCLUDED.dmarc_record,
                            valid_spf = EXCLUDED.valid_spf,
                            scan_date = EXCLUDED.scan_date,
                            live = EXCLUDED.live,
                            spf_record = EXCLUDED.spf_record,
                            valid_dmarc = EXCLUDED.valid_dmarc,
                            valid_dmarc_base_domain = EXCLUDED.valid_dmarc_base_domain,
                            dmarc_policy = EXCLUDED.dmarc_policy,
                            dmarc_policy_percentage = EXCLUDED.dmarc_policy_percentage,
                            aggregate_report_uris = EXCLUDED.aggregate_report_uris,
                            dmarc_subdomain_policy = EXCLUDED.dmarc_subdomain_policy,
                            domain_supports_smtp = EXCLUDED.domain_supports_smtp;
                        """
            insert_cyhy_scorecard_data(
                pe_db_conn, trustymail_df, table_name, on_conflict
            )
            small_list = []

    pe_db_conn.close()
    trustymail_data.close()


def get_cyhy_sslyze(staging=False):
    """Get CyHy sslyze scan."""

    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get the P&E org mapping table
    pe_org_map = get_pe_org_map(pe_db_conn)

    # Get P&E orgs for org_uid
    pe_orgs = query_pe_orgs(pe_db_conn)

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_scan_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["sslyze_scan"]
    query = {}
    sslyze_data = collection.find(query, no_cursor_timeout=True)

    # Loop through cyhy sslyze_scan collection
    sslyze_list = []
    small_list = []
    sslyze_count = 0
    skip_count = 0
    sslyze_total = collection.count_documents(query)
    LOGGER.info("%d total documents", sslyze_total)
    for sslyze in sslyze_data:
        # Replace mismatching cyhy org ids. For example, Treasury should be TREASURY
        if sslyze["agency"]["id"] in pe_org_map["cyhy_id"].values:
            new_org_id = pe_org_map.loc[
                pe_org_map["cyhy_id"] == sslyze["agency"]["id"], "pe_org_id"
            ].item()
            sslyze["agency"]["id"] = new_org_id

        # Get P&E organization UID
        try:
            pe_org_uid = pe_orgs.loc[
                pe_orgs["cyhy_db_name"] == sslyze["agency"]["id"], "organizations_uid"
            ].item()
        except Exception as e:
            print(e)
            print(
                "%s probably isn't in the P&E organizations table.",
                sslyze["agency"]["id"],
            )
            skip_count += 1
            continue

        # Create sslyze_scan object
        sslyze_dict = {
            "organizations_uid": pe_org_uid,
            "cyhy_id": str(sslyze["_id"]),
            "cyhy_latest": sslyze["latest"],
            "scanned_port": sslyze["scanned_port"],
            "domain": sslyze["domain"],
            "base_domain": sslyze["base_domain"],
            "is_base_domain": sslyze["is_base_domain"],
            "scanned_hostname": sslyze["scanned_hostname"],
            "sslv2": sslyze["sslv2"],
            "sslv3": sslyze["sslv2"],
            "scan_date": sslyze["scan_date"],
            "any_3des": sslyze["any_3des"],
            "any_rc4": sslyze["any_rc4"],
            "first_seen": DATE,
            "last_seen": DATE,
            "is_symantec_cert": sslyze.get("is_symantec_cert"),
        }
        sslyze_count += 1
        sslyze_list.append(sslyze_dict)
        small_list.append(sslyze_dict)

        if (sslyze_count % 100000 == 0) or (
            sslyze_count == (sslyze_total - skip_count)
        ):
            LOGGER.info("%d/%d complete", sslyze_count, sslyze_total - skip_count)

            # Insert sslyze data into the P&E database
            LOGGER.info("Inserting sslyze data.")
            sslyze_df = pd.DataFrame(small_list)
            table_name = "cyhy_sslyze"
            on_conflict = """
                        ON CONFLICT (cyhy_id)
                        DO UPDATE SET
                            last_seen = EXCLUDED.last_seen,
                            organizations_uid = EXCLUDED.organizations_uid,
                            cyhy_latest = EXCLUDED.cyhy_latest,
                            scanned_port = EXCLUDED.scanned_port,
                            domain = EXCLUDED.domain,
                            base_domain = EXCLUDED.base_domain,
                            is_base_domain = EXCLUDED.is_base_domain,
                            scanned_hostname = EXCLUDED.scanned_hostname,
                            sslv2 = EXCLUDED.sslv2,
                            sslv3 = EXCLUDED.sslv3,
                            scan_date = EXCLUDED.scan_date,
                            any_3des = EXCLUDED.any_3des,
                            is_symantec_cert = EXCLUDED.is_symantec_cert,
                            any_rc4 = EXCLUDED.any_rc4;
                        """
            insert_cyhy_scorecard_data(pe_db_conn, sslyze_df, table_name, on_conflict)
            small_list = []

    pe_db_conn.close()
    sslyze_data.close()


def main():
    """Connect to CyHy DB and update org information and assets."""
    get_cyhy_port_scans()


if __name__ == "__main__":
    main()
