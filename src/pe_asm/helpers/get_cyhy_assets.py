#!/usr/bin/python3
"""Query CyHy database to update P&E assets."""

# Standard Python Libraries
import datetime
import logging

# Third-Party Libraries
from bs4 import BeautifulSoup
import pandas as pd
import requests

# cisagov Libraries
from pe_asm.data.cyhy_db_query import (  # get_pe_org_map,
    identify_org_asset_changes,
    insert_assets,
    insert_contacts,
    insert_cyhy_agencies,
    insert_dot_gov_domains,
    mongo_connect,
    pe_db_connect,
    pe_db_staging_connect,
    query_pe_orgs,
    update_child_parent_orgs,
    update_scan_status,
)

LOGGER = logging.getLogger(__name__)


def dotgov_domains():
    """Get list of dotgov domains from the github repo."""
    URL = "https://github.com/cisagov/dotgov-data/blob/main/current-federal.csv"
    r = requests.get(URL)
    soup = BeautifulSoup(r.content, features="lxml")
    table = soup.find_all("table")
    df = pd.read_html(str(table))[0]
    df = df.drop(columns=["Unnamed: 0"])
    df = df.rename(
        columns={
            "Domain Name": "domain_name",
            "Domain Type": "domain_type",
            "Agency": "agency",
            "Organization": "organization",
            "City": "city",
            "State": "state",
            "Security Contact Email": "security_contact_email",
        }
    )
    return df


def get_cyhy_assets(staging=False):
    """Get CyHy assets."""
    # Connect to P&E postgres database
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()

    # Get the P&E org mapping table
    # pe_org_map = get_pe_org_map(pe_db_conn)

    # Connect to the CyHy database and fetch all request data
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    collection = cyhy_db["requests"]

    query = {"_id": "EXECUTIVE"}
    fceb_doc = collection.find(query)
    for row in fceb_doc:
        fceb_list = row["children"]

    cyhy_request_data = collection.find()

    # Loop through all CyHy agencies
    cyhy_agencies = []
    assets = []
    contact_list = []
    child_parent_dict = {}
    for cyhy_request in cyhy_request_data:
        # If the CyHy org has a type and network, get the org info
        # if cyhy_request["agency"].get("type") and len(cyhy_request["networks"]) > 0:
        if cyhy_request["agency"].get("type"):
            agency = {
                "name": cyhy_request["agency"]["name"],
                "cyhy_db_name": cyhy_request["_id"],
                "password": cyhy_request["key"],
                "agency_type": cyhy_request["agency"].get("type"),
                "retired": cyhy_request.get("retired", False),
                "receives_cyhy_report": "CYHY" in cyhy_request["report_types"],
                "receives_bod_report": "BOD" in cyhy_request["report_types"],
                "receives_cybex_report": "CYBEX" in cyhy_request["report_types"],
                "is_parent": len(cyhy_request.get("children", [])) > 0,
                "fceb": cyhy_request["_id"] in fceb_list,
            }
            cyhy_agencies.append(agency)

            # If the org has children/subsidiaries,
            # save the child to a dictionary with the parent cyhy_db_id
            if cyhy_request.get("children"):
                for child in cyhy_request["children"]:
                    child_parent_dict[child] = cyhy_request["_id"]

            # Create contact info for each org
            for contact in cyhy_request["agency"]["contacts"]:
                if not contact.get("type"):
                    contact["type"] = "unspecified"
                contact_object = {
                    "org_id": cyhy_request["_id"],
                    "org_name": cyhy_request["agency"]["name"],
                    "phone": contact.get("phone"),
                    "contact_type": contact.get("type"),
                    "email": contact.get("email"),
                    "name": contact.get("name"),
                    "date_pulled": datetime.datetime.today().date(),
                }
                contact_list.append(contact_object)

            # # Replace mismatching cyhy org ids. For example, Treasury should be TREASURY
            # if cyhy_request["_id"] in pe_org_map["cyhy_id"].values:
            #     new_org_id = pe_org_map.loc[
            #         pe_org_map["cyhy_id"] == cyhy_request["_id"], "pe_org_id"
            #     ].item()
            #     LOGGER.info("Replacing %s with %s", cyhy_request["_id"], new_org_id)
            #     cyhy_request["_id"] = new_org_id

            # Create network dictionary for CIDRs and IPs
            for network in cyhy_request["networks"]:
                cidr_dict = {
                    "org_id": cyhy_request["_id"],
                    "org_name": cyhy_request["agency"]["name"],
                    "contact": str(cyhy_request["agency"]["contacts"]),
                    "network": network,
                    "first_seen": datetime.datetime.today().date(),
                    "last_seen": datetime.datetime.today().date(),
                }
                if "/" in network:
                    cidr_dict["type"] = "cidr"
                else:
                    cidr_dict["type"] = "ip"
                assets.append(cidr_dict)

        else:
            continue

    LOGGER.info("%d total assets found.", len(assets))

    # Create DataFrames from the json lists
    cyhy_agency_df = pd.DataFrame(cyhy_agencies)
    assets_df = pd.DataFrame(assets)
    contacts_df = pd.DataFrame(contact_list)

    # Insert CyHy assets into the P&E database
    insert_assets(pe_db_conn, assets_df, "cyhy_db_assets")

    # Drop duplicates in contacts and insert into P&E database
    contacts_df.drop_duplicates(
        subset=["org_id", "name", "contact_type", "email"],
        inplace=True,
        ignore_index=True,
    )
    insert_contacts(pe_db_conn, contacts_df, "cyhy_contacts")

    # Insert CyHy agencies into the P&E database
    insert_cyhy_agencies(pe_db_conn, cyhy_agency_df)

    # For each parent/child relationship,
    # add the parent's org_uid to the child org
    LOGGER.info("Update parent/child relationships")
    pe_orgs = query_pe_orgs(pe_db_conn)
    for child_name, parent_name in child_parent_dict.items():
        parent_uid = pe_orgs.loc[
            pe_orgs["cyhy_db_name"] == parent_name, "organizations_uid"
        ].item()
        update_child_parent_orgs(pe_db_conn, parent_uid, child_name)

        parent_report_on = pe_orgs.loc[
            pe_orgs["cyhy_db_name"] == parent_name, "report_on"
        ].item()
        if parent_report_on:
            update_scan_status(pe_db_conn, child_name)

        # TODO: If FCEB set fceb_child to true so that all BOD/scorecard calculations also consider these

    # Scrape dot gov domains and insert into P&E database
    LOGGER.info("Lookup and insert dot_gov domains.")
    dotgov_df = dotgov_domains()
    insert_dot_gov_domains(pe_db_conn, dotgov_df, "dotgov_domains")

    # Identify org changes. If an asset's last seen field is not today,
    # then mark set currently_in_cyhy to False
    LOGGER.info("Identify changes in cyhy_db_assets table")
    identify_org_asset_changes(pe_db_conn)

    pe_db_conn.close()
    return 0


def main():
    """Connect to CyHy DB and update org information and assets."""
    get_cyhy_assets()


if __name__ == "__main__":
    main()
