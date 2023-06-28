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
from pe_asm.data.cyhy_db_query import (  # get_pe_org_map,; updated_scorecard_child_status,
    add_sector_hierachy,
    identify_org_asset_changes,
    insert_assets,
    insert_contacts,
    insert_cyhy_agencies,
    insert_dot_gov_domains,
    insert_sector_org_relationship,
    insert_sectors,
    mongo_connect,
    pe_db_connect,
    pe_db_staging_connect,
    query_pe_orgs,
    query_pe_sectors,
    update_child_parent_orgs,
    update_fceb_child_status,
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

    # categories = collection.find({'agency.type' : {"$exists": False } })

    # Loop through all CyHy agencies
    cyhy_agencies = []
    assets = []
    contact_list = []
    child_parent_dict = {}
    sector_info_list = []
    sector_list = []
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
                "cyhy_period_start": cyhy_request.get("period_start"),
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
        # if in org does not have a type it is actually a sector or category and will be put in a separate table
        else:
            # Add to sector ids to sector_list
            sector_list.append(cyhy_request["_id"])
            # Create a dictionary of sector data
            sector_dict = {
                "id": cyhy_request["_id"],
                "acronym": cyhy_request["agency"].get("acronym", ""),
                "name": cyhy_request["agency"].get("name", "No Name"),
                "children": cyhy_request.get("children", []),
                "password": cyhy_request.get("key", ""),
                "retired": cyhy_request.get("retired", False),
            }
            # if only one contact is available add it to the dictionary
            if len(cyhy_request["agency"]["contacts"]) == 1:
                sector_dict["email"] = cyhy_request["agency"]["contacts"][0]["email"]
                sector_dict["contact_name"] = cyhy_request["agency"]["contacts"][0][
                    "name"
                ]
            # if multiple contacts are identified save the DISTRO email to the dictionary
            elif len(cyhy_request["agency"]["contacts"]) > 1:
                for i in range(len(cyhy_request["agency"]["contacts"])):
                    if cyhy_request["agency"]["contacts"][i]["type"] == "DISTRO":
                        sector_dict["email"] = cyhy_request["agency"]["contacts"][i][
                            "email"
                        ]
                        sector_dict["contact_name"] = cyhy_request["agency"][
                            "contacts"
                        ][i]["name"]
            # if no contact is found add None
            else:
                sector_dict["email"] = None
                sector_dict["contact_name"] = None
            # since ROOT and DOD are not sectors ignore them
            if sector_dict["acronym"] in ["ROOT", "DOD"]:
                continue
            # append dictionary to list
            else:
                sector_info_list.append(sector_dict)

    LOGGER.info("%d total assets found.", len(assets))

    # Create DataFrames from the json lists
    cyhy_agency_df = pd.DataFrame(cyhy_agencies)
    assets_df = pd.DataFrame(assets)
    contacts_df = pd.DataFrame(contact_list)

    # insert all sectors into the pe_database
    insert_sectors(pe_db_conn, sector_info_list)
    # query back all pe_sectors
    pe_sectors = query_pe_sectors(pe_db_conn)
    # create a list of sector ids for orgs that are flagged to run_scorecards
    # scorecard_sectors = pe_sectors[pe_sectors['run_scorecards'] == True]['id'].values.tolist()

    # fill a list of all the children orgs or sectors of sectors flagged to run_scorecards
    # scorecard_orgs = []
    # for sector in sector_info_list:
    #     if sector['id'] in scorecard_sectors:
    #         scorecard_orgs += sector['children']

    # # mark orgs that are directly related to
    # cyhy_agency_df['scorecard'] = cyhy_agency_df['cyhy_db_name'].isin(scorecard_orgs)

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
    if staging:
        pe_db_conn = pe_db_staging_connect()
    else:
        pe_db_conn = pe_db_connect()
    insert_cyhy_agencies(pe_db_conn, cyhy_agency_df)

    # Query PE orgs with uids
    pe_orgs = query_pe_orgs(pe_db_conn)
    sector_child_list = []
    sub_sector_list = []
    for sec in sector_info_list:
        # save uid of the current sector
        sector_uid = pe_sectors.loc[
            pe_sectors["acronym"] == sec["acronym"], "sector_uid"
        ].item()
        # loop through the sectors children, they can be orgs or sectors
        for child_agency in sec["children"]:
            # check if child is a sector
            if child_agency in sector_list:
                print(sec["id"])
                print(child_agency)
                # ignore child if it is DOD
                if child_agency == "DOD":
                    continue
                # append sector sector relationship
                sub_sector_list.append(
                    (
                        pe_sectors.loc[
                            pe_sectors["acronym"] == child_agency, "sector_uid"
                        ].item(),
                        sector_uid,
                    )
                )
            # if the child is an org
            else:
                # grab the org_uid
                child_uid = pe_orgs.loc[
                    pe_orgs["cyhy_db_name"] == child_agency, "organizations_uid"
                ].item()
                # append to child_sector relationship list
                if child_uid and sector_uid:
                    sector_child_list.append(
                        (
                            sector_uid,
                            child_uid,
                            datetime.datetime.today().date(),
                            datetime.datetime.today().date(),
                        )
                    )
    # insert sector org relationship
    insert_sector_org_relationship(pe_db_conn, sector_child_list)
    child_list = []
    # add relationship between sectors to database not allowing duplicate parents
    for relationship in sub_sector_list:
        if relationship[0] not in child_list:
            add_sector_hierachy(pe_db_conn, relationship[0], relationship[1])
            child_list.append(relationship[0])
        else:
            print(relationship[0] + " already has a sector parent")
            continue

    # For each parent/child relationship,
    # add the parent's org_uid to the child org
    LOGGER.info("Update parent/child relationships")
    for child_name, parent_name in child_parent_dict.items():
        parent_uid = pe_orgs.loc[
            pe_orgs["cyhy_db_name"] == parent_name, "organizations_uid"
        ].item()
        update_child_parent_orgs(pe_db_conn, parent_uid, child_name)

        parent_report_on = pe_orgs.loc[
            pe_orgs["cyhy_db_name"] == parent_name, "report_on"
        ].item()
        parent_fceb = pe_orgs.loc[pe_orgs["cyhy_db_name"] == parent_name, "fceb"].item()
        if parent_report_on:
            update_scan_status(pe_db_conn, child_name)

        # Set fceb_child
        if parent_fceb:
            update_fceb_child_status(pe_db_conn, child_name)

        # # For orgs whose parent is a scorecard mark scorecard
        # parent_scorecard = pe_orgs.loc[pe_orgs["cyhy_db_name"] == parent_name, "scorecard"].item()
        # if parent_scorecard:
        #     updated_scorecard_child_status(pe_db_conn, child_name)

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
