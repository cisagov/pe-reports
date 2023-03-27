"""Collect IntelX credential leak data."""
# Standard Python Libraries
import datetime
import logging
import sys
import time

# Third-Party Libraries
import numpy as np
import pandas as pd
import requests

from .data.pe_db.config import get_params
from .data.pe_db.db_query_source import (
    connect,
    get_data_source_uid,
    get_intelx_breaches,
    get_orgs,
    insert_intelx_breaches,
    insert_intelx_credentials,
    org_root_domains,
)

# Calculate datetimes for collection period
TODAY = datetime.date.today()
DAYS_BACK = datetime.timedelta(days=16)
START_DATE = (TODAY - DAYS_BACK).strftime("%Y-%m-%d %H:%M:%S")
END_DATE = TODAY.strftime("%Y-%m-%d %H:%M:%S")


section = "intelx"
params = get_params(section)
api_key = params[0][1]

LOGGER = logging.getLogger(__name__)


class IntelX:
    """Fetch IntelX data."""

    def __init__(self, orgs_list):
        """Initialize IntelX class."""
        LOGGER.info("Initialized IntelX")
        self.orgs_list = orgs_list

    def run_intelx(self):
        """Run IntelX API calls."""
        orgs_list = self.orgs_list

        pe_orgs = get_orgs()
        for pe_org in pe_orgs:
            cyhy_org_id = pe_org["cyhy_db_name"]
            pe_org_uid = pe_org["org_uid"]

            # Verify the org is in the list of orgs to scan
            if cyhy_org_id in orgs_list or orgs_list == "all":
                if self.get_credentials(cyhy_org_id, pe_org_uid) == 1:
                    LOGGER.error("Failed to get credentials for %s", cyhy_org_id)

    def get_credentials(self, cyhy_org_id, pe_org_uid):
        """Get credentials for a provided org."""
        LOGGER.info("Fetching credential data for %s.", cyhy_org_id)
        source_uid = get_data_source_uid("IntelX")
        try:
            conn = connect()
            roots_df = org_root_domains(conn, pe_org_uid)
            LOGGER.info("Got roots for %s", cyhy_org_id)
        except Exception as e:
            LOGGER.error("Failed fetching root domains for %s", cyhy_org_id)
            LOGGER.error(e)
            return 1

        leaks_json = self.find_credential_leaks(
            roots_df["root_domain"].values.tolist(), START_DATE, END_DATE
        )
        if len(leaks_json) < 1:
            LOGGER.info("No credentials found for %s", cyhy_org_id)
            return 0
        creds_df, breaches_df = self.process_leaks_results(leaks_json, pe_org_uid)
        # Insert breach data into the PE database
        try:
            insert_intelx_breaches(breaches_df)
        except Exception as e:
            LOGGER.error("Failed inserting IntelX breaches for %s", cyhy_org_id)
            LOGGER.error(e)
            return 1

        breach_dict = get_intelx_breaches(source_uid)
        breach_dict = dict(breach_dict)
        for cred_index, cred_row in creds_df.iterrows():
            breach_uid = breach_dict[cred_row["breach_name"]]
            creds_df.at[cred_index, "credential_breaches_uid"] = breach_uid
        try:
            insert_intelx_credentials(creds_df)
        except Exception as e:
            LOGGER.error("Failed inserting IntelX credentials for %s", cyhy_org_id)
            LOGGER.error(e)
            return 1
        return 0

    def query_identity_api(self, domain, start_date, end_date):
        """Create an initial search and return the search id."""
        url = f"https://3.intelx.io/accounts/csv?selector={domain}&k={api_key}&datefrom={start_date}&dateto={end_date}"
        payload = {}
        headers = {}
        attempts = 0
        while True:
            try:
                response = requests.request("GET", url, headers=headers, data=payload)
                break
            except requests.exceptions.Timeout:
                time.sleep(5)
                attempts += 1
                if attempts == 5:
                    LOGGER.error("IntelX Identity is not responding. Exiting program.")
                    sys.exit()
                LOGGER.info("IntelX Identity API response timed out. Trying again.")
            except Exception as e:
                LOGGER.error("Error occurred getting search id: %s", e)
                return 0
        LOGGER.info("Acquired search id.")
        time.sleep(5)
        return response.json()

    def get_search_results(self, id):
        """Search IntelX for email leaks."""
        url = f"https://3.intelx.io/live/search/result?id={id}&format=1&k={api_key}"

        payload = {}
        headers = {}
        attempts = 0
        while True:
            try:
                response = requests.request("GET", url, headers=headers, data=payload)
                break
            except requests.exceptions.Timeout:
                time.sleep(5)
                attempts += 1
                if attempts == 5:
                    LOGGER.error("IntelX Identity is not responding. Exiting program.")
                    sys.exit()
                LOGGER.info("IntelX Identity API response timed out. Trying again.")
            except Exception as e:
                LOGGER.error(f"Error occurred getting search results: {e}")
                return 0
        response = response.json()

        return response

    def find_credential_leaks(self, domain_list, start_date, end_date):
        """Find leaks for a domain between two dates."""
        all_results_list = []
        for domain in domain_list:
            LOGGER.info("Finding credentials leaked associated with %s", domain)
            response = self.query_identity_api(domain, start_date, end_date)
            if not response:
                continue
            search_id = response["id"]
            while True:
                results = self.get_search_results(search_id)
                if not results:
                    break
                if results["status"] == 0:
                    current_results = results["records"]
                    if current_results:
                        # Add the root_domain to each result object
                        LOGGER.info(
                            "IntelX returned %s more credentials for %s",
                            len(current_results),
                            domain,
                        )
                        result = [
                            dict(item, **{"root_domain": domain})
                            for item in current_results
                        ]
                        all_results_list = all_results_list + result
                    time.sleep(3)
                # If still waiting on new results wait
                elif results["status"] == 1:
                    LOGGER.info("IntelX still searching for more credentials")
                    time.sleep(7)
                # if status is two collect the last remaining values and exit loop
                elif results["status"] == 2:
                    current_results = results["records"]
                    if current_results:
                        # Add the root_domain to each result object
                        LOGGER.info(
                            "IntelX returned %s more credentials for %s",
                            len(current_results),
                            domain,
                        )
                        result = [
                            dict(item, **{"root_domain": domain})
                            for item in current_results
                        ]
                        all_results_list = all_results_list + result
                    break
                elif results["status"] == 3:
                    LOGGER.error("Search id not found")
                    break
        LOGGER.info("Identified %s credential leak combos.", len(all_results_list))
        return all_results_list

    def process_leaks_results(self, leaks_json, org_uid):
        """Prepare and format credentials and breach dataframes."""
        # Convert json into a dataframe
        all_df = pd.DataFrame.from_dict(leaks_json)

        # format email to all lowercase and remove duplicates
        all_df["user"] = all_df["user"].str.lower()
        LOGGER.info("%s unique emails found", all_df["user"].nunique())
        LOGGER.info("%s unique posts", all_df["sourceshort"].nunique())
        all_df = all_df.drop_duplicates(subset=["user", "sourceshort"], keep="first")
        LOGGER.info(
            "%s emails found after removing duplicates in the same post",
            len(leaks_json),
        )

        # Format date
        all_df["datetime"] = pd.to_datetime(all_df["date"])
        all_df["date"] = all_df["datetime"].dt.strftime("%Y-%m-%d")

        # Create boolean column for if password is included
        all_df["password_included"] = np.where(
            (pd.isna(all_df["password"])) | (all_df["password"] == ""), 0, 1
        )
        # Create new column for subdomain, organization uid, and data source uid
        all_df["sub_domain"] = all_df["user"].str.split("@").str[1]
        all_df["organizations_uid"] = org_uid
        all_df["data_source_uid"] = get_data_source_uid("IntelX")

        # rename fields to match database
        all_df.rename(
            columns={
                "user": "email",
                "sourceshort": "breach_name",
                "date": "modified_date",
                "systemid": "intelx_system_id",
                "passwordtype": "hash_type",
            },
            inplace=True,
        )

        creds_df = all_df[
            [
                "email",
                "organizations_uid",
                "root_domain",
                "sub_domain",
                "breach_name",
                "modified_date",
                "data_source_uid",
                "password",
                "hash_type",
                "intelx_system_id",
            ]
        ].reset_index(drop=True)

        # group results by breaches
        breaches_df = all_df.groupby(
            ["breach_name", "modified_date", "bucket", "data_source_uid"]
        ).aggregate({"email": "count", "password_included": "sum"})
        breaches_df = breaches_df.reset_index()
        breaches_df["password_included"] = breaches_df["password_included"] > 0

        breaches_df.rename(columns={"email": "exposed_cred_count"}, inplace=True)
        # Build breach description
        breaches_df["description"] = (
            breaches_df["breach_name"]
            + " was identified on "
            + breaches_df["modified_date"]
            + ". The post "
            + (
                "does not contain"
                if breaches_df["password_included"] is True
                else "contains"
            )
            + " passwords. It falls in the following category: "
            + breaches_df["bucket"]
        )

        breaches_df["breach_date"] = breaches_df["modified_date"]
        breaches_df["added_date"] = breaches_df["modified_date"]
        breaches_df = breaches_df[
            [
                "breach_name",
                "description",
                "breach_date",
                "added_date",
                "modified_date",
                "password_included",
                "data_source_uid",
            ]
        ]

        return creds_df, breaches_df
