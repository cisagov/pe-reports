"""Collect Cybersixgill data."""

# Standard Python Libraries
from datetime import date, datetime, timedelta
import sys
import traceback

# cisagov Libraries
from pe_reports import app

from .data.pe_db.db_query_source import (
    get_breaches,
    get_data_source_uid,
    get_orgs,
    insert_sixgill_alerts,
    insert_sixgill_breaches,
    insert_sixgill_credentials,
    insert_sixgill_mentions,
    insert_sixgill_topCVEs,
)
from .data.sixgill.api import get_sixgill_organizations
from .data.sixgill.source import (
    alerts,
    alias_organization,
    all_assets_list,
    creds,
    cve_summary,
    get_alerts_content,
    mentions,
    root_domains,
    top_cves,
)

LOGGER = app.config["LOGGER"]

# Set todays date formatted YYYY-MM-DD and the start_date 30 days prior
TODAY = date.today()
DAYS_BACK = timedelta(days=30)
MENTIONS_DAYS_BACK = timedelta(days=16)
MENTIONS_START_DATE = str(TODAY - MENTIONS_DAYS_BACK)
END_DATE = str(TODAY)
DATE_SPAN = f"[{MENTIONS_START_DATE} TO {END_DATE}]"

# Set dates to YYYY-MM-DD H:M:S format
NOW = datetime.now()
START_DATE_TIME = (NOW - DAYS_BACK).strftime("%Y-%m-%d %H:%M:%S")
END_DATE_TIME = NOW.strftime("%Y-%m-%d %H:%M:%S")


class Cybersixgill:
    """Fetch Cybersixgill data."""

    def __init__(self, orgs_list, method_list):
        """Initialize Cybersixgill class."""
        self.orgs_list = orgs_list
        self.method_list = method_list

    def run_cybersixgill(self):
        """Run Cybersixgill api calls."""
        orgs_list = self.orgs_list
        method_list = self.method_list

        # Get org info from PE database
        pe_orgs = get_orgs()

        # Get Cybersixgill org info
        sixgill_orgs = get_sixgill_organizations()
        failed = []
        count = 0

        # Get data source uid
        source_uid = get_data_source_uid("Cybersixgill")

        # Run top CVEs. Same for all orgs
        if "topCVEs" in method_list:
            if self.get_topCVEs(source_uid) == 1:
                failed.append("Top CVEs")

        for pe_org in pe_orgs:
            org_id = pe_org["cyhy_db_name"]
            pe_org_uid = pe_org["org_uid"]
            # Only run on specified orgs
            if org_id in orgs_list or orgs_list == "all":
                count += 1
                # Get sixgill_org_id associated with the PE org
                try:
                    sixgill_org_id = sixgill_orgs[org_id][5]
                except KeyError as err:
                    LOGGER.error("PE org is not listed in Cybersixgill.")
                    LOGGER.error(err, file=sys.stderr)
                    failed.append("%s not in sixgill" % org_id)
                    continue

                # Run alerts
                if "alerts" in method_list:
                    if (
                        self.get_alerts(org_id, sixgill_org_id, pe_org_uid, source_uid)
                        == 1
                    ):
                        failed.append("%s alerts" % org_id)
                # Run mentions
                if "mentions" in method_list:
                    if (
                        self.get_mentions(
                            org_id, sixgill_org_id, pe_org_uid, source_uid
                        )
                        == 1
                    ):
                        failed.append("%s mentions" % org_id)
                # Run credentials
                if "credentials" in method_list:
                    if (
                        self.get_credentials(
                            org_id, sixgill_org_id, pe_org_uid, source_uid
                        )
                        == 1
                    ):
                        failed.append("%s credentials" % org_id)
        if len(failed) > 0:
            LOGGER.error("Failures: %s", failed)

    def get_alerts(self, org_id, sixgill_org_id, pe_org_uid, source_uid):
        """Get alerts."""
        LOGGER.info("Fetching alert data for %s.", org_id)

        # Fetch alert data with sixgill_org_id
        try:
            alerts_df = alerts(sixgill_org_id)
            # Add pe_org_id
            alerts_df["organizations_uid"] = pe_org_uid
            # Add data source uid
            alerts_df["data_source_uid"] = source_uid
            # Rename columns
            alerts_df = alerts_df.rename(columns={"id": "sixgill_id"})
        except Exception as e:
            LOGGER.error("Failed fetching alert data for %s", org_id)
            LOGGER.error(e)
            LOGGER.error(traceback.format_exc())
            return 1

        # Get Alert content
        try:
            LOGGER.info("Fetching alert content data for %s.", org_id)

            # Fetch organization assets
            org_assets_dict = all_assets_list(sixgill_org_id)
            for i, row in alerts_df.iterrows():
                try:
                    alert_id = row["sixgill_id"]
                    content_snip, asset_mentioned, asset_type = get_alerts_content(
                        sixgill_org_id, alert_id, org_assets_dict
                    )
                    alerts_df.at[i, "content_snip"] = content_snip
                    alerts_df.at[i, "asset_mentioned"] = asset_mentioned
                    alerts_df.at[i, "asset_type"] = asset_type
                except Exception as e:
                    LOGGER.error(
                        "Failed fetching a specific alert content for %s", org_id
                    )
                    LOGGER.error(e)
                    alerts_df.at[i, "content_snip"] = ""
                    alerts_df.at[i, "asset_mentioned"] = ""
                    alerts_df.at[i, "asset_type"] = ""
            LOGGER.info(alerts_df["asset_mentioned"])

        except Exception as e:
            LOGGER.error("Failed fetching alert content for %s", org_id)
            LOGGER.error(e)
            LOGGER.error(traceback.format_exc())
            return 1

        # Insert alert data into the PE database
        try:
            insert_sixgill_alerts(alerts_df)
        except Exception as e:
            LOGGER.error("Failed inserting alert data for %s", org_id)
            LOGGER.error(e)
            return 1
        return 0

    def get_mentions(self, org_id, sixgill_org_id, pe_org_uid, source_uid):
        """Get mentions."""
        LOGGER.info("Fetching mention data for %s.", org_id)

        # Fetch org aliases from Cybersixgill
        try:
            aliases = alias_organization(sixgill_org_id)
        except Exception as e:
            LOGGER.error("Failed fetching aliases for %s", org_id)
            LOGGER.error(e)
            return 1

        # Fetch mention data
        try:
            mentions_df = mentions(DATE_SPAN, aliases)
            mentions_df = mentions_df.rename(columns={"id": "sixgill_mention_id"})
            mentions_df["organizations_uid"] = pe_org_uid
            # Add data source uid
            mentions_df["data_source_uid"] = source_uid
        except Exception as e:
            LOGGER.error("Failed fetching mentions for %s", org_id)
            LOGGER.error(e)
            return 1

        # Insert mention data into the PE database
        try:
            insert_sixgill_mentions(mentions_df)
        except Exception as e:
            LOGGER.error("Failed inserting mentions for %s", org_id)
            LOGGER.error(e)
            return 1
        return 0

    def get_credentials(self, org_id, sixgill_org_id, pe_org_uid, source_uid):
        """Get credentials."""
        LOGGER.info("Fetching credential data for %s.", org_id)

        # Fetch org root domains from Cybersixgill
        try:
            roots = root_domains(sixgill_org_id)
        except Exception as e:
            LOGGER.error("Failed fetching root domains for %s", org_id)
            LOGGER.error(e)
            return 1

        # Fetch credential data
        try:
            creds_df = creds(roots, START_DATE_TIME, END_DATE_TIME)
            creds_df["organizations_uid"] = pe_org_uid
            # Add data source uid
            creds_df["data_source_uid"] = source_uid
        except Exception as e:
            LOGGER.error("Failed fetching credentials for %s", org_id)
            LOGGER.error(e)
            return 1

        if creds_df.empty:
            LOGGER.error("No credentials for %s", org_id)
            return 1

        # Change empty and ambiguous breach names
        try:
            creds_df.loc[
                creds_df["breach_name"] == "", "breach_name"
            ] = "Cybersixgill_" + creds_df["breach_id"].astype(str)

            creds_df.loc[
                creds_df["breach_name"] == "Automatic leaked credentials detection",
                "breach_name",
            ] = "Cybersixgill_" + creds_df["breach_id"].astype(str)
            creds_breach_df = creds_df[
                [
                    "breach_name",
                    "description",
                    "breach_date",
                    "password",
                    "data_source_uid",
                ]
            ].reset_index()

            # Create password_included column
            creds_breach_df["password_included"] = creds_breach_df["password"] != ""

            # Group breaches and count the number of credentials
            count_creds = creds_breach_df.groupby(
                [
                    "breach_name",
                    "description",
                    "breach_date",
                    "password_included",
                    "data_source_uid",
                ]
            ).size()
            creds_breach_df = count_creds.to_frame(
                name="exposed_cred_count"
            ).reset_index()
            creds_breach_df["modified_date"] = creds_breach_df["breach_date"]
            creds_breach_df.drop_duplicates(
                subset=["breach_name"], keep="first", inplace=True
            )
        except Exception as e:
            LOGGER.error("Probably no credential breaches for %s", org_id)
            LOGGER.error(e)
            return 1

        # Insert breach data into the PE database
        try:
            insert_sixgill_breaches(creds_breach_df)
        except Exception as e:
            LOGGER.error("Failed inserting breaches for %s", org_id)
            LOGGER.error(e)
            return 1

        # Get breach uids and match to credentials
        breach_dict = dict(get_breaches())
        for i, row in creds_df.iterrows():
            breach_uid = breach_dict[row["breach_name"]]
            creds_df.at[i, "credential_breaches_uid"] = breach_uid

        # Insert credential data into the PE database
        creds_df = creds_df.rename(
            columns={"domain": "sub_domain", "breach_date": "modified_date"}
        )
        creds_df = creds_df[
            [
                "modified_date",
                "sub_domain",
                "email",
                "hash_type",
                "name",
                "login_id",
                "password",
                "phone",
                "breach_name",
                "organizations_uid",
                "data_source_uid",
                "credential_breaches_uid",
            ]
        ]
        try:
            insert_sixgill_credentials(creds_df)
        except Exception as e:
            LOGGER.error("Failed inserting credentials for %s", org_id)
            LOGGER.error(e)
            return 1
        return 0

    def get_topCVEs(self, source_uid):
        """Get top CVEs."""
        LOGGER.info("Fetching top CVE data.")

        # Fetch top CVE data
        try:
            top_cve_df = top_cves(10)
            top_cve_df["date"] = END_DATE
            top_cve_df["nvd_base_score"] = top_cve_df["nvd_base_score"].astype("str")
            # Add data source uid
            top_cve_df["data_source_uid"] = source_uid
            # Get CVE summary from circl.lu
            top_cve_df["summary"] = ""
            for index, row in top_cve_df.iterrows():
                try:
                    resp = cve_summary(row["cve_id"])
                    summary = resp["summary"]
                except Exception:
                    summary = ""
                top_cve_df.at[index, "summary"] = summary
        except Exception as e:
            LOGGER.error("Failed fetching top CVEs.")
            LOGGER.error(e)
            return 1

        # Insert credential data into the PE database
        try:
            insert_sixgill_topCVEs(top_cve_df)
        except Exception as e:
            LOGGER.error("Failed inserting top CVEs.")
            LOGGER.error(e)
            return 1
        return 0
