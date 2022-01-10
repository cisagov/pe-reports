"""Collect Cybersixgill data."""

# Standard Python Libraries
from datetime import date, datetime, timedelta
import logging
import sys

from .data.pe_db.db_query import (
    get_orgs,
    insert_sixgill_alerts,
    insert_sixgill_credentials,
    insert_sixgill_mentions,
    insert_sixgill_topCVEs,
)
from .data.sixgill.api import get_sixgill_organizations
from .data.sixgill.source import (
    alerts,
    alias_organization,
    creds,
    cve_summary,
    mentions,
    root_domains,
    top_cves,
)

# Set todays date formatted YYYY-MM-DD and the start_date 30 days prior
TODAY = date.today()
DAYS_BACK = timedelta(days=30)
START_DATE = str(TODAY - DAYS_BACK)
END_DATE = str(TODAY)
DATE_SPAN = f"[{START_DATE} TO {END_DATE}]"

# Set todays date  and 30 days prior to YYY-MM-DD H:M:S format
NOW = datetime.now()
BACK = timedelta(days=30)
FROM_DATE = (NOW - BACK).strftime("%Y-%m-%d %H:%M:%S")
TO_DATE = NOW.strftime("%Y-%m-%d %H:%M:%S")


class Cybersixgill:
    """Fetch cybersixgill data."""

    def __init__(self, orgs_list, method_list):
        """Initialize cybersixgill class."""
        self.orgs_list = orgs_list
        self.method_list = method_list

    def run_cybersixgill(self):
        """Run cybersixgill api calls."""
        orgs_list = self.orgs_list
        method_list = self.method_list

        # Get org info from PE database
        pe_orgs = get_orgs()

        # Get sixgill org info
        sixgill_orgs = get_sixgill_organizations()
        failed = []
        count = 0

        # Run top CVEs. Same for all orgs
        if "topCVEs" in method_list:
            topCVEs = self.get_topCVEs()
            if topCVEs == 1:
                failed.append("Top CVEs")

        for pe_org in pe_orgs:
            org_id = pe_org[2]
            pe_org_uid = pe_org[0]
            # Only run on specified orgs
            if org_id in orgs_list or orgs_list == "all":
                count += 1
                # Get sixgill_org_id associated with the PE org
                try:
                    sixgill_org_id = sixgill_orgs[org_id][5]
                except KeyError as err:
                    logging.error("PE org is not listed in Cybersixgill.")
                    print(err, file=sys.stderr)
                    failed.append(f"{org_id} not in sixgill")
                    continue

                # Run alerts
                if "alerts" in method_list:
                    alert = self.get_alerts(org_id, sixgill_org_id, pe_org_uid)
                    if alert == 1:
                        failed.append(f"{org_id} alerts")
                # Run mentions
                if "mentions" in method_list:
                    mention = self.get_mentions(org_id, sixgill_org_id, pe_org_uid)
                    if mention == 1:
                        failed.append(f"{org_id} mentions")
                # Run credentials
                if "credentials" in method_list:
                    cred = self.get_credentials(org_id, sixgill_org_id, pe_org_uid)
                    if cred == 1:
                        failed.append(f"{org_id} credentials")
        if len(failed) > 0:
            logging.error(f"Failures: {failed}")

    def get_alerts(self, org_id, sixgill_org_id, pe_org_uid):
        """Get alerts."""
        logging.info(f"Fetching alert data for {org_id}.")

        # Fetch alert data with sixgill_org_id
        try:
            alerts_df = alerts(sixgill_org_id)
            # Add pe_org_id
            alerts_df["organizations_uid"] = pe_org_uid
            # Rename columns
            alerts_df = alerts_df.rename(columns={"id": "sixgill_id"})
        except Exception as e:
            logging.error(f"Failed fetching alert data for {org_id}")
            logging.error(e)
            return 1

        # Insert alert data into the PE database
        try:
            insert_sixgill_alerts(alerts_df)
        except Exception as e:
            logging.error(f"Failed inserting alert data for {org_id}")
            logging.error(e)
            return 1
        return 0

    def get_mentions(self, org_id, sixgill_org_id, pe_org_uid):
        """Get mentions."""
        logging.info(f"Fetching mention data for {org_id}.")

        # Fetch org aliases from cybersix
        try:
            aliases = alias_organization(sixgill_org_id)
        except Exception as e:
            logging.error(f"Failed fetching aliases for {org_id}")
            logging.error(e)
            return 1

        # Fetch mention data
        try:
            mentions_df = mentions(DATE_SPAN, aliases)
            mentions_df = mentions_df.rename(columns={"id": "sixgill_mention_id"})
            mentions_df["organizations_uid"] = pe_org_uid
        except Exception as e:
            logging.error(f"Failed fetching mentions for {org_id}")
            logging.error(e)
            return 1

        # Insert mention data into the PE database
        try:
            insert_sixgill_mentions(mentions_df)
        except Exception as e:
            logging.error(f"Failed inserting mentions for {org_id}")
            logging.error(e)
            return 1
        return 0

    def get_credentials(self, org_id, sixgill_org_id, pe_org_uid):
        """Get credentials."""
        logging.info(f"Fetching credential data for {org_id}.")

        # Fetch org root domains from cybersix
        try:
            roots = root_domains(sixgill_org_id)
        except Exception as e:
            logging.error(f"Failed fetching root domains for {org_id}")
            logging.error(e)
            return 1

        # Fetch credential data
        try:
            creds_df = creds(roots, FROM_DATE, TO_DATE)
            creds_df["organizations_uid"] = pe_org_uid
        except Exception as e:
            logging.error(f"Failed fetching credentials for {org_id}")
            logging.error(e)
            return 1

        # Insert credential data into the PE database
        try:
            insert_sixgill_credentials(creds_df)
        except Exception as e:
            logging.error(f"Failed inserting credentials for {org_id}")
            logging.error(e)
            return 1
        return 0

    def get_topCVEs(self):
        """Get top CVEs."""
        logging.info("Fetching top CVE data.")

        # Fetch top CVE data
        try:
            top_cve_df = top_cves(10)
            top_cve_df["date"] = END_DATE
            top_cve_df["nvd_base_score"] = top_cve_df["nvd_base_score"].astype("str")
            # Get CVE description from circl.lu
            top_cve_df["summary"] = ""
            for index, row in top_cve_df.iterrows():
                try:
                    resp = cve_summary(row["cve_id"])
                    summary = resp["summary"]
                except Exception:
                    summary = ""
                top_cve_df.at[index, "summary"] = summary
        except Exception as e:
            logging.error("Failed fetching top CVEs.")
            logging.error(e)
            return 1

        # Insert credential data into the PE database
        try:
            insert_sixgill_topCVEs(top_cve_df)
        except Exception as e:
            logging.error("Failed inserting topCVEs.")
            logging.error(e)
            return 1
        return 0
