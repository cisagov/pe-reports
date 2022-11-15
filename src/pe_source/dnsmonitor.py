"""Collect DNSMonitor data."""

# Standard Python Libraries
import datetime
import logging

from .data.dnsmonitor.source import (
    get_dns_records,
    get_domain_alerts,
    get_monitored_domains,
)
from .data.pe_db.config import dnsmonitor_token
from .data.pe_db.db_query import (
    addSubdomain,
    execute_dnsmonitor_alert_data,
    execute_dnsmonitor_data,
    get_data_source_uid,
    get_orgs,
    getSubdomain,
)

NOW = datetime.datetime.now()
DAYS_BACK = datetime.timedelta(days=20)
DAY = datetime.timedelta(days=1)
START_DATE = NOW - DAYS_BACK
END_DATE = NOW + DAY

LOGGER = logging.getLogger(__name__)


class DNSMonitor:
    """Fetch DNSMonitor data."""

    def __init__(self, orgs_list):
        """Initialize Shodan class."""
        self.orgs_list = orgs_list

    def run_dnsMonitor(self):
        """Run DNSMonitor calls."""
        orgs_list = self.orgs_list

        # Get orgs from PE database
        pe_orgs = get_orgs()

        # Filter orgs if specified
        if orgs_list == "all":
            pe_orgs_final = pe_orgs
        else:
            pe_orgs_final = []
            for pe_org in pe_orgs:
                if pe_org["cyhy_db_name"] in orgs_list:
                    pe_orgs_final.append(pe_org)
                else:
                    continue

        # Fetch the bearer token
        token = dnsmonitor_token()
        # Get all of the Domains being monitored
        domain_df = get_monitored_domains(token)

        failed = []
        # Iterate through each org
        for org in pe_orgs_final:
            org_name = org["org_name"]
            org_uid = org["org_uid"]
            org_code = org["cyhy_db_name"]
            LOGGER.info("\nRunning DNSMonitor on %s", org_code)

            # Get respective domain IDs
            domain_ids = domain_df[domain_df["org"] == org_name]
            LOGGER.info("Found %s root domains being monitored.", len(domain_ids))
            domain_ids = str(domain_ids["domainId"].tolist())

            # Get Alerts for a specific org based on the list of domain IDs
            if domain_ids == "[]":
                LOGGER.error("Can't match org to any domains...")
                failed.append(f"{org_code} - No domains")
                continue
            else:
                alerts_df = get_domain_alerts(token, domain_ids, START_DATE, END_DATE)
                LOGGER.info("Fetched %s alerts.", len(alerts_df.index))

                # If no alerts, continue
                if alerts_df.empty:
                    LOGGER.error("No alerts for %s", org_code)
                    failed.append(f"{org_code} - No alerts")
                    continue

            for alert_index, alert_row in alerts_df.iterrows():
                # Get subdomain_uid
                root_domain = alert_row["rootDomain"]
                sub_domain = getSubdomain(root_domain)
                if not sub_domain:
                    LOGGER.info(
                        "Root domain, %s, isn't in subdomain table as a sub_domain.",
                        root_domain,
                    )
                    try:
                        addSubdomain(None, root_domain, org_uid)
                        LOGGER.info(
                            "Success adding %s to subdomain table.", root_domain
                        )
                    except Exception as e:
                        LOGGER.error("Failure adding root domain to subdomain table.")
                        LOGGER.error(e)
                        failed.append(
                            f"{org_code} - {root_domain} - Failed inserting into subdomain table"
                        )
                    sub_domain = getSubdomain(root_domain)

                # Add subdomain_uid to associated alert
                sub_domain_uid = sub_domain[0]
                alerts_df.at[alert_index, "sub_domain_uid"] = sub_domain_uid

                # Get DNS records for each domain permutation
                dom_perm = alert_row["domainPermutation"]
                mx_list, ns_list, ipv4, ipv6 = get_dns_records(dom_perm)

                # Add records to the dataframe
                alerts_df.at[alert_index, "mail_server"] = mx_list
                alerts_df.at[alert_index, "name_server"] = ns_list
                alerts_df.at[alert_index, "ipv4"] = ipv4
                alerts_df.at[alert_index, "ipv6"] = ipv6

            # Set the data_source_uid and organization_uid
            alerts_df["data_source_uid"] = get_data_source_uid("DNSMonitor")
            alerts_df["organizations_uid"] = org_uid

            # Format dataframe and insert into domain_permutations table
            alerts_df = alerts_df.rename(
                columns={
                    "domainPermutation": "domain_permutation",
                    "dateCreated": "date_observed",
                    "alertType": "alert_type",
                    "previousValue": "previous_value",
                    "newValue": "new_value",
                }
            )
            dom_perm_df = alerts_df[
                [
                    "organizations_uid",
                    "sub_domain_uid",
                    "data_source_uid",
                    "domain_permutation",
                    "ipv4",
                    "ipv6",
                    "mail_server",
                    "name_server",
                    "date_observed",
                ]
            ]
            dom_perm_df = dom_perm_df.drop_duplicates(
                subset=["domain_permutation"], keep="last"
            )
            try:
                execute_dnsmonitor_data(dom_perm_df, "domain_permutations")
                LOGGER.info("Success inserting into domain_permutations - %s", org_code)
            except Exception as e:
                LOGGER.error("Failed inserting into domain_permutations - %s", org_code)
                LOGGER.error(e)
                failed.append(f"{org_code} - Failed inserting into dom_perms")

            # Format dataframe and insert into domain_alerts table
            alerts_df = alerts_df.rename(columns={"date_observed": "date"})
            domain_alerts = alerts_df[
                [
                    "organizations_uid",
                    "sub_domain_uid",
                    "data_source_uid",
                    "alert_type",
                    "message",
                    "previous_value",
                    "new_value",
                    "date",
                ]
            ]
            try:
                execute_dnsmonitor_alert_data(domain_alerts, "domain_alerts")
                LOGGER.info("Success inserting into domain_alerts - %s", org_code)
            except Exception as e:
                LOGGER.error("Failed inserting into domain_alerts - %s", org_code)
                LOGGER.error(e)
                failed.append(f"{org_code} - Failed inserting into dom_alerts")

        # Output any failures
        if len(failed) > 0:
            LOGGER.error("Failures: %s", failed)
