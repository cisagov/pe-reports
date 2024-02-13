"""Collect DNSMonitor data."""

# Standard Python Libraries
import datetime
import logging

from .data.pe_db.db_query_source import (
    execute_hibp_breach_values,
    execute_hibp_emails_values,
    get_data_source_uid,
    get_emails,
    get_hibp_breaches,
    get_orgs,
    query_db,
    query_PE_subs,
)

NOW = datetime.datetime.now()
DAYS_BACK = datetime.timedelta(days=20)
DAY = datetime.timedelta(days=1)
START_DATE = NOW - DAYS_BACK
END_DATE = NOW + DAY

LOGGER = logging.getLogger(__name__)


class Hibp:
    """Fetch HIBP data."""

    def __init__(self, orgs_list):
        """Initialize Shodan class."""
        self.orgs_list = orgs_list

    def run_hibp(self):
        """Run HIBP calls."""
        orgs_list = self.orgs_list
        # Get org info from PE database
        all_pe_orgs = get_orgs()

        pe_orgs_final = []
        if orgs_list == "all":
            for pe_org in all_pe_orgs:
                if pe_org["report_on"]:
                    pe_orgs_final.append(pe_org)
                else:
                    continue
        elif orgs_list == "DEMO":
            for pe_org in all_pe_orgs:
                if pe_org["demo"]:
                    pe_orgs_final.append(pe_org)
                else:
                    continue
        else:
            for pe_org in all_pe_orgs:
                if pe_org["cyhy_db_name"] in orgs_list:
                    pe_orgs_final.append(pe_org)
                else:
                    continue

        try:
            source_uid = get_data_source_uid("HaveIBeenPwnd")
            LOGGER.info("Success fetching the data source")
        except Exception:
            LOGGER.error("Failed fetching the data source.")

        breaches = get_hibp_breaches()
        compiled_breaches = breaches[1]
        b_list = []
        for breach in compiled_breaches.values():
            # LOGGER.info(breach)
            breach_dict = {
                "breach_name": breach["breach_name"],
                "description": breach["description"],
                "exposed_cred_count": breach["exposed_cred_count"],
                "breach_date": breach["breach_date"],
                "added_date": breach["added_date"],
                "modified_date": breach["modified_date"],
                "data_classes": breach["data_classes"],
                "password_included": breach["password_included"],
                "is_verified": breach["is_verified"],
                "is_fabricated": breach["is_fabricated"],
                "is_sensitive": breach["is_sensitive"],
                "is_retired": breach["is_retired"],
                "is_spam_list": breach["is_spam_list"],
                "data_source_uid": source_uid,
            }
            b_list.append(breach_dict)

        execute_hibp_breach_values(b_list, "public.credential_breaches")
        sql = """SELECT breach."breach_name", breach."credential_breaches_uid" from public.credential_breaches as breach"""
        breaches_UIDs = query_db(sql)
        # Create a dictionary of each breach: UID combo
        breach_UIDS_Dict = {}
        for UID in breaches_UIDs:
            breach_UIDS_Dict.update(
                {UID["breach_name"]: UID["credential_breaches_uid"]}
            )

        for pe_org in pe_orgs_final:
            pe_org_uid = pe_org["organizations_uid"]
            cyhy_id = pe_org["cyhy_db_name"]
            # LOGGER.info(cyhy_id)

            LOGGER.info(f"Running HIBP on {cyhy_id}")

            subs = query_PE_subs(pe_org_uid).sort_values(
                by="sub_domain", key=lambda col: col.str.count(".")
            )

            for sub_index, sub in subs.iterrows():
                sd = sub["sub_domain"]
                if sd.endswith(".gov"):
                    print(f"Finding breaches for {sd}")
                else:
                    continue
                try:
                    hibp_resp = get_emails(sd)
                except Exception as e:
                    LOGGER.info("Failed after 5 tries.")
                    LOGGER.info(e)
                    continue
                if hibp_resp:
                    # LOGGER.info(emails)
                    # flat = flatten_data(emails, sub['name'], compiled_breaches)
                    creds_list = []
                    for email, breach_list in hibp_resp.items():
                        # LOGGER.info(emails)
                        # for email, breach_list in emails.items():
                        subdomain = sd
                        root_domain = sub["root_domain"]
                        for b in breach_list:
                            try:
                                cred = {
                                    "email": email + "@" + subdomain,
                                    "organizations_uid": pe_org_uid,
                                    "root_domain": root_domain,
                                    "sub_domain": subdomain,
                                    "modified_date": compiled_breaches[b][
                                        "modified_date"
                                    ],
                                    "breach_name": b,
                                    "credential_breaches_uid": breach_UIDS_Dict[b],
                                    "data_source_uid": source_uid,
                                    "name": None,
                                }
                                creds_list.append(cred)
                            except Exception as e:
                                LOGGER.info("error adding cred to cred_list")
                                LOGGER.info(e)
                    LOGGER.info("\t\tthere are %s creds found", len(creds_list))
                    # Insert new creds into the PE DB
                    execute_hibp_emails_values(creds_list)
