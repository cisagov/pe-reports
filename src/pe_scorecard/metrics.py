"""Calculations for scorecard metrics."""
# Standard Python Libraries
import calendar
import datetime
import json
import logging

# Third-Party Libraries
from bs4 import BeautifulSoup
import numpy as np
import pandas as pd
import requests

from .data.db_query import (
    find_last_data_updated,
    find_last_scan_date,
    get_scorecard_metrics_past,
    query_certs_counts,
    query_domain_counts,
    query_https_scan,
    query_ips_counts,
    query_kev_list,
    query_open_vulns,
    query_profiling_views,
    query_software_scans,
    query_sslyze_scan,
    query_trusty_mail,
    query_vuln_tickets,
    query_webapp_counts,
)
from .unified_scorecard_generator import create_scorecard

BOD1801_DMARC_RUA_URI = "mailto:reports@dmarc.cyber.dhs.gov"
# Setup logging to central
LOGGER = logging.getLogger(__name__)


class Scorecard:
    """Class to generate scorecard metrics."""

    def __init__(
        self,
        month,
        year,
        org_data,
        org_uid_list,
        cyhy_id_list,
        vs_time_to_remediate,
        vs_fceb_results,
        was_fceb_ttr,
    ):
        """Initialize scorecard class."""
        self.org_data = org_data
        self.scorecard_dict = {
            "agency_name": org_data["name"],
            "agency_id": org_data["cyhy_db_name"],
            "sector_name": "FCEB" if org_data["fceb"] is True else "Sector",
            "date": calendar.month_name[int(month)] + " " + year,
            "data_pulled_date": find_last_scan_date()[0].strftime("%b %d, %Y"),
        }

        last_updated = find_last_data_updated(cyhy_id_list)[0]

        if not last_updated:
            last_updated = org_data["cyhy_period_start"].strftime("%b %d, %Y")
        else:
            last_updated = last_updated.strftime("%b %d, %Y")

        self.scorecard_dict["last_data_sent_date"] = last_updated

        start_date = datetime.date(int(year), int(month), 1)
        end_date = (start_date + datetime.timedelta(days=32)).replace(day=1)
        self.start_date = start_date
        self.end_date = end_date
        self.org_uid_list = org_uid_list
        self.cyhy_id_list = cyhy_id_list

        self.scorecard_dict["start_date"] = start_date
        self.scorecard_dict["end_date"] = end_date
        self.scorecard_dict["organizations_uid"] = org_data["organizations_uid"]

        # TODO: Actually calculate these. This is just a placeholder
        self.scorecard_dict["overall_score"] = None
        self.scorecard_dict["discovery_score"] = None
        self.scorecard_dict["profiling_score"] = None
        self.scorecard_dict["identification_score"] = None
        self.scorecard_dict["tracking_score"] = None

        self.ip_counts = query_ips_counts(org_uid_list)
        self.domain_counts = query_domain_counts(org_uid_list)
        # # TODO possibly need to format a date string based on the new column
        self.webapp_counts = query_webapp_counts(start_date, org_uid_list)
        self.cert_counts = query_certs_counts()

        # self.ports_data = query_cyhy_port_scans(start_date, end_date, org_uid_list)
        self.profiling_dict = query_profiling_views(start_date, org_uid_list)
        self.software_counts = query_software_scans(start_date, end_date, org_uid_list)

        self.vs_vuln_counts = query_vuln_tickets(org_uid_list)
        # self.vs_remediation = query_vuln_remediation(start_date, end_date, org_uid_list)
        self.vs_remediation = vs_time_to_remediate
        self.vs_fceb_results = vs_fceb_results

        self.vs_open_vulns = query_open_vulns(org_uid_list)
        self.kev_list = query_kev_list()

        self.was_fceb_ttr = was_fceb_ttr
        # # TODO adjust queries parameters
        # self.sslyze_data = query_sslyze_scan(org_uid_list)
        # self.https_data = query_https_scan(org_uid_list,
        # )
        # self.trusty_mail_data = query_trusty_mail(org_uid_list)

    @staticmethod
    def get_percent_compliance(total, overdue):
        """Calculate percentage of compliance."""
        if total == 0:
            return 100
        else:
            return round(((total - overdue) / total) * 100, 2)

    @staticmethod
    def get_age(start_time, end_time):
        """Identify age of open vulnerability."""
        # if "." in start_time:
        #     start_time = start_time.split(".")[0]
        # start_time = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        start_time = start_time.timestamp()
        start_time = datetime.datetime.fromtimestamp(start_time, datetime.timezone.utc)
        start_time = start_time.replace(tzinfo=None)
        end_time = end_time.timestamp()
        end_time = datetime.datetime.fromtimestamp(end_time, datetime.timezone.utc)
        end_time = end_time.replace(tzinfo=None)
        age = round((float((end_time - start_time).total_seconds()) / 60 / 60 / 24), 2)
        return age

    def calculate_discovery_metrics_counts(self):
        """Summarize discovery findings into key metrics."""
        total_ips_df = self.ip_counts
        total_ips = total_ips_df["total_ips"].sum()

        total_identified_ips = total_ips_df["cidr_reported"].sum()

        self.scorecard_dict["ips_monitored"] = total_ips
        self.scorecard_dict["ips_identified"] = total_identified_ips
        if self.scorecard_dict["ips_identified"]:
            self.scorecard_dict["ips_monitored_pct"] = total_ips / (
                total_ips - total_identified_ips
            )
        else:
            self.scorecard_dict["ips_monitored_pct"] = None

        self.scorecard_dict["domains_monitored"] = (
            self.domain_counts["identified"].sum()
            + self.domain_counts["unidentified"].sum()
        )
        self.scorecard_dict["domains_identified"] = self.domain_counts[
            "unidentified"
        ].sum()

        if self.scorecard_dict["domains_identified"]:
            self.scorecard_dict["domains_monitored_pct"] = (
                self.scorecard_dict["domains_monitored"]
                / self.scorecard_dict["domains_identified"]
            )
        else:
            self.scorecard_dict["domains_monitored_pct"] = None
        # TODO add webapps
        webapp_df = self.webapp_counts
        self.scorecard_dict["webapps_identified"] = webapp_df["web_app_cnt"].sum()
        self.scorecard_dict["webapps_monitored"] = webapp_df["web_app_cnt"].sum()

        if self.scorecard_dict["webapps_identified"]:
            self.scorecard_dict["web_apps_monitored_pct"] = (
                self.scorecard_dict["webapps_monitored"]
                / self.scorecard_dict["webapps_identified"]
            )
        else:
            self.scorecard_dict["web_apps_monitored_pct"] = None
        # TODO add certs
        self.scorecard_dict["certs_identified"] = (
            self.cert_counts[0] if self.cert_counts[0] else 0
        )
        self.scorecard_dict["certs_monitored"] = (
            self.cert_counts[1] if self.cert_counts[1] else 0
        )

        if self.scorecard_dict["certs_identified"]:
            self.scorecard_dict["certs_monitored_pct"] = (
                self.scorecard_dict["certs_monitored"]
                / self.scorecard_dict["certs_identified"]
            )
        else:
            self.scorecard_dict["certs_monitored_pct"] = None

    def calculate_profiling_metrics(self):
        """Summarize profiling findings into key metrics."""
        profiling_dict = self.profiling_dict
        # print(ports_df)
        # insecure_protocols_list = [
        #         "rdp",
        #         "telnet",
        #         "ftp",
        #         "rpc",
        #         "smb",
        #         "sql",
        #         "ldap",
        #         "irc",
        #         "netbios",
        #         "kerberos",
        # ]
        # services_list = ["http", "https", "http-proxy"]
        # # ports_df.groupby(['ip', 'port']).ngroups
        # total_ports = set()  # *
        # insecure_ports = set()  # *
        # total_protocols = set()
        # insecure_protocols = set()
        # total_services = set()

        # ports_df
        # for index2, portscan in ports_df.iterrows():
        #     total_ports.add((portscan["ip"], portscan["port"]))
        #     # Currently this won't allow multiple risky services on the same port
        #     if (
        #         portscan["service_name"] in insecure_protocols_list
        #         and portscan["state"] == "open"
        #     ):
        #         insecure_ports.add((portscan["ip"], portscan["port"]))

        #     total_protocols.add((portscan["service_name"], portscan["port"]))
        #     if (
        #         portscan["service_name"] in insecure_protocols_list
        #         and portscan["state"] == "open"
        #     ):
        #         insecure_protocols.add((portscan["service_name"], portscan["port"]))

        #     if portscan["service_name"] in services_list:
        #         total_services.add((portscan["service_name"], portscan["port"]))

        # self.scorecard_dict["ports_total_count"] = len(total_ports)
        # self.scorecard_dict["ports_risky_count"] = len(insecure_ports)
        # self.scorecard_dict["protocol_total_count"] = len(total_protocols)
        # self.scorecard_dict["protocol_insecure_count"] = len(insecure_protocols)
        # self.scorecard_dict["services_total_count"] = len(total_services)
        self.scorecard_dict["ports_total_count"] = profiling_dict["ports_count"]
        self.scorecard_dict["ports_risky_count"] = profiling_dict["risky_ports_count"]
        self.scorecard_dict["protocol_total_count"] = profiling_dict["protocols_count"]
        self.scorecard_dict["protocol_insecure_count"] = profiling_dict[
            "risky_protocols_count"
        ]
        self.scorecard_dict["services_total_count"] = profiling_dict["services"]

        software_df = self.software_counts
        self.scorecard_dict["software_unsupported_count"] = software_df["count"].sum()

    def calculate_identification_metrics(self):
        """Summarize identification findings into key metrics."""
        vuln_counts = self.vs_vuln_counts
        self.scorecard_dict["external_host_kev"] = vuln_counts["kev"].sum()
        self.scorecard_dict["external_host_critical"] = vuln_counts["critical"].sum()
        self.scorecard_dict["external_host_high"] = vuln_counts["high"].sum()
        was_counts = self.webapp_counts
        self.scorecard_dict["webapp_kev"] = "N/A"
        self.scorecard_dict["webapp_critical"] = was_counts["crit_vuln_cnt"].sum()
        self.scorecard_dict["webapp_high"] = was_counts["high_vuln_cnt"].sum()

    def calculate_tracking_metrics(self):
        """Summarize tracking findings into key metrics."""
        vs_remediation_df = self.vs_remediation
        vs_remediation_df = vs_remediation_df.replace({np.NaN: None})
        print(vs_remediation_df)
        vuln_kev_attr = vs_remediation_df["weighted_kev"].sum()
        if vs_remediation_df["kev_count"].sum() == 0:
            self.scorecard_dict["vuln_org_kev_ttr"] = "N/A"
        else:
            self.scorecard_dict["vuln_org_kev_ttr"] = round(vuln_kev_attr)

        vuln_critical_attr = vs_remediation_df["weighted_critical"].sum()
        if vs_remediation_df["critical_count"].sum() == 0:
            self.scorecard_dict["vuln_org_critical_ttr"] = "N/A"
        else:
            self.scorecard_dict["vuln_org_critical_ttr"] = round(vuln_critical_attr)

        vuln_high_attr = vs_remediation_df["weighted_high"].mean()
        if vs_remediation_df["high_count"].sum() == 0:
            self.scorecard_dict["vuln_org_high_ttr"] = "N/A"
        else:
            self.scorecard_dict["vuln_org_high_ttr"] = round(vuln_high_attr)

        vs_fceb_df = self.vs_fceb_results
        self.scorecard_dict["vuln_sector_kev_ttr"] = (
            "N/A"
            if vs_fceb_df["ATTR KEVs"] is np.nan
            else round(vs_fceb_df["ATTR KEVs"])
        )
        self.scorecard_dict["vuln_sector_critical_ttr"] = (
            "N/A"
            if vs_fceb_df["ATTR Crits"] is np.nan
            else round(vs_fceb_df["ATTR Crits"])
        )
        self.scorecard_dict["vuln_sector_high_ttr"] = (
            "N/A"
            if vs_fceb_df["ATTR Highs"] is np.nan
            else round(vs_fceb_df["ATTR Highs"])
        )

        # Calculate bod compliance percentage
        open_tickets_df = self.vs_open_vulns
        kevs_df = self.kev_list
        total_kevs = 0
        overdue_kevs = 0
        total_crits = 0
        overdue_crits = 0
        total_highs = 0
        overdue_highs = 0
        for index2, ticket in open_tickets_df.iterrows():
            time_opened = ticket["time_opened"]
            now = datetime.datetime.now()
            age = self.get_age(time_opened, now)
            if ticket["cve"] in kevs_df["kev"].values:
                total_kevs = total_kevs + 1
                if age > 14.0:
                    overdue_kevs += 1
            if ticket["cvss_base_score"] >= 9.0:
                total_crits = total_crits + 1
                if age > 15.0:
                    overdue_crits += 1
            if ticket["cvss_base_score"] >= 7.0 and ticket["cvss_base_score"] < 9.0:
                total_highs = total_highs + 1
                if age > 30.0:
                    overdue_highs += 1
        bod_22_01 = self.get_percent_compliance(total_kevs, overdue_kevs)
        self.scorecard_dict["vuln_bod_22-01"] = True if bod_22_01 == 100 else False
        crit_19_02 = self.get_percent_compliance(total_crits, overdue_crits)
        self.scorecard_dict["vuln_critical_bod_19-02"] = (
            True if crit_19_02 == 100 else False
        )
        high_19_02 = self.get_percent_compliance(total_highs, overdue_highs)
        self.scorecard_dict["vuln_high_bod_19-02"] = (
            True if high_19_02 == 100 else False
        )

        webapp_df = self.webapp_counts
        was_fceb_ttr = self.was_fceb_ttr

        was_critical_attr = webapp_df["crit_rem_time"].mean()
        if not was_critical_attr:
            self.scorecard_dict["webapp_org_critical_ttr"] = was_critical_attr
        else:
            self.scorecard_dict["webapp_org_critical_ttr"] = "N/A"
        was_high_attr = webapp_df["high_rem_time"].mean()
        if not was_high_attr:
            self.scorecard_dict["webapp_org_high_ttr"] = was_high_attr
        else:
            self.scorecard_dict["webapp_org_high_ttr"] = "N/A"

        self.scorecard_dict["webapp_sector_critical_ttr"] = was_fceb_ttr["critical"]
        self.scorecard_dict["webapp_sector_high_ttr"] = was_fceb_ttr["high"]

        self.scorecard_dict[
            "email_compliance_pct"
        ] = self.calculate_bod18_compliance_email(self.org_uid_list)
        self.scorecard_dict[
            "https_compliance_pct"
        ] = self.calculate_bod18_compliance_https(self.org_uid_list)

    def fill_scorecard_dict(self):
        """Fill dictionary with scorecard metrics."""
        print("Filling scorecard dictionary")
        self.calculate_discovery_metrics_counts()
        self.calculate_profiling_metrics()
        self.calculate_identification_metrics()
        self.calculate_tracking_metrics()
        self.get_last_month_metrics()
        print(self.scorecard_dict)

    @staticmethod
    def ocsp_exclusions():
        """Prepare a list of OCSP sites to exclude."""
        URL = "https://github.com/cisagov/dotgov-data/blob/main/dotgov-websites/ocsp-crl.csv"
        r = requests.get(URL)
        soup = BeautifulSoup(r.content, features="lxml")

        table = soup.find_all("table")
        df = pd.read_html(str(table))[0]

        df = df.drop(columns=[0])
        ocsp_crl = df[1].values.tolist()

        return ocsp_crl

    @staticmethod
    def add_weak_crypto_data_to_domain(domain_doc, sslyze_data_all_domains):
        """Calculate weak crypto data for a given domain."""
        # Look for weak crypto data in sslyze_data_all_domains and
        # add hosts with weak crypto to
        # domain_doc['hosts_with_weak_crypto']
        domain_doc["domain_has_weak_crypto"] = False
        domain_doc["hosts_with_weak_crypto"] = []
        domain_doc["domain_has_symantec_cert"] = False

        if sslyze_data_all_domains.get(domain_doc["domain"]):
            for host in sslyze_data_all_domains[domain_doc["domain"]]:
                if (
                    host["sslv2"]
                    or host["sslv3"]
                    or host["any_3des"]
                    or host["any_rc4"]
                ):
                    domain_doc["domain_has_weak_crypto"] = True
                    domain_doc["hosts_with_weak_crypto"].append(host)
                if host["is_symantec_cert"]:
                    domain_doc["domain_has_symantec_cert"] = True
        return domain_doc

    def calculate_bod18_compliance_email(self, agency):
        """Calculate BOD 18-01 trusty mail compliance."""
        bod_1801_compliant_count = 0
        base_domain_plus_smtp_subdomain_count = 0

        sslyze_data_all_domains = dict()
        for host in query_sslyze_scan(agency, ["25", "587", "465"]):
            current_host_dict = {
                "scanned_hostname": host["scanned_hostname"],
                "scanned_port": host["scanned_port"],
                "sslv2": host["sslv2"],
                "sslv3": host["sslv3"],
                "any_3des": host["any_3des"],
                "any_rc4": host["any_rc4"],
                "is_symantec_cert": host["is_symantec_cert"],
            }

            if not sslyze_data_all_domains.get(host["domain"]):
                sslyze_data_all_domains[host["domain"]] = [current_host_dict]
            else:
                sslyze_data_all_domains[host["domain"]].append(current_host_dict)

        for domain in query_trusty_mail(agency):
            domain = self.add_weak_crypto_data_to_domain(
                domain, sslyze_data_all_domains
            )

            if domain["live"]:
                domain["valid_dmarc2"] = (
                    domain["valid_dmarc"] or domain["valid_dmarc_base_domain"]
                )
                domain["valid_dmarc_subdomain_policy_reject"] = False
                # According to RFC7489, "'sp' will be ignored for DMARC
                # records published on subdomains of Organizational
                # Domains due to the effect of the DMARC policy discovery
                # mechanism."  Therefore we have chosen not to penalize
                # for sp!=reject when considering subdomains.
                #
                # See here for more details:
                # https://tools.ietf.org/html/rfc7489#section-6.3
                if domain["valid_dmarc2"] and (
                    not domain["is_base_domain"]
                    or domain["dmarc_subdomain_policy"] == "reject"
                ):
                    domain["valid_dmarc_subdomain_policy_reject"] = True

                domain["valid_dmarc_policy_reject"] = False
                if domain["valid_dmarc2"] and domain["dmarc_policy"] == "reject":
                    domain["valid_dmarc_policy_reject"] = True

                domain["valid_dmarc_policy_pct"] = False

                if (
                    domain["valid_dmarc2"]
                    and domain["dmarc_policy_percentage"] == "100"
                ):
                    domain["valid_dmarc_policy_pct"] = True

                domain["valid_dmarc_policy_of_reject"] = False
                if (
                    domain["valid_dmarc_policy_reject"]
                    and domain["valid_dmarc_subdomain_policy_reject"]
                    and domain["valid_dmarc_policy_pct"]
                ):
                    domain["valid_dmarc_policy_of_reject"] = True

                if domain["is_base_domain"]:
                    domain["spf_covered"] = domain["valid_spf"]
                else:
                    domain["spf_covered"] = domain["valid_spf"] or (
                        domain["spf_record"] is False
                        and domain["valid_dmarc_policy_of_reject"]
                    )

                domain["valid_dmarc_bod1801_rua_uri"] = False
                if domain["valid_dmarc2"]:
                    for uri_dict in json.loads(
                        domain["aggregate_report_uris"]
                        .replace("'", '"')
                        .replace("None", "null")
                    ):
                        if uri_dict["uri"].lower() == BOD1801_DMARC_RUA_URI.lower():
                            domain["valid_dmarc_bod1801_rua_uri"] = True
                            break

                if domain["is_base_domain"] or (
                    not domain["is_base_domain"] and domain["domain_supports_smtp"]
                ):
                    base_domain_plus_smtp_subdomain_count += 1
                    if (
                        domain["domain_supports_smtp"]
                        and domain["domain_supports_starttls"]
                    ) or not domain["domain_supports_smtp"]:
                        if (
                            domain["spf_covered"]
                            and not domain["domain_has_weak_crypto"]
                            and domain["valid_dmarc_policy_reject"]
                            and domain["valid_dmarc_subdomain_policy_reject"]
                            and domain["valid_dmarc_policy_pct"]
                            and domain["valid_dmarc_bod1801_rua_uri"]
                        ):
                            bod_1801_compliant_count += 1

        if base_domain_plus_smtp_subdomain_count == 0:
            LOGGER.error(agency)
            LOGGER.error("Divide by zero in bod 18 email compliance")
            return None
        bod_1801_compliant_percentage = round(
            bod_1801_compliant_count / base_domain_plus_smtp_subdomain_count * 100.0,
            1,
        )
        return bod_1801_compliant_percentage

    def calculate_bod18_compliance_https(self, agency):
        """Calculate BOD 18-01 compliance percentage for https."""
        bod_1801_count = 0
        all_eligible_domains_count = 0
        ocsp_exclusion_list = self.ocsp_exclusions()

        all_domains = query_https_scan(agency)
        sslyze_data_all_domains = dict()
        for host in query_sslyze_scan(agency, ["443"]):
            current_host_dict = {
                "scanned_hostname": host["scanned_hostname"],
                "scanned_port": host["scanned_port"],
                "sslv2": host["sslv2"],
                "sslv3": host["sslv3"],
                "any_3des": host["any_3des"],
                "any_rc4": host["any_rc4"],
                "is_symantec_cert": host["is_symantec_cert"],
            }

            if not sslyze_data_all_domains.get(host["domain"]):
                sslyze_data_all_domains[host["domain"]] = [current_host_dict]
            else:
                sslyze_data_all_domains[host["domain"]].append(current_host_dict)

        for domain in all_domains:
            domain = self.add_weak_crypto_data_to_domain(
                domain, sslyze_data_all_domains
            )
            domain["ocsp_domain"] = domain["domain"] in ocsp_exclusion_list

            if domain["live"]:
                if not domain["ocsp_domain"]:
                    all_eligible_domains_count += 1

            # BOD 18-01 compliant?
            if (
                (
                    domain["domain_supports_https"]
                    and domain["domain_enforces_https"]
                    and domain["domain_uses_strong_hsts"]
                )
                or (
                    domain["live"]
                    and (
                        domain["hsts_base_domain_preloaded"]
                        or (
                            not domain["https_full_connection"]
                            and domain["https_client_auth_required"]
                        )
                    )
                )
            ) and not domain["domain_has_weak_crypto"]:
                if not domain["ocsp_domain"]:
                    bod_1801_count += 1
        if all_eligible_domains_count == 0:
            LOGGER.error(agency)
            LOGGER.error("Divide by zero in bod 18 https compliance")
            return None
        bod_1801_percentage = round(
            bod_1801_count / all_eligible_domains_count * 100.0, 1
        )

        return bod_1801_percentage

    def get_last_month_metrics(self):
        """Get the Scorecard metrics from the last month."""
        scorecard_dict_past = get_scorecard_metrics_past(
            self.org_data["organizations_uid"],
            self.start_date - datetime.timedelta(days=1),
        )
        LOGGER.info(
            "Past report date: %s", self.start_date - datetime.timedelta(days=1)
        )

        if scorecard_dict_past.empty:
            LOGGER.error("No Scorecard summary data for the last report period.")
            ips_trend_pct = self.scorecard_dict["ips_monitored_pct"]
            domains_trend_pct = self.scorecard_dict["domains_monitored_pct"]
            webapps_trend_pct = self.scorecard_dict["web_apps_monitored_pct"]
            certs_trend_pct = self.scorecard_dict["certs_monitored_pct"]
            ports_total_trend = self.scorecard_dict["ports_total_count"]
            ports_risky_trend = self.scorecard_dict["ports_risky_count"]
            protocol_total_trend = self.scorecard_dict["protocol_total_count"]
            protocol_insecure_trend = self.scorecard_dict["protocol_insecure_count"]
            services_total_trend = self.scorecard_dict["services_total_count"]
            software_unsupported_trend = self.scorecard_dict[
                "software_unsupported_count"
            ]
            email_compliance_last_period = self.scorecard_dict["email_compliance_pct"]
            https_compliance_last_period = self.scorecard_dict["https_compliance_pct"]
            discovery_trend = self.scorecard_dict.get("discovery_score", 0)
            profiling_trend = self.scorecard_dict.get("profiling_score", 0)
            identification_trend = self.scorecard_dict.get("identification_score", 0)
            tracking_trend = self.scorecard_dict.get("tracking_score", 0)
        else:
            ips_trend_pct = scorecard_dict_past["ips_monitored_pct"]
            domains_trend_pct = scorecard_dict_past["domains_monitored_pct"]
            webapps_trend_pct = scorecard_dict_past["web_apps_monitored_pct"]
            certs_trend_pct = scorecard_dict_past["certs_monitored_pct"]
            ports_total_trend = scorecard_dict_past["total_ports"]
            ports_risky_trend = scorecard_dict_past["risky_ports"]
            protocol_total_trend = scorecard_dict_past["protocols"]
            protocol_insecure_trend = scorecard_dict_past["insecure_protocols"]
            services_total_trend = scorecard_dict_past["total_services"]
            software_unsupported_trend = scorecard_dict_past["unsupported_software"]
            email_compliance_last_period = scorecard_dict_past["email_compliance_pct"]
            https_compliance_last_period = scorecard_dict_past["https_compliance_pct"]
            discovery_trend = scorecard_dict_past["discovery_score"]
            profiling_trend = scorecard_dict_past["profiling_score"]
            identification_trend = scorecard_dict_past["identification_score"]
            tracking_trend = scorecard_dict_past["tracking_score"]

        past_scorecard_metrics_dict = {
            "ips_trend_pct": ips_trend_pct,
            "domains_trend_pct": domains_trend_pct,
            "webapps_trend_pct": webapps_trend_pct,
            "certs_trend_pct": certs_trend_pct,
            "ports_total_trend": ports_total_trend,
            "ports_risky_trend": ports_risky_trend,
            "protocol_total_trend": protocol_total_trend,
            "protocol_insecure_trend": protocol_insecure_trend,
            "services_total_trend": services_total_trend,
            "software_unsupported_trend": software_unsupported_trend,
            "email_compliance_last_period": email_compliance_last_period,
            "https_compliance_last_period": https_compliance_last_period,
            "discovery_trend": discovery_trend,
            "profiling_trend": profiling_trend,
            "identification_trend": identification_trend,
            "tracking_trend": tracking_trend,
        }
        self.scorecard_dict.update(past_scorecard_metrics_dict)

    def generate_scorecard(self, output_directory, include_bods=True):
        """Generate a scorecard with the prefilled data_dictionary."""
        scorecard_dict = self.scorecard_dict

        file_name = (
            output_directory
            + "/scorecard_"
            + scorecard_dict["agency_id"]
            + "_"
            + self.start_date.strftime("%b-%Y")
            + ".pdf"
        )

        create_scorecard(scorecard_dict, file_name, True, False, include_bods)

        return file_name
