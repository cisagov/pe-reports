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
    query_certs,
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
    query_web_app_counts,
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
        sector,
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
            "sector_name": sector,
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
        self.scorecard_dict["score"] = None
        self.scorecard_dict["discovery_score"] = None
        self.scorecard_dict["profiling_score"] = None
        self.scorecard_dict["identification_score"] = None
        self.scorecard_dict["tracking_score"] = None

        self.ip_counts = query_ips_counts(org_uid_list)
        self.domain_counts = query_domain_counts(org_uid_list)
        # # TODO possibly need to format a date string based on the new column
        self.web_app_counts = query_web_app_counts(start_date, org_uid_list)
        self.cert_counts = query_certs(start_date, end_date)

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

        total_self_reported_ips = total_ips_df["cidr_reported"].sum()
        discovered_ips = total_ips_df["ip_discovered"].sum()

        self.scorecard_dict["ips_self_reported"] = total_self_reported_ips
        self.scorecard_dict["ips_discovered"] = discovered_ips
        self.scorecard_dict["ips_monitored"] = total_ips

        if total_self_reported_ips == 0 and discovered_ips == 0:
            self.scorecard_dict["ips_monitored"] = None

        domains_identified = self.domain_counts["identified"].sum()
        domains_self_reported = self.domain_counts["unidentified"].sum()

        self.scorecard_dict["domains_self_reported"] = domains_self_reported
        self.scorecard_dict["domains_discovered"] = domains_identified

        self.scorecard_dict["domains_monitored"] = (
            domains_self_reported + domains_identified
        )

        if domains_self_reported == 0 and domains_identified == 0:
            self.scorecard_dict["domains_monitored"] = None

        # TODO add web_apps
        web_app_df = self.web_app_counts
        web_apps_self_reported = web_app_df["web_app_cnt"].sum()
        web_apps_discovered = 0

        self.scorecard_dict["web_apps_self_reported"] = web_apps_self_reported
        self.scorecard_dict["web_apps_discovered"] = web_apps_discovered

        self.scorecard_dict["web_apps_monitored"] = (
            web_apps_self_reported + web_apps_discovered
        )

        if web_apps_self_reported == 0 and web_apps_discovered == 0:
            self.scorecard_dict["web_apps_monitored"] = None

        # TODO add certs
        certs_df = self.cert_counts
        certs_df_filtered = certs_df[
            certs_df["organizations_uid"].isin(self.org_uid_list)
        ]
        certs_count = certs_df_filtered["count"].sum()
        if certs_count:
            self_reported_certs = certs_count
        else:
            self_reported_certs = 0
        discovered_certs = 0

        self.scorecard_dict["certs_self_reported"] = self_reported_certs
        self.scorecard_dict["certs_discovered"] = discovered_certs
        self.scorecard_dict["certs_monitored"] = self_reported_certs + discovered_certs

        if self_reported_certs == 0 and discovered_certs == 0:
            self.scorecard_dict["certs_monitored"] = None

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
        self.scorecard_dict["total_ports"] = profiling_dict["ports_count"]
        self.scorecard_dict["risky_ports"] = profiling_dict["risky_ports_count"]
        self.scorecard_dict["protocols"] = profiling_dict["protocols_count"]
        self.scorecard_dict["insecure_protocols"] = profiling_dict[
            "risky_protocols_count"
        ]
        self.scorecard_dict["total_services"] = profiling_dict["services"]

        software_df = self.software_counts
        self.scorecard_dict["unsupported_software"] = software_df["count"].sum()

    def calculate_identification_metrics(self):
        """Summarize identification findings into key metrics."""
        vuln_counts = self.vs_vuln_counts
        self.scorecard_dict["ext_host_kev"] = vuln_counts["kev"].sum()
        self.scorecard_dict["ext_host_vuln_critical"] = vuln_counts["critical"].sum()
        self.scorecard_dict["ext_host_vuln_high"] = vuln_counts["high"].sum()
        was_counts = self.web_app_counts
        self.scorecard_dict["web_apps_kev"] = "N/A"
        self.scorecard_dict["web_apps_vuln_critical"] = was_counts[
            "crit_vuln_cnt"
        ].sum()
        self.scorecard_dict["web_apps_vuln_high"] = was_counts["high_vuln_cnt"].sum()

    def calculate_tracking_metrics(self):
        """Summarize tracking findings into key metrics."""
        vs_remediation_df = self.vs_remediation
        vs_remediation_df = vs_remediation_df.replace({np.NaN: None})
        print(vs_remediation_df)
        vuln_kev_attr = vs_remediation_df["weighted_kev"].sum()
        if vs_remediation_df["kev_count"].sum() == 0:
            self.scorecard_dict["org_avg_days_remediate_kev"] = "N/A"
        else:
            self.scorecard_dict["org_avg_days_remediate_kev"] = round(vuln_kev_attr)

        vuln_critical_attr = vs_remediation_df["weighted_critical"].sum()
        if vs_remediation_df["critical_count"].sum() == 0:
            self.scorecard_dict["org_avg_days_remediate_critical"] = "N/A"
        else:
            self.scorecard_dict["org_avg_days_remediate_critical"] = round(
                vuln_critical_attr
            )

        vuln_high_attr = vs_remediation_df["weighted_high"].mean()
        if vs_remediation_df["high_count"].sum() == 0:
            self.scorecard_dict["org_avg_days_remediate_high"] = "N/A"
        else:
            self.scorecard_dict["org_avg_days_remediate_high"] = round(vuln_high_attr)

        vs_fceb_df = self.vs_fceb_results
        self.scorecard_dict["sect_avg_days_remediate_kev"] = (
            "N/A"
            if vs_fceb_df["ATTR KEVs"] is np.nan
            else round(vs_fceb_df["ATTR KEVs"])
        )
        self.scorecard_dict["sect_avg_days_remediate_critical"] = (
            "N/A"
            if vs_fceb_df["ATTR Crits"] is np.nan
            else round(vs_fceb_df["ATTR Crits"])
        )
        self.scorecard_dict["sect_avg_days_remediate_high"] = (
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
        self.scorecard_dict["bod_22_01-01"] = True if bod_22_01 == 100 else False
        crit_19_02 = self.get_percent_compliance(total_crits, overdue_crits)
        self.scorecard_dict["bod_19_02_critical"] = True if crit_19_02 == 100 else False
        high_19_02 = self.get_percent_compliance(total_highs, overdue_highs)
        self.scorecard_dict["bod_19_02_high"] = True if high_19_02 == 100 else False

        web_app_df = self.web_app_counts
        was_fceb_ttr = self.was_fceb_ttr

        total_critical = web_app_df["crit_rem_cnt"].sum()
        web_app_df["weighted_critical"] = (
            web_app_df["crit_rem_cnt"] / total_critical
        ) * web_app_df["crit_rem_time"]

        self.scorecard_dict["org_web_avg_days_remediate_critical"] = (
            web_app_df["weighted_critical"].sum() if total_critical > 0 else "N/A"
        )

        total_high = web_app_df["high_rem_cnt"].sum()
        web_app_df["weighted_high"] = (
            web_app_df["high_rem_cnt"] / total_high
        ) * web_app_df["high_rem_time"]
        self.scorecard_dict["org_web_avg_days_remediate_high"] = (
            web_app_df["weighted_high"].sum() if total_high > 0 else "N/A"
        )

        self.scorecard_dict["sect_web_avg_days_remediate_critical"] = was_fceb_ttr[
            "critical"
        ]
        self.scorecard_dict["sect_web_avg_days_remediate_high"] = was_fceb_ttr["high"]

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
        # self.get_last_month_metrics()
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
            LOGGER.info(agency)
            LOGGER.info("Divide by zero in bod 18 email compliance")
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
            LOGGER.info(agency)
            LOGGER.info("Divide by zero in bod 18 https compliance")
            return None
        bod_1801_percentage = round(
            bod_1801_count / all_eligible_domains_count * 100.0, 1
        )

        return bod_1801_percentage

    def get_last_month_metrics(self):
        """Get the Scorecard metrics from the last month."""
        scorecard_dict_past = get_scorecard_metrics_past(
            self.org_data["organizations_uid"],
            self.start_date,
        )
        LOGGER.info(
            "Past report date: %s", self.start_date - datetime.timedelta(days=1)
        )

        if scorecard_dict_past.empty:
            LOGGER.error("No Scorecard summary data for the last report period.")
            ips_monitored_trend = self.scorecard_dict["ips_monitored"]
            domains_monitored_trend = self.scorecard_dict["domains_monitored"]
            web_apps_monitored_trend = self.scorecard_dict["web_apps_monitored"]
            certs_monitored_trend = self.scorecard_dict["certs_monitored"]
            ports_total_trend = self.scorecard_dict["total_ports"]
            ports_risky_trend = self.scorecard_dict["risky_ports"]
            protocol_total_trend = self.scorecard_dict["protocols"]
            protocol_insecure_trend = self.scorecard_dict["insecure_protocols"]
            services_total_trend = self.scorecard_dict["total_services"]
            software_unsupported_trend = self.scorecard_dict["unsupported_software"]
            email_compliance_last_period = self.scorecard_dict["email_compliance_pct"]
            https_compliance_last_period = self.scorecard_dict["https_compliance_pct"]
            discovery_trend = self.scorecard_dict.get("discovery_score", 0)
            profiling_trend = self.scorecard_dict.get("profiling_score", 0)
            identification_trend = self.scorecard_dict.get("identification_score", 0)
            tracking_trend = self.scorecard_dict.get("tracking_score", 0)
        else:
            ips_monitored_trend = scorecard_dict_past["ips_monitored"][0]
            domains_monitored_trend = scorecard_dict_past["domains_monitored"][0]
            web_apps_monitored_trend = scorecard_dict_past["web_apps_monitored"][0]
            certs_monitored_trend = scorecard_dict_past["certs_monitored"][0]
            ports_total_trend = scorecard_dict_past["total_ports"][0]
            ports_risky_trend = scorecard_dict_past["risky_ports"][0]
            protocol_total_trend = scorecard_dict_past["protocols"][0]
            protocol_insecure_trend = scorecard_dict_past["insecure_protocols"][0]
            services_total_trend = scorecard_dict_past["total_services"][0]
            software_unsupported_trend = scorecard_dict_past["unsupported_software"][0]
            email_compliance_last_period = scorecard_dict_past["email_compliance_pct"][
                0
            ]
            https_compliance_last_period = scorecard_dict_past["https_compliance_pct"][
                0
            ]
            discovery_trend = scorecard_dict_past["discovery_score"][0]
            profiling_trend = scorecard_dict_past["profiling_score"][0]
            identification_trend = scorecard_dict_past["identification_score"][0]
            tracking_trend = scorecard_dict_past["tracking_score"][0]

        past_scorecard_metrics_dict = {
            "ips_monitored_trend": ips_monitored_trend,
            "domains_monitored_trend": domains_monitored_trend,
            "web_apps_monitored_trend": web_apps_monitored_trend,
            "certs_monitored_trend": certs_monitored_trend,
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

    def generate_scorecard(self, output_directory, exclude_bods=False):
        """Generate a scorecard with the prefilled data_dictionary."""
        scorecard_dict = self.scorecard_dict

        file_name = (
            output_directory
            + "/scorecard_"
            + scorecard_dict["agency_id"]
            + "_"
            + scorecard_dict["sector_name"]
            + "_"
            + self.start_date.strftime("%b-%Y")
            + ".pdf"
        )

        create_scorecard(scorecard_dict, file_name, True, False, exclude_bods)

        return file_name
