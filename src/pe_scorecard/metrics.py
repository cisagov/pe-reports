"""Calculations for scorecard metrics."""
# Third-Party Libraries
from bs4 import BeautifulSoup
import pandas as pd
import requests

from .data.db_query import (  # query_subs_https_scan,
    query_https_scan,
    query_sslyze_scan,
    query_trusty_mail,
)

BOD1801_DMARC_RUA_URI = "mailto:reports@dmarc.cyber.dhs.gov"


def ocsp_exclusions():
    """Prepare a list of OCSP sites to exclude."""
    URL = (
        "https://github.com/cisagov/dotgov-data/blob/main/dotgov-websites/ocsp-crl.csv"
    )
    r = requests.get(URL)
    soup = BeautifulSoup(r.content, features="lxml")

    table = soup.find_all("table")
    df = pd.read_html(str(table))[0]

    df = df.drop(columns=[0])
    ocsp_crl = df[1].values.tolist()

    return ocsp_crl


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
            if host["sslv2"] or host["sslv3"] or host["any_3des"] or host["any_rc4"]:
                domain_doc["domain_has_weak_crypto"] = True
                domain_doc["hosts_with_weak_crypto"].append(host)
            if host["is_symantec_cert"]:
                domain_doc["domain_has_symantec_cert"] = True
    return domain_doc


def calculate_bod18_compliance_https(month, agency):
    """Calculate BOD 18-01 compliance percentage for https."""
    bod_1801_count = 0
    all_eligible_domains_count = 0
    ocsp_exclusion_list = ocsp_exclusions()  # TODO pull list from github

    all_domains = query_https_scan(month, agency)
    sslyze_data_all_domains = dict()
    for host in query_sslyze_scan(month, agency):
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
        domain = add_weak_crypto_data_to_domain(domain, sslyze_data_all_domains)
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
    bod_1801_percentage = round(bod_1801_count / all_eligible_domains_count * 100.0, 1)

    return bod_1801_percentage


def calculate_bod18_compliance_email(month, agency):
    """Calculate BOD 18-01 trusty mail compliance."""
    bod_1801_compliant_count = 0
    base_domain_plus_smtp_subdomain_count = 0

    sslyze_data_all_domains = dict()
    for host in query_sslyze_scan(month, agency):
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

    for domain in query_trusty_mail(month, agency):
        # domain  = add_weak_crypto_data_to_domain(domain, sslyze_data_all_domains)

        if domain["live"]:

            if domain["is_base_domain"] or (
                not domain["is_base_domain"] and domain["domain_supports_smtp"]
            ):
                base_domain_plus_smtp_subdomain_count += 1

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
            if domain["valid_dmarc2"] and domain["dmarc_policy_percentage"] == 100:
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
                for uri_dict in domain["aggregate_report_uris"]:
                    if uri_dict["uri"].lower() == BOD1801_DMARC_RUA_URI.lower():
                        domain["valid_dmarc_bod1801_rua_uri"] = True
                        break

            if (
                domain["spf_covered"]
                and not domain["domain_has_weak_crypto"]
                and domain["valid_dmarc_policy_reject"]
                and domain["valid_dmarc_subdomain_policy_reject"]
                and domain["valid_dmarc_policy_pct"]
                and domain["valid_dmarc_bod1801_rua_uri"]
            ):
                bod_1801_compliant_count += 1

    bod_1801_compliant_percentage = round(
        bod_1801_compliant_count / base_domain_plus_smtp_subdomain_count * 100.0,
        1,
    )
    return bod_1801_compliant_percentage
