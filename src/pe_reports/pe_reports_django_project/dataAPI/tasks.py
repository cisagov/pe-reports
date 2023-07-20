# Standard Python Libraries
import ast
import json
from typing import List
import uuid

# Third-Party Libraries
from celery import shared_task
from django.core import serializers
from home.models import MatVwOrgsAllIps

# from pe_reports.helpers import ip_passthrough # TESTING
import datetime
from django.db.models import Q

from home.models import (
    # General DB Table Models:
    CyhyKevs,
    Organizations,
    # D-Score View Models:
    VwDscoreVSCert,
    VwDscoreVSMail,
    VwDscorePEIp,
    VwDscorePEDomain,
    VwDscoreWASWebapp,
    # I-Score View Models:
    VwIscoreVSVuln,
    VwIscoreVSVulnPrev,
    VwIscorePEVuln,
    VwIscorePECred,
    VwIscorePEBreach,
    VwIscorePEDarkweb,
    VwIscorePEProtocol,
    VwIscoreWASVuln,
    VwIscoreWASVulnPrev,
    # Misc. Score View Models:
    VwIscoreOrgsIpCounts,
)

from home.models import (
    Ips,
    SubDomains,
    ReportSummaryStats,
    CveInfo,
    Cidrs,
    CredentialBreaches,
)


# v ---------- Task Helper Functions ---------- v
def convert_uuid_to_string(uuid):
    """Convert uuid to string if not None."""
    if uuid is not None:
        return str(uuid)
    return uuid


def convert_date_to_string(date):
    """Convert date to string if not None."""
    if date is not None:
        return date.strftime("%Y-%m-%d")
    return date


# ^ ---------- Task Helper Functions ---------- ^


@shared_task(bind=True)
def get_vs_info(self, cyhy_db_names: List[str]):
    vs_data_orm = list(MatVwOrgsAllIps.objects.filter(cyhy_db_name__in=cyhy_db_names))

    vs_data = serializers.serialize("json", vs_data_orm)

    vs_data = json.loads(vs_data)

    # Convert the string representation of a list into an actual list
    for item in vs_data:
        item["fields"]["ip_addresses"] = ast.literal_eval(
            item["fields"]["ip_addresses"]
        )

    return [item["fields"] for item in vs_data]


@shared_task
def get_ve_info(ip_address: List[str]):
    ve_data = MatVwOrgsAllIps.objects.filter(ip_addresses__contains=ip_address)

    print(ve_data)  # temporary print for debugging

    # To get cyhy_db_name values:
    cyhy_db_name_values = ve_data.values_list("cyhy_db_name", flat=True)

    # Return the result as a list of dictionaries for JSON serialization
    result = [{"cyhy_db_name": value} for value in cyhy_db_name_values]

    return result


@shared_task
def get_rva_info(ip_address: List[str]):
    # rva_data = MatVwOrgsAllIps.objects.filter(ip_addresses__contains=ip_address)

    # print(rva_data)  # temporary print for debugging

    ## If no results found in rva_data, then pass ip_address to the passthrough function
    # if not rva_data:
    #    result = ip_passthrough.passthrough(ip_address)
    # else:
    #    # To get cyhy_db_name values:
    #    cyhy_db_name_values = rva_data.values_list("cyhy_db_name", flat=True)
    #
    #    # Store the result as a list of dictionaries for JSON serialization
    #    result = [{"cyhy_db_name": value} for value in cyhy_db_name_values]

    # return result
    return None


# --- Issue 559 ---
@shared_task(bind=True)
def ips_insert_task(self, new_ips: List[dict]):
    """Task function for the ips_insert API endpoint."""
    # Go through each new ip
    for new_ip in new_ips:
        # Get Cidrs.origin_cidr object for this ip
        curr_ip_origin_cidr = Cidrs.objects.get(cidr_uid=new_ip["origin_cidr"])
        try:
            item = Ips.objects.get(ip=new_ip["ip"])
        except Ips.DoesNotExist:
            # If ip record doesn't exist yet, create one
            Ips.objects.create(
                ip_hash=new_ip["ip_hash"],
                ip=new_ip["ip"],
                origin_cidr=curr_ip_origin_cidr,
            )
        else:
            # If ip record does exits, update it
            item = Ips.objects.filter(ip=new_ip["ip"]).update(
                ip_hash=new_ip["ip_hash"],
                origin_cidr=new_ip["origin_cidr"],
            )
    # Return success message
    return "New ip records have been inserted into ips table"


# --- Issue 560 ---
@shared_task(bind=True)
def sub_domains_table_task(self):
    """Task function for the sub_domains_table API endpoint."""
    # Make database query and convert to list of dictionaries
    sub_domains_data = list(SubDomains.objects.all().values())
    # Convert uuids to strings
    for row in sub_domains_data:
        row["sub_domain_uid"] = convert_uuid_to_string(row["sub_domain_uid"])
        row["root_domain_uid_id"] = convert_uuid_to_string(row["root_domain_uid_id"])
        row["data_source_uid_id"] = convert_uuid_to_string(row["data_source_uid_id"])
        row["dns_record_uid_id"] = convert_uuid_to_string(row["dns_record_uid_id"])
        row["first_seen"] = convert_date_to_string(row["first_seen"])
        row["last_seen"] = convert_date_to_string(row["last_seen"])
    return sub_domains_data


# --- Issue 632 ---
@shared_task(bind=True)
def rss_insert_task(
    self,
    organizations_uid: str,
    start_date: str,
    end_date: str,
    ip_count: int,
    root_count: int,
    sub_count: int,
    ports_count: int,
    creds_count: int,
    breach_count: int,
    cred_password_count: int,
    domain_alert_count: int,
    suspected_domain_count: int,
    insecure_port_count: int,
    verified_vuln_count: int,
    suspected_vuln_count: int,
    suspected_vuln_addrs_count: int,
    threat_actor_count: int,
    dark_web_alerts_count: int,
    dark_web_mentions_count: int,
    dark_web_executive_alerts_count: int,
    dark_web_asset_alerts_count: int,
    pe_number_score: int,
    pe_letter_grade: str,
):
    """Task function for the rss_insert API endpoint."""
    # Get Organizations.organization_uid object for the specified org
    specified_org_uid = Organizations.objects.get(organizations_uid=organizations_uid)
    # Insert new record. If record already exists, update that record
    rss_insert_record_data = ReportSummaryStats.objects.update_or_create(
        organizations_uid=specified_org_uid,
        start_date=start_date,
        defaults={
            "organizations_uid": specified_org_uid,
            "start_date": start_date,
            "end_date": end_date,
            "ip_count": ip_count,
            "root_count": root_count,
            "sub_count": sub_count,
            "ports_count": ports_count,
            "creds_count": creds_count,
            "breach_count": breach_count,
            "cred_password_count": cred_password_count,
            "domain_alert_count": domain_alert_count,
            "suspected_domain_count": suspected_domain_count,
            "insecure_port_count": insecure_port_count,
            "verified_vuln_count": verified_vuln_count,
            "suspected_vuln_count": suspected_vuln_count,
            "suspected_vuln_addrs_count": suspected_vuln_addrs_count,
            "threat_actor_count": threat_actor_count,
            "dark_web_alerts_count": dark_web_alerts_count,
            "dark_web_mentions_count": dark_web_mentions_count,
            "dark_web_executive_alerts_count": dark_web_executive_alerts_count,
            "dark_web_asset_alerts_count": dark_web_asset_alerts_count,
            "pe_number_score": pe_number_score,
            "pe_letter_grade": pe_letter_grade,
        },
    )
    # Return success message
    return f"New report_summary_stats record inserted for the following organization/start_date: {organizations_uid}, {start_date}"


# --- Issue 634 ---
@shared_task(bind=True)
def rss_prev_period_task(self, org_uid: str, prev_end_date: str):
    """Task function for the rss_prev_period API endpoint."""
    # Make database query and convert to list of dictionaries
    rss_prev_period_data = list(
        ReportSummaryStats.objects.filter(
            organizations_uid=org_uid, end_date=prev_end_date
        ).values(
            "ip_count",
            "root_count",
            "sub_count",
            "cred_password_count",
            "suspected_vuln_addrs_count",
            "suspected_vuln_count",
            "insecure_port_count",
            "threat_actor_count",
        )
    )
    return rss_prev_period_data


# --- Issue 637 ---
@shared_task(bind=True)
def cve_info_insert_task(self, new_cves: List[dict]):
    """Task function for the cve_info_insert API endpoint."""
    # Go through each new cve
    for cve in new_cves:
        try:
            item = CveInfo.objects.get(cve_name=cve["cve_name"])
        except CveInfo.DoesNotExist:
            # If CVE record doesn't exist yet, create one
            CveInfo.objects.create(
                # generate new uuid
                cve_uuid=uuid.uuid1(),
                cve_name=cve["cve_name"],
                cvss_2_0=cve["cvss_2_0"],
                cvss_2_0_severity=cve["cvss_2_0_severity"],
                cvss_2_0_vector=cve["cvss_2_0_vector"],
                cvss_3_0=cve["cvss_3_0"],
                cvss_3_0_severity=cve["cvss_3_0_severity"],
                cvss_3_0_vector=cve["cvss_3_0_vector"],
                dve_score=cve["dve_score"],
            )
        else:
            # If CVE record does exits, update it
            item = CveInfo.objects.filter(cve_name=cve["cve_name"]).update(
                # use existing uuid
                cvss_2_0=cve["cvss_2_0"],
                cvss_2_0_severity=cve["cvss_2_0_severity"],
                cvss_2_0_vector=cve["cvss_2_0_vector"],
                cvss_3_0=cve["cvss_3_0"],
                cvss_3_0_severity=cve["cvss_3_0_severity"],
                cvss_3_0_vector=cve["cvss_3_0_vector"],
                dve_score=cve["dve_score"],
            )
    # Return success message
    return "New CVE records have been inserted into cve_info table"


# --- Issue 641 ---
@shared_task(bind=True)
def cred_breach_intelx_task(self, source_uid: str):
    """Task function for the cred_breach_intelx API endpoint."""
    # Make database query and convert to list of dictionaries
    cred_breach_intelx_data = list(
        CredentialBreaches.objects.filter(data_source_uid=source_uid).values(
            "breach_name", "credential_breaches_uid"
        )
    )
    # Convert uuids to strings
    for row in cred_breach_intelx_data:
        row["credential_breaches_uid"] = convert_uuid_to_string(
            row["credential_breaches_uid"]
        )
    return cred_breach_intelx_data


# ---------- D-Score View Tasks ----------
@shared_task(bind=True)
def get_dscore_vs_cert_info(self, specified_orgs: List[str]):
    """Task function for the dscore_vs_cert API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_vs_cert = list(
        VwDscoreVSCert.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    for row in dscore_vs_cert:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
    return dscore_vs_cert


@shared_task(bind=True)
def get_dscore_vs_mail_info(self, specified_orgs: List[str]):
    """Task function for the dscore_vs_mail API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_vs_mail = list(
        VwDscoreVSMail.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    for row in dscore_vs_mail:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
    return dscore_vs_mail


@shared_task(bind=True)
def get_dscore_pe_ip_info(self, specified_orgs: List[str]):
    """Task function for the dscore_pe_ip API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_pe_ip = list(
        VwDscorePEIp.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    for row in dscore_pe_ip:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
    return dscore_pe_ip


@shared_task(bind=True)
def get_dscore_pe_domain_info(self, specified_orgs: List[str]):
    """Task function for the dscore_pe_domain API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_pe_domain = list(
        VwDscorePEDomain.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    for row in dscore_pe_domain:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
    return dscore_pe_domain


@shared_task(bind=True)
def get_dscore_was_webapp_info(self, specified_orgs: List[str]):
    """Task function for the dscore_was_webapp API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_was_webapp = list(
        VwDscoreWASWebapp.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    for row in dscore_was_webapp:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
    return dscore_was_webapp


@shared_task(bind=True)
def get_fceb_status_info(self, specified_orgs: List[str]):
    """Task function for the FCEB status query API endpoint."""
    # Make database query and convert to list of dictionaries
    fceb_status = list(
        Organizations.objects.filter(organizations_uid__in=specified_orgs).values(
            "organizations_uid", "fceb"
        )
    )
    # Convert uuids to strings
    for row in fceb_status:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    return fceb_status


# ---------- I-Score View Tasks ----------
@shared_task(bind=True)
def get_iscore_vs_vuln_info(self, specified_orgs: List[str]):
    """Task function for the iscore_vs_vuln API endpoint."""
    # Make database query and convert to list of dictionaries
    iscore_vs_vuln = list(
        VwIscoreVSVuln.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    for row in iscore_vs_vuln:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
    return iscore_vs_vuln


@shared_task(bind=True)
def get_iscore_vs_vuln_prev_info(
    self, specified_orgs: List[str], start_date: str, end_date: str
):
    """Task function for the iscore_vs_vuln_prev API endpoint."""
    # Make database query and convert to list of dictionaries
    iscore_vs_vuln_prev = list(
        VwIscoreVSVulnPrev.objects.filter(
            organizations_uid__in=specified_orgs,
            time_closed__range=[start_date, end_date],
        ).values()
    )
    # Convert uuids/datetime to strings
    for row in iscore_vs_vuln_prev:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
        row["time_closed"] = convert_date_to_string(row["time_closed"])
    return iscore_vs_vuln_prev


@shared_task(bind=True)
def get_iscore_pe_vuln_info(
    self, specified_orgs: List[str], start_date: str, end_date: str
):
    """Task function for the iscore_pe_vuln API endpoint."""
    # Make database query and convert to list of dictionaries
    iscore_pe_vuln = list(
        VwIscorePEVuln.objects.filter(
            organizations_uid__in=specified_orgs,
            date__range=[start_date, end_date],
        ).values()
    )
    # Convert uuids/datetime to strings
    for row in iscore_pe_vuln:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
        row["date"] = convert_date_to_string(row["date"])
        if row["cvss_score"] is not None:
            row["cvss_score"] = float(row["cvss_score"])
    return iscore_pe_vuln


@shared_task(bind=True)
def get_iscore_pe_cred_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_pe_cred API endpoint."""
    # Make database query and convert to list of dictionaries
    iscore_pe_cred = list(
        VwIscorePECred.objects.filter(
            organizations_uid__in=specified_orgs,
            date__range=[start_date, end_date],
        ).values()
    )
    # Convert uuids/datetime to strings
    for row in iscore_pe_cred:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
        row["date"] = convert_date_to_string(row["date"])
    return iscore_pe_cred


@shared_task(bind=True)
def get_iscore_pe_breach_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_pe_breach API endpoint."""
    # Make database query and convert to list of dictionaries
    iscore_pe_breach = list(
        VwIscorePEBreach.objects.filter(
            organizations_uid__in=specified_orgs,
            date__range=[start_date, end_date],
        ).values()
    )
    # Convert uuids/datetime to strings
    for row in iscore_pe_breach:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
        row["date"] = convert_date_to_string(row["date"])
    return iscore_pe_breach


@shared_task(bind=True)
def get_iscore_pe_darkweb_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_pe_darkweb API endpoint."""
    # Make database query and convert to list of dictionaries
    iscore_pe_darkweb = list(
        VwIscorePEDarkweb.objects.filter(
            Q(organizations_uid__in=specified_orgs),
            (Q(date__gte=start_date) & Q(date__lte=end_date)) | Q(date="0001-01-01"),
        ).values()
    )
    # Convert uuids/datetime to strings
    for row in iscore_pe_darkweb:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
        row["date"] = convert_date_to_string(row["date"])
    return iscore_pe_darkweb


@shared_task(bind=True)
def get_iscore_pe_protocol_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_pe_protocol API endpoint."""
    # Make database query and convert to list of dictionaries
    iscore_pe_protocol = list(
        VwIscorePEProtocol.objects.filter(
            organizations_uid__in=specified_orgs,
            date__range=[start_date, end_date],
        ).values()
    )
    # Convert uuids/datetime to strings
    for row in iscore_pe_protocol:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
        row["date"] = convert_date_to_string(row["date"])
    return iscore_pe_protocol


@shared_task(bind=True)
def get_iscore_was_vuln_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_was_vuln API endpoint."""
    # Make database query and convert to list of dictionaries
    iscore_was_vuln = list(
        VwIscoreWASVuln.objects.filter(
            organizations_uid__in=specified_orgs,
            date__range=[start_date, end_date],
        ).values()
    )
    # Convert uuids/datetime to strings
    for row in iscore_was_vuln:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
        row["date"] = convert_date_to_string(row["date"])
    return iscore_was_vuln


@shared_task(bind=True)
def get_iscore_was_vuln_prev_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_was_vuln_prev API endpoint."""
    # Make database query and convert to list of dictionaries
    iscore_was_vuln_prev = list(
        VwIscoreWASVulnPrev.objects.filter(
            organizations_uid__in=specified_orgs,
            date__range=[start_date, end_date],
        ).values()
    )
    # Convert uuids/datetime to strings
    for row in iscore_was_vuln_prev:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["parent_org_uid"] = convert_uuid_to_string(row["parent_org_uid"])
        row["date"] = convert_date_to_string(row["date"])
    return iscore_was_vuln_prev


@shared_task(bind=True)
def get_kev_list_info(self):
    """Task function for the KEV list query API endpoint."""
    # Make database query
    kev_list = list(CyhyKevs.objects.values("kev"))
    return kev_list


# ---------- Misc. Score View Tasks ----------
@shared_task(bind=True)
def get_xs_stakeholders_info(self):
    """Task function for the XS stakeholder list query API endpoint."""
    # Make database query and convert to list of dictionaries
    xs_stakeholders = list(
        VwIscoreOrgsIpCounts.objects.filter(
            ip_count__gte=0,
            ip_count__lte=100,
        ).values("organizations_uid", "cyhy_db_name")
    )
    # Convert uuids to strings
    for row in xs_stakeholders:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    return xs_stakeholders


@shared_task(bind=True)
def get_s_stakeholders_info(self):
    """Task function for the S stakeholder list query API endpoint."""
    # Make database query and convert to list of dictionaries
    s_stakeholders = list(
        VwIscoreOrgsIpCounts.objects.filter(
            ip_count__gt=100,
            ip_count__lte=1000,
        ).values("organizations_uid", "cyhy_db_name")
    )
    # Convert uuids to strings
    for row in s_stakeholders:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    return s_stakeholders


@shared_task(bind=True)
def get_m_stakeholders_info(self):
    """Task function for the M stakeholder list query API endpoint."""
    # Make database query and convert to list of dictionaries
    m_stakeholders = list(
        VwIscoreOrgsIpCounts.objects.filter(
            ip_count__gt=1000,
            ip_count__lte=10000,
        ).values("organizations_uid", "cyhy_db_name")
    )
    # Convert uuids to strings
    for row in m_stakeholders:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    return m_stakeholders


@shared_task(bind=True)
def get_l_stakeholders_info(self):
    """Task function for the L stakeholder list query API endpoint."""
    # Make database query and convert to list of dictionaries
    l_stakeholders = list(
        VwIscoreOrgsIpCounts.objects.filter(
            ip_count__gt=10000,
            ip_count__lte=100000,
        ).values("organizations_uid", "cyhy_db_name")
    )
    # Convert uuids to strings
    for row in l_stakeholders:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    return l_stakeholders


@shared_task(bind=True)
def get_xl_stakeholders_info(self):
    """Task function for the XL stakeholder list query API endpoint."""
    # Make database query and convert to list of dictionaries
    xl_stakeholders = list(
        VwIscoreOrgsIpCounts.objects.filter(ip_count__gt=100000).values(
            "organizations_uid", "cyhy_db_name"
        )
    )
    # Convert uuids to strings
    for row in xl_stakeholders:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    return xl_stakeholders
