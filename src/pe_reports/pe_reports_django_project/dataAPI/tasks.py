from typing import List
from celery import shared_task
from home.models import MatVwOrgsAllIps
from django.core import serializers
import json
import ast
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
