# Standard Python Libraries
import ast
import json
from typing import List
import uuid

# Third-Party Libraries
from celery import shared_task
from django.core import serializers
from home.models import MatVwOrgsAllIps
from pe_reports.helpers import ip_passthrough
import datetime
from django.db.models import Q
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

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
    # Other Models:
    Ips,
    SubDomains,
    CveInfo,
    Cidrs,
    CredentialBreaches,
)

# ---------- Task Helper Functions ----------
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
    rva_data = MatVwOrgsAllIps.objects.filter(ip_addresses__contains=ip_address)

    print(rva_data)  # temporary print for debugging

    # If no results found in rva_data, then pass ip_address to the passthrough function
    if not rva_data:
        result = ip_passthrough.passthrough(ip_address)
    else:
        # To get cyhy_db_name values:
        cyhy_db_name_values = rva_data.values_list("cyhy_db_name", flat=True)

        # Store the result as a list of dictionaries for JSON serialization
        result = [{"cyhy_db_name": value} for value in cyhy_db_name_values]

    return result


# ---------- Score Tasks Helper Functions ----------
def convert_uuids_to_strings(list_of_dicts):
    """Convert organizations_uid and parent_org_uid to strings."""
    for row in list_of_dicts:
        row["organizations_uid"] = str(row["organizations_uid"])
        if row["parent_org_uid"] is not None:
            row["parent_org_uid"] = str(row["parent_org_uid"])
    return list_of_dicts


# ---------- D-Score View Tasks ----------
@shared_task(bind=True)
def get_dscore_vs_cert_info(self, specified_orgs: List[str]):
    """Task function for the dscore_vs_cert API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_vs_cert = list(
        VwDscoreVSCert.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    dscore_vs_cert = convert_uuids_to_strings(dscore_vs_cert)
    return dscore_vs_cert


@shared_task(bind=True)
def get_dscore_vs_mail_info(self, specified_orgs: List[str]):
    """Task function for the dscore_vs_mail API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_vs_mail = list(
        VwDscoreVSMail.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    dscore_vs_mail = convert_uuids_to_strings(dscore_vs_mail)
    return dscore_vs_mail


@shared_task(bind=True)
def get_dscore_pe_ip_info(self, specified_orgs: List[str]):
    """Task function for the dscore_pe_ip API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_pe_ip = list(
        VwDscorePEIp.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    dscore_pe_ip = convert_uuids_to_strings(dscore_pe_ip)
    return dscore_pe_ip


@shared_task(bind=True)
def get_dscore_pe_domain_info(self, specified_orgs: List[str]):
    """Task function for the dscore_pe_domain API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_pe_domain = list(
        VwDscorePEDomain.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    dscore_pe_domain = convert_uuids_to_strings(dscore_pe_domain)
    return dscore_pe_domain


@shared_task(bind=True)
def get_dscore_was_webapp_info(self, specified_orgs: List[str]):
    """Task function for the dscore_was_webapp API endpoint."""
    # Make database query and convert to list of dictionaries
    dscore_was_webapp = list(
        VwDscoreWASWebapp.objects.filter(organizations_uid__in=specified_orgs).values()
    )
    # Convert uuids to strings
    dscore_was_webapp = convert_uuids_to_strings(dscore_was_webapp)
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
        row["organizations_uid"] = str(row["organizations_uid"])
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
    iscore_vs_vuln = convert_uuids_to_strings(iscore_vs_vuln)
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
    # Convert datetime objects to string
    for row in iscore_vs_vuln_prev:
        row["time_closed"] = row["time_closed"].strftime("%Y-%m-%d")
    # Convert uuids to strings
    iscore_vs_vuln_prev = convert_uuids_to_strings(iscore_vs_vuln_prev)
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
    # Fix data types
    for row in iscore_pe_vuln:
        row["date"] = row["date"].strftime("%Y-%m-%d")
        if row["cvss_score"] is not None:
            row["cvss_score"] = float(row["cvss_score"])
    # Convert uuids to strings
    iscore_pe_vuln = convert_uuids_to_strings(iscore_pe_vuln)
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
    # Fix data types
    for row in iscore_pe_cred:
        row["date"] = row["date"].strftime("%Y-%m-%d")
    # Convert uuids to strings
    iscore_pe_cred = convert_uuids_to_strings(iscore_pe_cred)
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
    # Fix data types
    for row in iscore_pe_breach:
        row["date"] = row["date"].strftime("%Y-%m-%d")
    # Convert uuids to strings
    iscore_pe_breach = convert_uuids_to_strings(iscore_pe_breach)
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
    # Fix data types
    for row in iscore_pe_darkweb:
        row["date"] = row["date"].strftime("%Y-%m-%d")
    # Convert uuids to strings
    iscore_pe_darkweb = convert_uuids_to_strings(iscore_pe_darkweb)
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
    # Fix data types
    for row in iscore_pe_protocol:
        row["date"] = row["date"].strftime("%Y-%m-%d")
    # Convert uuids to strings
    iscore_pe_protocol = convert_uuids_to_strings(iscore_pe_protocol)
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
    # Fix data types
    for row in iscore_was_vuln:
        row["date"] = row["date"].strftime("%Y-%m-%d")
    # Convert uuids to strings
    iscore_was_vuln = convert_uuids_to_strings(iscore_was_vuln)
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
    # Fix data types
    for row in iscore_was_vuln_prev:
        row["date"] = row["date"].strftime("%Y-%m-%d")
    # Convert uuids to strings
    iscore_was_vuln_prev = convert_uuids_to_strings(iscore_was_vuln_prev)
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
        row["organizations_uid"] = str(row["organizations_uid"])
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
        row["organizations_uid"] = str(row["organizations_uid"])
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
        row["organizations_uid"] = str(row["organizations_uid"])
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
        row["organizations_uid"] = str(row["organizations_uid"])
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
        row["organizations_uid"] = str(row["organizations_uid"])
    return xl_stakeholders


# --- execute_ips(), Issue 559 ---
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


# --- query_all_subs(), Issue 560 ---
@shared_task(bind=True)
def sub_domains_table_task(self, page: int, per_page: int):
    """Task function for the sub_domains_table API endpoint."""
    # Make database query and grab all data
    total_data = list(SubDomains.objects.all().values())
    # Divide up data w/ specified num records per page
    paged_data = Paginator(total_data, per_page)
    # Attempt to retrieve specified page
    try:
        single_page_data = paged_data.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        single_page_data = paged_data.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        single_page_data = paged_data.page(paged_data.num_pages)
    # Serialize specified page
    single_page_data = list(single_page_data)
    # Convert uuids to strings
    for row in single_page_data:
        row["sub_domain_uid"] = convert_uuid_to_string(row["sub_domain_uid"])
        row["root_domain_uid_id"] = convert_uuid_to_string(row["root_domain_uid_id"])
        row["data_source_uid_id"] = convert_uuid_to_string(row["data_source_uid_id"])
        row["dns_record_uid_id"] = convert_uuid_to_string(row["dns_record_uid_id"])
        row["first_seen"] = convert_date_to_string(row["first_seen"])
        row["last_seen"] = convert_date_to_string(row["last_seen"])
    result = {
        "total_pages": paged_data.num_pages,
        "current_page": page,
        "data": single_page_data,
    }
    return result


# --- upsert_new_cves(), Issue 637 ---
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


# --- get_intelx_breaches(), Issue 641 ---
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
