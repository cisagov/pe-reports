"""API tasks."""
# Standard Python Libraries
import ast
import datetime
import json
from typing import List, Optional
import uuid

# Third-Party Libraries
from celery import shared_task
from django.core import serializers
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.db.models import Count, Prefetch, Q, Sum
from home.models import (
    Alerts,
    Cidrs,
    CpeProduct,
    CredentialBreaches,
    CredentialExposures,
    CveInfo,
    Cves,
    CyhyKevs,
    DataSource,
    DomainAlerts,
    DomainPermutations,
    Ips,
    MatVwOrgsAllIps,
    Mentions,
    Organizations,
    SubDomains,
    TopCves,
    VwBreachcomp,
    VwBreachcompCredsbydate,
    VwDarkwebInviteonlymarkets,
    VwDarkwebMentionsbydate,
    VwDarkwebPotentialthreats,
    VwDscorePEDomain,
    VwDscorePEIp,
    VwDscoreVSCert,
    VwDscoreVSMail,
    VwDscoreWASWebapp,
    VwIscoreOrgsIpCounts,
    VwIscorePEBreach,
    VwIscorePECred,
    VwIscorePEDarkweb,
    VwIscorePEProtocol,
    VwIscorePEVuln,
    VwIscoreVSVuln,
    VwIscoreVSVulnPrev,
    VwIscoreWASVuln,
    VwIscoreWASVulnPrev,
    VwOrgsAttacksurface,
    VwPshttDomainsToRun,
    VwShodanvulnsSuspected,
    VwShodanvulnsVerified,
    XpanseAlerts,
)

from . import schemas


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


# v ---------- Task Functions ---------- v
@shared_task(bind=True)
def get_vs_info(self, cyhy_db_names: List[str]):
    """Get the Vulnerability Scanning information from the database."""
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
    """Get the VE information from the database."""
    ve_data = MatVwOrgsAllIps.objects.filter(ip_addresses__contains=ip_address)

    print(ve_data)  # temporary print for debugging

    # To get cyhy_db_name values:
    cyhy_db_name_values = ve_data.values_list("cyhy_db_name", flat=True)

    # Return the result as a list of dictionaries for JSON serialization
    result = [{"cyhy_db_name": value} for value in cyhy_db_name_values]

    return result


@shared_task(bind=True)
def get_vw_pshtt_domains_to_run_info(self):
    """Get subdomains to run through the PSHTT scan."""
    # Make database query, then convert to list of dictionaries
    endpoint_data = list(VwPshttDomainsToRun.objects.all().values())

    # Convert UUID data to string (UUIDs cause issues with formatting)
    for row in endpoint_data:
        row["sub_domain_uid"] = str(row["sub_domain_uid"])
        row["organizations_uid"] = str(row["organizations_uid"])
    # Return results
    return endpoint_data


# ---------- D-Score Tasks ----------
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


# ---------- I-Score Tasks ----------
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


# ---------- General Score Tasks ----------
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


# ---------- Misc. Tasks ----------
# --- execute_ips(), Issue 559 ---
@shared_task(bind=True)
def ips_insert_task(self, new_ips: List[dict]):
    """Task function for the ips_insert API endpoint."""
    # Go through each new ip
    for new_ip in new_ips:
        # Get Cidrs.origin_cidr object for this ip
        curr_ip_origin_cidr = Cidrs.objects.get(cidr_uid=new_ip["origin_cidr"])
        try:
            Ips.objects.get(ip=new_ip["ip"])
        except Ips.DoesNotExist:
            # If ip record doesn't exist yet, create one
            from_cidr_state = False
            if curr_ip_origin_cidr:
                from_cidr_state = True
            Ips.objects.create(
                ip_hash=new_ip["ip_hash"],
                ip=new_ip["ip"],
                origin_cidr=curr_ip_origin_cidr,
                from_cidr=from_cidr_state,
            )
        else:
            # If ip record does exits, update it
            Ips.objects.filter(ip=new_ip["ip"]).update(
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


# -- set_from_cidr(), Issue 616 ---
@shared_task(bind=True)
def ips_update_from_cidr_task(self):
    """Task function for the ips_update_from_cidr API endpoint."""
    # Make database query and convert to list of dictionaries
    Ips.objects.filter(origin_cidr__isnull=False).update(from_cidr=True)
    return "Ips table from_cidr field has been updated."


# --- darkweb_cves(), Issue 630 ---
@shared_task(bind=True)
def darkweb_cves_task(self):
    """Task function for the darkweb_cves API endpoint."""
    # Make database query and convert to list of dictionaries
    all_data = list(TopCves.objects.all().values())
    for row in all_data:
        row["top_cves_uid"] = convert_uuid_to_string(row["top_cves_uid"])
        row["data_source_uid_id"] = convert_uuid_to_string(row["data_source_uid_id"])
        row["date"] = convert_date_to_string(row["date"])
    return all_data


# --- query_subs(), Issue 633 ---
@shared_task(bind=True)
def sub_domains_by_org_task(self, org_uid: str, page: int, per_page: int):
    """Task function for the subdomains by org query API endpoint."""
    # Make database query and convert to list of dictionaries
    total_data = list(
        SubDomains.objects.filter(root_domain_uid__organizations_uid=org_uid).values()
    )
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
    # Catch query no results scenario
    if not total_data:
        single_page_data = [{x: None for x in schemas.SubDomainTable.__fields__}]
        return {
            "total_pages": paged_data.num_pages,
            "current_page": page,
            "data": single_page_data,
        }
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


# --- pescore_hist_domain_alert(), Issue 635 ---
@shared_task(bind=True)
def pescore_hist_domain_alert_task(self, start_date: str, end_date: str):
    """Task function for the pescore_hist_domain_alert API endpoint."""
    # Make database query and convert to list of dictionaries
    # Get reported orgs
    reported_orgs = list(
        Organizations.objects.filter(report_on=True).values(
            "organizations_uid", "cyhy_db_name"
        )
    )
    # Get domain alert data
    pescore_hist_domain_alert_data = list(
        DomainAlerts.objects.filter(date__range=[start_date, end_date]).values(
            "organizations_uid", "date"
        )
    )
    # Convert uuids to strings
    for row in reported_orgs:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    for row in pescore_hist_domain_alert_data:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["date"] = convert_date_to_string(row["date"])
    return {
        "reported_orgs": reported_orgs,
        "hist_domain_alert_data": pescore_hist_domain_alert_data,
    }


# --- pescore_hist_darkweb_alert(), Issue 635 ---
@shared_task(bind=True)
def pescore_hist_darkweb_alert_task(self, start_date: str, end_date: str):
    """Task function for the pescore_hist_darkweb_alert API endpoint."""
    # Make database query and convert to list of dictionaries
    # Get reported orgs
    reported_orgs = list(
        Organizations.objects.filter(report_on=True).values(
            "organizations_uid", "cyhy_db_name"
        )
    )
    # Get darkweb alert data
    pescore_hist_darkweb_alert_data = list(
        Alerts.objects.filter(date__range=[start_date, end_date]).values(
            "organizations_uid", "date"
        )
    )
    # Convert uuids to strings
    for row in reported_orgs:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    for row in pescore_hist_darkweb_alert_data:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["date"] = convert_date_to_string(row["date"])
    return {
        "reported_orgs": reported_orgs,
        "hist_darkweb_alert_data": pescore_hist_darkweb_alert_data,
    }


# --- pescore_hist_darkweb_ment(), Issue 635 ---
@shared_task(bind=True)
def pescore_hist_darkweb_ment_task(self, start_date: str, end_date: str):
    """Task function for the pescore_hist_darkweb_ment API endpoint."""
    # Make database query and convert to list of dictionaries
    # Get reported orgs
    reported_orgs = list(
        Organizations.objects.filter(report_on=True).values(
            "organizations_uid", "cyhy_db_name"
        )
    )
    # Get darkweb mention data
    pescore_hist_darkweb_ment_data = list(
        VwDarkwebMentionsbydate.objects.filter(
            date__range=[start_date, end_date]
        ).values("organizations_uid", "date", "count")
    )
    # Convert uuids to strings
    for row in reported_orgs:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    for row in pescore_hist_darkweb_ment_data:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["date"] = convert_date_to_string(row["date"])
    return {
        "reported_orgs": reported_orgs,
        "hist_darkweb_ment_data": pescore_hist_darkweb_ment_data,
    }


# --- pescore_hist_cred(), Issue 635 ---
@shared_task(bind=True)
def pescore_hist_cred_task(self, start_date: str, end_date: str):
    """Task function for the pescore_hist_cred API endpoint."""
    # Make database query and convert to list of dictionaries
    # Get reported orgs
    reported_orgs = list(
        Organizations.objects.filter(report_on=True).values(
            "organizations_uid", "cyhy_db_name"
        )
    )
    # Get cred data
    pescore_hist_cred_data = list(
        VwBreachcompCredsbydate.objects.filter(
            mod_date__range=[start_date, end_date]
        ).values()
    )
    # Convert uuids to strings
    for row in reported_orgs:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    for row in pescore_hist_cred_data:
        row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
        row["mod_date"] = convert_date_to_string(row["mod_date"])
    return {
        "reported_orgs": reported_orgs,
        "hist_cred_data": pescore_hist_cred_data,
    }


# --- pescore_base_metrics(), Issue 635 ---
@shared_task(bind=True)
def pescore_base_metrics_task(self, start_date: str, end_date: str):
    """Task function for the pescore_base_metrics API endpoint."""
    # Make database query and convert to list of dictionaries
    # Get reported orgs
    reported_orgs = list(
        Organizations.objects.filter(report_on=True).values("organizations_uid")
    )
    # print("pescore_base_metric query status: got reported_orgs")
    # Gather credential data and aggregate
    cred_data = list(
        VwBreachcompCredsbydate.objects.filter(mod_date__range=[start_date, end_date])
        .values("organizations_uid")
        .annotate(
            no_password=Sum("no_password"), password_included=Sum("password_included")
        )
        .order_by()
    )
    # print("pescore_base_metric query status: got cred_data")
    # Gather breach data and aggregate
    breach_data = list(
        VwBreachcomp.objects.filter(modified_date__range=[start_date, end_date])
        .values("organizations_uid")
        .annotate(num_breaches=Count("breach_name", distinct=True))
        .order_by()
    )
    # print("pescore_base_metric query status: got breach_data")
    # Gather suspected domain data and aggregate
    domain_sus_data = list(
        DomainPermutations.objects.filter(
            date_active__range=[start_date, end_date], malicious=True
        )
        .values("organizations_uid")
        .annotate(num_sus_domain=Count("*"))
        .order_by()
    )
    # print("pescore_base_metric query status: got domain_sus_data")
    # Gather domain alert data and aggregate
    domain_alert_data = list(
        DomainAlerts.objects.filter(date__range=[start_date, end_date])
        .values("organizations_uid")
        .annotate(num_alert_domain=Count("*"))
        .order_by()
    )
    # print("pescore_base_metric query status: got domain_alert_data")
    # Gather verified vulnerability data and aggregate
    vuln_verif_data = (
        VwShodanvulnsVerified.objects.filter(timestamp__range=[start_date, end_date])
        .values("organizations_uid", "cve", "ip")
        .distinct()
    )
    vuln_verif_data = list(
        vuln_verif_data.values("organizations_uid")
        .annotate(num_verif_vulns=Count("*"))
        .order_by()
    )
    # print("pescore_base_metric query status: got vuln_verif_data")
    # Gather unverified vulnerability data and aggregate
    # unnest CVEs?
    vuln_unverif_data = (
        VwShodanvulnsSuspected.objects.filter(timestamp__range=[start_date, end_date])
        .exclude(type="Insecure Protocol")
        .values("organizations_uid", "potential_vulns", "ip")
        .distinct()
    )
    vuln_unverif_data = list(
        vuln_unverif_data.values("organizations_uid")
        .annotate(num_assets_unverif_vulns=Count("*"))
        .order_by()
    )
    # print("pescore_base_metric query status: got vuln_unverif_data")
    # Gather port vulnerability data and aggregate
    vuln_port_data = (
        VwShodanvulnsSuspected.objects.filter(
            timestamp__range=[start_date, end_date], type="Insecure Protocol"
        )
        .exclude(protocol__in=("http", "smtp"))
        .values("organizations_uid", "protocol", "ip", "port")
        .distinct()
    )
    vuln_port_data = list(
        vuln_port_data.values("organizations_uid")
        .annotate(num_risky_ports=Count("port"))
        .order_by()
    )
    # print("pescore_base_metric query status: got vuln_port_data")
    # Gather darkweb alert data and aggregate
    darkweb_alert_data = list(
        Alerts.objects.filter(date__range=[start_date, end_date])
        .values("organizations_uid")
        .annotate(num_dw_alerts=Count("*"))
        .order_by()
    )
    # print("pescore_base_metric query status: got darkweb_alert_data")
    # Gather darkweb mention data and aggregate
    darkweb_ment_data = list(
        VwDarkwebMentionsbydate.objects.filter(date__range=[start_date, end_date])
        .values("organizations_uid")
        .annotate(num_dw_mentions=Sum("count"))
        .order_by()
    )
    # print("pescore_base_metric query status: got darkweb_ment_data")
    # Gather darkweb threat data and aggregate
    darkweb_threat_data = list(
        VwDarkwebPotentialthreats.objects.filter(date__range=[start_date, end_date])
        .values("organizations_uid")
        .annotate(num_dw_threats=Count("*"))
        .order_by()
    )
    # print("pescore_base_metric query status: got darkweb_threat_data")
    # Gather darkweb invite data and aggregate
    darkweb_inv_data = list(
        VwDarkwebInviteonlymarkets.objects.filter(date__range=[start_date, end_date])
        .values("organizations_uid")
        .annotate(num_dw_invites=Count("*"))
        .order_by()
    )
    # print("pescore_base_metric query status: got darkweb_inv_data")
    # Gather attacksurface data and aggregate
    attacksurface_data = list(
        VwOrgsAttacksurface.objects.values(
            "organizations_uid",
            "cyhy_db_name",
            "num_ports",
            "num_root_domain",
            "num_sub_domain",
            "num_ips",
        )
    )
    # Testing
    # reported_orgs = reported_orgs[:10]
    # cred_data = cred_data[:10]
    # breach_data = breach_data[:10]
    # domain_sus_data = domain_sus_data[:10]
    # domain_alert_data = domain_alert_data[:10]
    # vuln_verif_data = vuln_verif_data[:10]
    # vuln_unverif_data = vuln_unverif_data[:10]
    # vuln_port_data = vuln_port_data[:10]
    # darkweb_alert_data = darkweb_alert_data[:10]
    # darkweb_ment_data = darkweb_ment_data[:10]
    # darkweb_threat_data = darkweb_threat_data[:10]
    # darkweb_inv_data = darkweb_inv_data[:10]
    # attacksurface_data = attacksurface_data[:10]
    # print("pescore_base_metric query status: got attacksurface_data")
    # Convert uuids to strings
    for dataset in [
        reported_orgs,
        cred_data,
        breach_data,
        domain_sus_data,
        domain_alert_data,
        vuln_verif_data,
        vuln_unverif_data,
        vuln_port_data,
        darkweb_alert_data,
        darkweb_ment_data,
        darkweb_threat_data,
        darkweb_inv_data,
        attacksurface_data,
    ]:
        for row in dataset:
            row["organizations_uid"] = convert_uuid_to_string(row["organizations_uid"])
    return {
        "reported_orgs": reported_orgs,
        "cred_data": cred_data,
        "breach_data": breach_data,
        "domain_sus_data": domain_sus_data,
        "domain_alert_data": domain_alert_data,
        "vuln_verif_data": vuln_verif_data,
        "vuln_unverif_data": vuln_unverif_data,
        "vuln_port_data": vuln_port_data,
        "darkweb_alert_data": darkweb_alert_data,
        "darkweb_ment_data": darkweb_ment_data,
        "darkweb_threat_data": darkweb_threat_data,
        "darkweb_inv_data": darkweb_inv_data,
        "attacksurface_data": attacksurface_data,
    }


# --- upsert_new_cves(), Issue 637 ---
@shared_task(bind=True)
def cve_info_insert_task(self, new_cves: List[dict]):
    """Task function for the cve_info_insert API endpoint."""
    # Go through each new cve
    for cve in new_cves:
        try:
            CveInfo.objects.get(cve_name=cve["cve_name"])
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
            CveInfo.objects.filter(cve_name=cve["cve_name"]).update(
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


@shared_task(bind=True)
def get_xpanse_vulns(
    self, business_unit: str, modified_datetime: Optional[datetime.datetime] = None
):
    """Task function for the Xpanse Vulns by business_unit and modified_date API endpoint."""
    # Make database query and convert to list of dictionaries

    xpanse_alerts = XpanseAlerts.objects.filter(
        business_units__entity_name=business_unit
    )

    if modified_datetime is not None:
        xpanse_alerts = xpanse_alerts.filter(
            Q(local_insert_ts__gte=modified_datetime)
            | Q(last_modified_ts__gte=modified_datetime)
        )

    vulns = []
    for alert in xpanse_alerts:
        vuln_dict = {
            "alert_name": alert.alert_name,  # str
            "description": alert.description,  # str
            "last_modified_ts": alert.last_modified_ts,  # datetime
            "local_insert_ts": alert.local_insert_ts,  # datetime
            "event_timestamp": alert.event_timestamp,  # List[datetime]
            "host_name": alert.host_name,  # str
            "alert_action": alert.alert_action,  # str
            "action_country": alert.action_country,  # List[str]
            "action_remote_port": alert.action_remote_port,  # List[int]
            "external_id": alert.external_id,  # str
            "related_external_id": alert.related_external_id,  # str
            "alert_occurrence": alert.alert_occurrence,  # int
            "severity": alert.severity,  # str
            "matching_status": alert.matching_status,  # str
            "alert_type": alert.alert_type,  # str
            "resolution_status": alert.resolution_status,  # str
            "resolution_comment": alert.resolution_comment,  # str
            "last_observed": alert.last_observed,  # datetime
            "country_codes": alert.country_codes,  # List[str]
            "cloud_providers": alert.cloud_providers,  # List[str]
            "ipv4_addresses": alert.ipv4_addresses,  # List[str]
            "domain_names": alert.domain_names,  # List[str]
            "port_protocol": alert.port_protocol,  # str
            "time_pulled_from_xpanse": alert.time_pulled_from_xpanse,  # datetime
            "action_pretty": alert.action_pretty,  # str
            "attack_surface_rule_name": alert.attack_surface_rule_name,  # str
            "certificate": alert.certificate,  # Dict
            "remediation_guidance": alert.remediation_guidance,  # str
            "asset_identifiers": alert.asset_identifiers,  # List[Dict]
            "services": [],
        }

        for service in alert.services.all():
            service_dict = {
                "service_id": service.service_id,
                "service_name": service.service_name,
                "service_type": service.service_type,
                "ip_address": service.ip_address,
                "domain": service.domain,
                "externally_detected_providers": service.externally_detected_providers,
                "is_active": service.is_active,
                "first_observed": service.first_observed,
                "last_observed": service.last_observed,
                "port": service.port,
                "protocol": service.protocol,
                "active_classifications": service.active_classifications,
                "inactive_classifications": service.inactive_classifications,
                "discovery_type": service.discovery_type,
                "externally_inferred_vulnerability_score": service.externally_inferred_vulnerability_score,
                "externally_inferred_cves": service.externally_inferred_cves,
                "service_key": service.service_key,
                "service_key_type": service.service_key_type,
                "cves": [],
            }
            cve_services = service.xpansecveservice_set.select_related(
                "xpanse_inferred_cve"
            )
            for vuln in cve_services:
                service_dict["cves"].append(
                    {
                        "cve_id": vuln.xpanse_inferred_cve.cve_id,
                        "cvss_score_v2": vuln.xpanse_inferred_cve.cvss_score_v2,
                        "cve_severity_v2": vuln.xpanse_inferred_cve.cve_severity_v2,
                        "cvss_score_v3": vuln.xpanse_inferred_cve.cvss_score_v3,
                        "cve_severity_v3": vuln.xpanse_inferred_cve.cve_severity_v3,
                        "inferred_cve_match_type": vuln.inferred_cve_match_type,
                        "product": vuln.product,
                        "confidence": vuln.confidence,
                        "vendor": vuln.vendor,
                        "version_number": vuln.version_number,
                        "activity_status": vuln.activity_status,
                        "first_observed": vuln.first_observed,
                        "last_observed": vuln.last_observed,
                    }
                )

            vuln_dict["services"].append(service_dict)
        vulns.append(vuln_dict)

    return vulns


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


# --- insert_sixgill_alerts(), Issue 653 ---
@shared_task(bind=True)
def alerts_insert_task(self, new_alerts: List[dict]):
    """Task function for the alerts_insert API endpoint."""
    # Go through each new alert
    update_ct = 0
    create_ct = 0
    for new_alert in new_alerts:
        try:
            Alerts.objects.get(sixgill_id=new_alert["sixgill_id"])
        except Alerts.DoesNotExist:
            # If alert record doesn't exist yet, create one
            curr_org_inst = Organizations.objects.get(
                organizations_uid=new_alert["organizations_uid"]
            )
            curr_source_inst = DataSource.objects.get(
                data_source_uid=new_alert["data_source_uid"]
            )
            Alerts.objects.create(
                alerts_uid=uuid.uuid1(),
                alert_name=new_alert["alert_name"],
                content=new_alert["content"],
                date=new_alert["date"],
                sixgill_id=new_alert["sixgill_id"],
                read=new_alert["read"],
                severity=new_alert["severity"],
                site=new_alert["site"],
                threat_level=new_alert["threat_level"],
                threats=new_alert["threats"],
                title=new_alert["title"],
                user_id=new_alert["user_id"],
                category=new_alert["category"],
                lang=new_alert["lang"],
                organizations_uid=curr_org_inst,
                data_source_uid=curr_source_inst,
                content_snip=new_alert["content_snip"],
                asset_mentioned=new_alert["asset_mentioned"],
                asset_type=new_alert["asset_type"],
            )
            create_ct += 1
        else:
            # If alert record does exits, update it
            Alerts.objects.filter(sixgill_id=new_alert["sixgill_id"]).update(
                content=new_alert["content"],
                content_snip=new_alert["content_snip"],
                asset_mentioned=new_alert["asset_mentioned"],
                asset_type=new_alert["asset_type"],
            )
            update_ct += 1
    # Return success message
    return (
        str(create_ct)
        + " records created, "
        + str(update_ct)
        + " records updated in the alerts table"
    )


# --- insert_sixgill_mentions(), Issue 654 ---
@shared_task(bind=True)
def mentions_insert_task(self, new_mentions: List[dict]):
    """Task function for the mentions_insert API endpoint."""
    create_ct = 0
    for new_mention in new_mentions:
        try:
            Mentions.objects.get(sixgill_mention_id=new_mention["sixgill_mention_id"])
            # If record already exists, do nothing
        except Mentions.DoesNotExist:
            # If mention record doesn't exist yet, create one
            curr_source_inst = DataSource.objects.get(
                data_source_uid=new_mention["data_source_uid"]
            )
            Mentions.objects.create(
                mentions_uid=uuid.uuid1(),
                organizations_uid=new_mention["organizations_uid"],
                data_source_uid=curr_source_inst,
                category=new_mention["category"],
                collection_date=new_mention["collection_date"],
                content=new_mention["content"],
                creator=new_mention["creator"],
                date=new_mention["date"],
                sixgill_mention_id=new_mention["sixgill_mention_id"],
                lang=new_mention["lang"],
                post_id=new_mention["post_id"],
                rep_grade=new_mention["rep_grade"],
                site=new_mention["site"],
                site_grade=new_mention["site_grade"],
                sub_category=new_mention["sub_category"],
                title=new_mention["title"],
                type=new_mention["type"],
                url=new_mention["url"],
                comments_count=new_mention["comments_count"],
                tags=new_mention["tags"],
            )
            create_ct += 1
    # Return success message
    return str(create_ct) + " records created in the mentions table"


# --- insert_sixgill_breaches(), Issue 655 ---
@shared_task(bind=True)
def cred_breach_sixgill_task(self, new_breaches: List[dict]):
    """Task function for the cred_breaches_sixgill_insert API endpoint."""
    create_ct = 0
    update_ct = 0
    for new_breach in new_breaches:
        # Insert each row of data
        try:
            CredentialBreaches.objects.get(breach_name=new_breach["breach_name"])
            # If record already exists, update
            CredentialBreaches.objects.filter(
                breach_name=new_breach["breach_name"]
            ).update(
                password_included=new_breach["password_included"],
            )
            update_ct += 1
        except CredentialBreaches.DoesNotExist:
            # Otherwise, create new record
            curr_source_inst = DataSource.objects.get(
                data_source_uid=new_breach["data_source_uid"]
            )
            CredentialBreaches.objects.create(
                credential_breaches_uid=uuid.uuid1(),
                breach_name=new_breach["breach_name"],
                description=new_breach["description"],
                breach_date=new_breach["breach_date"],
                password_included=new_breach["password_included"],
                data_source_uid=curr_source_inst,
                modified_date=new_breach["modified_date"],
            )
            create_ct += 1
    # Return success message
    return (
        str(create_ct)
        + " records created, "
        + str(update_ct)
        + " records updated in the credential_breaches table"
    )


# --- insert_sixgill_credentials(), Issue 656 ---
@shared_task(bind=True)
def cred_exp_sixgill_task(self, new_exposures: List[dict]):
    """Task function for the credexp_insert API endpoint."""
    update_ct = 0
    create_ct = 0
    for new_exposure in new_exposures:
        try:
            CredentialExposures.objects.get(
                breach_name=new_exposure["breach_name"],
                email=new_exposure["email"],
            )
        except CredentialExposures.DoesNotExist:
            # If cred exp record doesn't exist yet, create one
            curr_org_inst = Organizations.objects.get(
                organizations_uid=new_exposure["organizations_uid"]
            )
            curr_source_inst = DataSource.objects.get(
                data_source_uid=new_exposure["data_source_uid"]
            )
            curr_breach_inst = CredentialBreaches.objects.get(
                credential_breaches_uid=new_exposure["credential_breaches_uid"]
            )
            CredentialExposures.objects.create(
                credential_exposures_uid=uuid.uuid1(),
                modified_date=new_exposure["modified_date"],
                sub_domain=new_exposure["sub_domain"],
                email=new_exposure["email"],
                hash_type=new_exposure["hash_type"],
                name=new_exposure["name"],
                login_id=new_exposure["login_id"],
                password=new_exposure["password"],
                phone=new_exposure["phone"],
                breach_name=new_exposure["breach_name"],
                organizations_uid=curr_org_inst,
                data_source_uid=curr_source_inst,
                credential_breaches_uid=curr_breach_inst,
            )
            create_ct += 1
        else:
            # If cred exp record does exits, update it
            CredentialExposures.objects.filter(
                breach_name=new_exposure["breach_name"],
                email=new_exposure["email"],
            ).update(
                modified_date=new_exposure["modified_date"],
            )
            update_ct += 1
    # Return success message
    return (
        str(create_ct)
        + " records created, "
        + str(update_ct)
        + " records updated in the credential_exposures table"
    )


# --- insert_sixgill_topCVEs(), Issue 657 ---
@shared_task(bind=True)
def top_cves_insert_task(self, new_topcves: List[dict]):
    """Task function for the top_cves_insert API endpoint."""
    create_ct = 0
    for new_topcve in new_topcves:
        try:
            TopCves.objects.get(
                cve_id=new_topcve["cve_id"],
                date=new_topcve["date"],
            )
            # If record already exists, do nothing
        except TopCves.DoesNotExist:
            # If record doesn't exist yet, create one
            curr_source_inst = DataSource.objects.get(
                data_source_uid=new_topcve["data_source_uid"]
            )
            TopCves.objects.create(
                top_cves_uid=uuid.uuid1(),
                cve_id=new_topcve["cve_id"],
                dynamic_rating=new_topcve["dynamic_rating"],
                nvd_base_score=new_topcve["nvd_base_score"],
                date=new_topcve["date"],
                summary=new_topcve["summary"],
                data_source_uid=curr_source_inst,
            )
            create_ct += 1
    # Return success message
    return str(create_ct) + " records created in the top_cves table"


# --- query_subs(), Issue 633 ---
@shared_task(bind=True)
def cves_by_modified_date_task(self, modified_datetime: str, page: int, per_page: int):
    """Task function for the subdomains by org query API endpoint."""
    # Make database query and convert to list of dictionaries
    total_data = Cves.objects.all()

    if modified_datetime is not None:
        total_data = total_data.filter(
            Q(last_modified_date__gte=modified_datetime)
            | Q(published_date__gte=modified_datetime)
        )

    total_data = total_data.order_by("cve_name")
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

    cve_list = []
    paged_queryset = single_page_data.object_list

    paged_queryset = paged_queryset.prefetch_related(
        Prefetch(
            "products",
            queryset=CpeProduct.objects.select_related("cpe_vender_uid"),
        )
    )
    if not paged_queryset:
        single_page_data = [{x: None for x in schemas.CveWithProducts.__fields__}]
        return {
            "total_pages": paged_data.num_pages,
            "current_page": page,
            "data": single_page_data,
        }
    else:
        for cve in paged_queryset:
            cve_obj = {
                "cve_uid": convert_uuid_to_string(cve.cve_uid),
                "cve_name": cve.cve_name,
                "published_date": cve.published_date,
                "last_modified_date": cve.last_modified_date,
                "vuln_status": cve.vuln_status,
                "description": cve.description,
                "cvss_v2_source": cve.cvss_v2_source,
                "cvss_v2_type": cve.cvss_v2_type,
                "cvss_v2_version": cve.cvss_v2_version,
                "cvss_v2_vector_string": cve.cvss_v2_vector_string,
                "cvss_v2_base_score": cve.cvss_v2_base_score,
                "cvss_v2_base_severity": cve.cvss_v2_base_severity,
                "cvss_v2_exploitability_score": cve.cvss_v2_exploitability_score,
                "cvss_v2_impact_score": cve.cvss_v2_impact_score,
                "cvss_v3_source": cve.cvss_v3_source,
                "cvss_v3_type": cve.cvss_v3_type,
                "cvss_v3_version": cve.cvss_v3_version,
                "cvss_v3_vector_string": cve.cvss_v3_vector_string,
                "cvss_v3_base_score": cve.cvss_v3_base_score,
                "cvss_v3_base_severity": cve.cvss_v3_base_severity,
                "cvss_v3_exploitability_score": cve.cvss_v3_exploitability_score,
                "cvss_v3_impact_score": cve.cvss_v3_impact_score,
                "cvss_v4_source": cve.cvss_v4_source,
                "cvss_v4_type": cve.cvss_v4_type,
                "cvss_v4_version": cve.cvss_v4_version,
                "cvss_v4_vector_string": cve.cvss_v4_vector_string,
                "cvss_v4_base_score": cve.cvss_v4_base_score,
                "cvss_v4_base_severity": cve.cvss_v4_base_severity,
                "cvss_v4_exploitability_score": cve.cvss_v4_exploitability_score,
                "cvss_v4_impact_score": cve.cvss_v4_impact_score,
                "weaknesses": cve.weaknesses,
                "reference_urls": cve.reference_urls,
                "cpe_list": cve.cpe_list,
                "vender_product": {},
            }

            for product in cve.products.all():
                product_obj = {
                    "cpe_product_name": product.cpe_product_name,
                    "version_number": product.version_number,
                    "vender": product.cpe_vender_uid.vender_name,
                }
                if product.cpe_vender_uid.vender_name in cve_obj["vender_product"]:
                    cve_obj["vender_product"][
                        product.cpe_vender_uid.vender_name
                    ].append(product_obj)
                else:
                    cve_obj["vender_product"][product.cpe_vender_uid.vender_name] = [
                        product_obj
                    ]

            cve_list.append(cve_obj)

        result = {
            "total_pages": paged_data.num_pages,
            "current_page": page,
            "data": cve_list,
        }
        return result
