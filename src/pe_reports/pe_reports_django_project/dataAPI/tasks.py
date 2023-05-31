from typing import List
from celery import shared_task
from home.models import MatVwOrgsAllIps
import datetime
from django.db.models import Q

# D-Score View Models:
from home.models import (
    VwDscoreVSCert,
    VwDscoreVSMail,
    VwDscorePEIp,
    VwDscorePEDomain,
    VwDscoreWASWebapp,
)

# I-Score View Models:
from home.models import (
    VwIscoreVSVuln,
    VwIscoreVSVulnPrev,
    VwIscorePEVuln,
    VwIscorePECred,
    VwIscorePEBreach,
    VwIscorePEDarkweb,
    VwIscorePEProtocol,
    VwIscoreWASVuln,
    VwIscoreWASVulnPrev,
)

# Misc. Score View Models:
# Need: kev_list, fceb_status, stakeholder lists?


@shared_task(bind=True)
def get_vs_info(self, cyhy_db_names: List[str]):
    vs_data = list(MatVwOrgsAllIps.objects.filter(cyhy_db_name__in=cyhy_db_names))
    return vs_data


# ---------- D-Score View Tasks ----------
@shared_task(bind=True)
def get_dscore_vs_cert_info(self, specified_orgs: List[str]):
    """Task function for the dscore_vs_cert API endpoint."""
    # Make database query
    dscore_vs_cert = list(
        VwDscoreVSCert.objects.filter(organizations_uid__in=specified_orgs)
    )
    return dscore_vs_cert


@shared_task(bind=True)
def get_dscore_vs_mail_info(self, specified_orgs: List[str]):
    """Task function for the dscore_vs_mail API endpoint."""
    # Make database query
    dscore_vs_mail = list(
        VwDscoreVSMail.objects.filter(organizations_uid__in=specified_orgs)
    )
    return dscore_vs_mail


@shared_task(bind=True)
def get_dscore_pe_ip_info(self, specified_orgs: List[str]):
    """Task function for the dscore_pe_ip API endpoint."""
    # Make database query
    dscore_pe_ip = list(
        VwDscorePEIp.objects.filter(organizations_uid__in=specified_orgs)
    )
    return dscore_pe_ip


@shared_task(bind=True)
def get_dscore_pe_domain_info(self, specified_orgs: List[str]):
    """Task function for the dscore_pe_domain API endpoint."""
    # Make database query
    dscore_pe_domain = list(
        VwDscorePEDomain.objects.filter(organizations_uid__in=specified_orgs)
    )
    return dscore_pe_domain


@shared_task(bind=True)
def get_dscore_was_webapp_info(self, specified_orgs: List[str]):
    """Task function for the dscore_was_webapp API endpoint."""
    # Make database query
    dscore_was_webapp = list(
        VwDscoreWASWebapp.objects.filter(organizations_uid__in=specified_orgs)
    )
    return dscore_was_webapp


# ---------- I-Score View Tasks ----------
@shared_task(bind=True)
def get_iscore_vs_vuln_info(self, specified_orgs: List[str]):
    """Task function for the iscore_vs_vuln API endpoint."""
    # Make database query
    iscore_vs_vuln = list(
        VwIscoreVSVuln.objects.filter(organizations_uid__in=specified_orgs)
    )
    return iscore_vs_vuln


@shared_task(bind=True)
def get_iscore_vs_vuln_prev_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_vs_vuln_prev API endpoint."""
    # Make database query
    iscore_vs_vuln_prev = list(
        VwIscoreVSVulnPrev.objects.filter(
            organizations_uid__in=specified_orgs,
            time_closed__gte=start_date,
            time_closed__lte=end_date,
        )
    )
    return iscore_vs_vuln_prev


@shared_task(bind=True)
def get_iscore_pe_vuln_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_pe_vuln API endpoint."""
    # Make database query
    iscore_pe_vuln = list(
        VwIscorePEVuln.objects.filter(
            organizations_uid__in=specified_orgs,
            time_closed__gte=start_date,
            time_closed__lte=end_date,
        )
    )
    return iscore_pe_vuln


@shared_task(bind=True)
def get_iscore_pe_cred_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_pe_cred API endpoint."""
    # Make database query
    iscore_pe_cred = list(
        VwIscorePECred.objects.filter(
            organizations_uid__in=specified_orgs,
            time_closed__gte=start_date,
            time_closed__lte=end_date,
        )
    )
    return iscore_pe_cred


@shared_task(bind=True)
def get_iscore_pe_breach_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_pe_breach API endpoint."""
    # Make database query
    iscore_pe_breach = list(
        VwIscorePEBreach.objects.filter(
            organizations_uid__in=specified_orgs,
            time_closed__gte=start_date,
            time_closed__lte=end_date,
        )
    )
    return iscore_pe_breach


@shared_task(bind=True)
def get_iscore_pe_darkweb_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_pe_darkweb API endpoint."""
    # Make database query
    iscore_pe_darkweb = list(
        VwIscorePEDarkweb.objects.filter(
            Q(organizations_uid__in=specified_orgs),
            (Q(date__gte=start_date) & Q(date__lte=end_date)) | Q(date="0001-01-01"),
        )
    )
    return iscore_pe_darkweb


@shared_task(bind=True)
def get_iscore_pe_protocol_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_pe_protocol API endpoint."""
    # Make database query
    iscore_pe_protocol = list(
        VwIscorePEProtocol.objects.filter(
            organizations_uid__in=specified_orgs,
            time_closed__gte=start_date,
            time_closed__lte=end_date,
        )
    )
    return iscore_pe_protocol


@shared_task(bind=True)
def get_iscore_was_vuln_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_was_vuln API endpoint."""
    # Make database query
    iscore_was_vuln = list(
        VwIscoreWASVuln.objects.filter(
            organizations_uid__in=specified_orgs,
            time_closed__gte=start_date,
            time_closed__lte=end_date,
        )
    )
    return iscore_was_vuln


@shared_task(bind=True)
def get_iscore_was_vuln_prev_info(
    self, specified_orgs: List[str], start_date: datetime.date, end_date: datetime.date
):
    """Task function for the iscore_was_vuln_prev API endpoint."""
    # Make database query
    iscore_was_vuln_prev = list(
        VwIscoreWASVulnPrev.objects.filter(
            organizations_uid__in=specified_orgs,
            time_closed__gte=start_date,
            time_closed__lte=end_date,
        )
    )
    return iscore_was_vuln_prev
