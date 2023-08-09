"""Pydantic models used by FastAPI"""
# Standard Python Libraries
from datetime import date, datetime

# from pydantic.types import UUID1, UUID
from typing import Any, List, Optional
import uuid
from uuid import UUID, uuid1, uuid4

# Third-Party Libraries
from pydantic import BaseModel, EmailStr, Field
from pydantic.schema import Optional

"""
Developer Note: If there comes an instance as in class Cidrs where there are
foreign keys. The data type will not be what is stated in the database. What is
happening is the data base is making a query back to the foreign key table and
returning it as the column in its entirety i.e. select * from <table>, so it
will error and not be able to report on its data type. In these scenario's use
the data type "Any" to see what the return is.
"""


class OrgType(BaseModel):
    org_type_uid: UUID

    class Config:
        orm_mode = True


class OrganizationBase(BaseModel):
    organizations_uid: UUID
    name: str
    cyhy_db_name: str = None
    org_type_uid: Any
    report_on: bool
    password: Optional[str]
    date_first_reported: Optional[datetime]
    parent_org_uid: Any
    premium_report: Optional[bool] = None
    agency_type: Optional[str] = None
    demo: bool = False

    class Config:
        orm_mode = True
        validate_assignment = True


class Organization(OrganizationBase):
    pass

    class Config:
        orm_mode = True


class SubDomainBase(BaseModel):
    sub_domain_uid: UUID
    sub_domain: str
    root_domain_uid: Optional[Any]
    data_source_uid: Optional[Any]
    dns_record_uid: Optional[Any] = None
    status: bool = False

    class Config:
        orm_mode = True
        validate_assignment = True


class VwBreachcomp(BaseModel):
    credential_exposures_uid: str
    email: str
    breach_name: str
    organizations_uid: str
    root_domain: str
    sub_domain: str
    hash_type: str
    name: str
    login_id: str
    password: str
    phone: str
    data_source_uid: str
    description: str
    breach_date: str
    added_date: str
    modified_date: str
    data_classes: str
    password_included: str
    is_verified: str
    is_fabricated: str
    is_sensitive: str
    is_retired: str
    is_spam_list: str


class VwBreachDetails(BaseModel):
    organizations_uid: str
    breach_name: str
    mod_date: str
    description: str
    breach_date: str
    password_included: str
    number_of_creds: str


class VwBreachcompCredsbydate(BaseModel):
    organizations_uid: str
    mod_date: str
    no_password: str
    password_included: str


class VwOrgsAttacksurface(BaseModel):
    organizations_uid: UUID
    cyhy_db_name: str
    num_ports: str
    num_root_domain: str
    num_sub_domain: str
    num_ips: str

    class Config:
        orm_mode = True


class VwOrgsAttacksurfaceInput(BaseModel):
    organizations_uid: UUID

    class Config:
        orm_mode = True


class MatVwOrgsAllIps(BaseModel):
    organizations_uid: Any
    cyhy_db_name: str
    ip_addresses: List[Optional[str]] = []

    class Config:
        orm_mode = True


class TaskResponse(BaseModel):
    task_id: str
    status: str
    result: List[MatVwOrgsAllIps] = None
    error: str = None


class veMatVwOrgsAllIps(BaseModel):
    cyhy_db_name: Optional[str]

    class Config:
        orm_mode = True


class veTaskResponse(BaseModel):
    task_id: str
    status: str
    result: List[veMatVwOrgsAllIps] = None
    error: str = None


class WASDataBase(BaseModel):
    # customer_id: UUID
    tag: Optional[str] = "test"
    customer_name: Optional[str] = "test"
    testing_sector: Optional[str] = "test"
    ci_type: Optional[str] = "test"
    jira_ticket: Optional[str] = "test"
    ticket: Optional[str] = "test"
    next_scheduled: Optional[str] = "test"
    last_scanned: Optional[str] = "test"
    frequency: Optional[str] = "test"
    comments_notes: Optional[str] = "test"
    was_report_poc: Optional[str] = "test"
    was_report_email: Optional[str] = "test"
    onboarding_date: Optional[str] = "test"
    no_of_web_apps: Optional[int]
    no_web_apps_last_updated: Optional[str] = "test"
    elections: Optional[str] = "test"
    fceb: Optional[str] = "test"
    special_report: Optional[str] = "test"
    report_password: Optional[str] = "test"
    child_tags: Optional[str] = "test"

    class Config:
        orm_mode = True
        validate_assignment = True


class WeeklyStatuses(BaseModel):

    key_accomplishments: Optional[str] = None
    ongoing_task: Optional[str] = None
    upcoming_task: Optional[str] = None
    obstacles: Optional[str] = None
    non_standard_meeting: Optional[str] = None
    deliverables: Optional[str] = None
    pto: Optional[str] = None
    week_ending: Optional[str] = None
    notes: Optional[str] = None
    statusComplete: Optional[str] = None

    class Config:
        orm_mode = True
        validate_assignment = True


class UserStatuses(BaseModel):

    user_fname: str

    class Config:
        orm_mode = True
        validate_assignment = True


class CyhyPortScans(BaseModel):
    cyhy_port_scans_uid: UUID
    organizations_uid: Any
    cyhy_id: str
    cyhy_time: str
    service_name: str
    port: str
    product: str
    cpe: str
    first_seen: str
    last_seen: str
    ip: str
    state: str
    agency_type: str

    class Config:
        orm_mode: True
        validate_assignment = True


class CyhyDbAssets(BaseModel):
    # field_id: str
    org_id: str
    org_name: str
    contact: Optional[str] = None
    network: str
    type: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    currently_in_cyhy: Optional[str] = None

    class Config:
        orm_mode = True


class CyhyDbAssetsInput(BaseModel):
    org_id: str

    class Config:
        orm_mode = True


class Cidrs(BaseModel):
    cidr_uid: UUID
    network: Any
    organizations_uid: Any
    data_source_uid: Any
    insert_alert: Optional[str] = None

    class Config:
        orm_mode = True


class VwCidrs(BaseModel):
    cidr_uid: str
    network: str
    organizations_uid: str
    data_source_uid: str
    insert_alert: Optional[str] = None


class DataSource(BaseModel):

    data_source_uid: Optional[UUID]
    name: Optional[str]
    description: Optional[str]
    last_run: Optional[str]

    class Config:
        orm_mode = True


class UserAPIBase(BaseModel):
    # user_id: int
    refresh_token: str


class UserAPI(UserAPIBase):
    pass

    class Config:
        orm_mode = True


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str


class TokenPayload(BaseModel):
    sub: str = None
    exp: int = None


class UserAuth(BaseModel):
    # id: UUID = Field(..., description='user UUID')
    # email: EmailStr = Field(..., description="user email")
    username: str = Field(..., description="user name")
    # password: str = Field(..., min_length=5, max_length=24,
    #                       description="user password")


class UserOut(BaseModel):
    id: UUID
    email: str


class SystemUser(UserOut):
    password: str


# Shared properties
class UserBase(BaseModel):
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = True
    is_superuser: bool = False
    full_name: Optional[str] = None


# Properties to receive via API on creation
class UserCreate(UserBase):
    email: EmailStr
    password: str


# Properties to receive via API on update
class UserUpdate(UserBase):
    password: Optional[str] = None


class UserInDBBase(UserBase):
    id: Optional[int] = None

    class Config:
        orm_mode = True


# Additional properties to return via API
class User(UserInDBBase):
    pass


# Additional properties stored in DB
class UserInDB(UserInDBBase):
    hashed_password: str


# ---------- D-Score View Schemas ----------
# vw_dscore_vs_cert schema:
class VwDscoreVSCert(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_cert: Optional[int] = None
    num_monitor_cert: Optional[int] = None

    class Config:
        orm_mode = True


# vw_dscore_vs_cert input schema:
class VwDscoreVSCertInput(BaseModel):
    specified_orgs: List[str]

    class Config:
        orm_mode = True


# vw_dscore_vs_cert task response schema:
class VwDscoreVSCertTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwDscoreVSCert] = None
    error: str = None


# vw_dscore_vs_mail schema:
class VwDscoreVSMail(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_valid_dmarc: Optional[int] = None
    num_valid_spf: Optional[int] = None
    num_valid_dmarc_or_spf: Optional[int] = None
    total_mail_domains: Optional[int] = None

    class Config:
        orm_mode = True


# vw_dscore_vs_mail input schema:
class VwDscoreVSMailInput(BaseModel):
    specified_orgs: List[str]

    class Config:
        orm_mode = True


# vw_dscore_vs_mail task response schema:
class VwDscoreVSMailTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwDscoreVSMail] = None
    error: str = None


# vw_dscore_pe_ip schema:
class VwDscorePEIp(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_ip: Optional[int] = None
    num_monitor_ip: Optional[int] = None

    class Config:
        orm_mode = True


# vw_dscore_pe_ip input schema:
class VwDscorePEIpInput(BaseModel):
    specified_orgs: List[str]

    class Config:
        orm_mode = True


# vw_dscore_pe_ip task response schema:
class VwDscorePEIpTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwDscorePEIp] = None
    error: str = None


# vw_dscore_pe_domain schema:
class VwDscorePEDomain(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_domain: Optional[int] = None
    num_monitor_domain: Optional[int] = None

    class Config:
        orm_mode = True


# vw_dscore_pe_domain input schema:
class VwDscorePEDomainInput(BaseModel):
    specified_orgs: List[str]

    class Config:
        orm_mode = True


# vw_dscore_pe_domain task response schema:
class VwDscorePEDomainTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwDscorePEDomain] = None
    error: str = None


# vw_dscore_was_webapp schema:
class VwDscoreWASWebapp(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_webapp: Optional[int] = None
    num_monitor_webapp: Optional[int] = None

    class Config:
        orm_mode = True


# vw_dscore_was_webapp input schema:
class VwDscoreWASWebappInput(BaseModel):
    specified_orgs: List[str]

    class Config:
        orm_mode = True


# vw_dscore_was_webapp task response schema:
class VwDscoreWASWebappTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwDscoreWASWebapp] = None
    error: str = None


# FCEB status query schema (no view):
class FCEBStatus(BaseModel):
    organizations_uid: str
    fceb: Optional[bool] = None

    class Config:
        orm_mode = True


# FCEB status query input schema (no view):
class FCEBStatusInput(BaseModel):
    specified_orgs: List[str]

    class Config:
        orm_mode = True


# FCEB status query task response schema (no view):
class FCEBStatusTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[FCEBStatus] = None
    error: str = None


# ---------- I-Score View Schemas ----------
# vw_iscore_vs_vuln schema:
class VwIscoreVSVuln(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None

    class Config:
        orm_mode = True


# vw_iscore_vs_vuln input schema:
class VwIscoreVSVulnInput(BaseModel):
    specified_orgs: List[str]

    class Config:
        orm_mode = True


# vw_iscore_vs_vuln task response schema:
class VwIscoreVSVulnTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscoreVSVuln] = None
    error: str = None


# vw_iscore_vs_vuln_prev schema:
class VwIscoreVSVulnPrev(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None
    time_closed: Optional[str] = None

    class Config:
        orm_mode = True


# vw_iscore_vs_vuln_prev input schema:
class VwIscoreVSVulnPrevInput(BaseModel):
    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        orm_mode = True


# vw_iscore_vs_vuln_prev task response schema:
class VwIscoreVSVulnPrevTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscoreVSVulnPrev] = None
    error: str = None


# vw_iscore_pe_vuln schema:
class VwIscorePEVuln(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None

    class Config:
        orm_mode = True


# vw_iscore_pe_vuln input schema:
class VwIscorePEVulnInput(BaseModel):
    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        orm_mode = True


# vw_iscore_pe_vuln task response schema:
class VwIscorePEVulnTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscorePEVuln] = None
    error: str = None


# vw_iscore_pe_cred schema:
class VwIscorePECred(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    password_creds: Optional[int] = None
    total_creds: Optional[int] = None

    class Config:
        orm_mode = True


# vw_iscore_pe_cred input schema:
class VwIscorePECredInput(BaseModel):
    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        orm_mode = True


# vw_iscore_pe_cred task response schema:
class VwIscorePECredTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscorePECred] = None
    error: str = None


# vw_iscore_pe_breach schema:
class VwIscorePEBreach(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    breach_count: Optional[int] = None

    class Config:
        orm_mode = True


# vw_iscore_pe_breach input schema:
class VwIscorePEBreachInput(BaseModel):
    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        orm_mode = True


# vw_iscore_pe_breach task response schema:
class VwIscorePEBreachTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscorePEBreach] = None
    error: str = None


# vw_iscore_pe_darkweb schema:
class VwIscorePEDarkweb(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    alert_type: Optional[str] = None
    date: Optional[str] = None
    Count: Optional[int] = None

    class Config:
        orm_mode = True


# vw_iscore_pe_darkweb input schema:
class VwIscorePEDarkwebInput(BaseModel):
    specified_orgs: List[str]
    start_date: str
    end_date: str
    # Don't forget 0001-01-01 dates

    class Config:
        orm_mode = True


# vw_iscore_pe_darkweb task response schema:
class VwIscorePEDarkwebTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscorePEDarkweb] = None
    error: str = None


# vw_iscore_pe_protocol schema:
class VwIscorePEProtocol(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    port: Optional[str] = None
    ip: Optional[str] = None
    protocol: Optional[str] = None
    protocol_type: Optional[str] = None
    date: Optional[str] = None

    class Config:
        orm_mode = True


# vw_iscore_pe_protocol input schema:
class VwIscorePEProtocolInput(BaseModel):
    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        orm_mode = True


# vw_iscore_pe_protocol task response schema:
class VwIscorePEProtocolTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscorePEProtocol] = None
    error: str = None


# vw_iscore_was_vuln schema:
class VwIscoreWASVuln(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None
    owasp_category: Optional[str] = None

    class Config:
        orm_mode = True


# vw_iscore_was_vuln input schema:
class VwIscoreWASVulnInput(BaseModel):
    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        orm_mode = True


# vw_iscore_was_vuln task response schema:
class VwIscoreWASVulnTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscoreWASVuln] = None
    error: str = None


# vw_iscore_was_vuln_prev schema:
class VwIscoreWASVulnPrev(BaseModel):
    organizations_uid: str
    parent_org_uid: Optional[str] = None
    was_total_vulns_prev: Optional[int] = None
    date: Optional[str] = None

    class Config:
        orm_mode = True


# vw_iscore_was_vuln_prev input schema:
class VwIscoreWASVulnPrevInput(BaseModel):
    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        orm_mode = True


# vw_iscore_was_vuln_prev task response schema:
class VwIscoreWASVulnPrevTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscoreWASVulnPrev] = None
    error: str = None


# KEV list query schema (no view):
# KEV list query does not use any input parameters
class KEVList(BaseModel):
    kev: str

    class Config:
        orm_mode = True


# KEV list query task response schema (no view):
class KEVListTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[KEVList] = None
    error: str = None


# ---------- Misc. Score Schemas ----------
# vw_iscore_orgs_ip_counts schema:
# vw_iscore_orgs_ip_counts does not use any input parameters
class VwIscoreOrgsIpCounts(BaseModel):
    organizations_uid: str
    cyhy_db_name: str

    class Config:
        orm_mode = True


# vw_iscore_orgs_ip_counts task response schema:
class VwIscoreOrgsIpCountsTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[VwIscoreOrgsIpCounts] = None
    error: str = None


# --- execute_ips(), Issue 559 ---
# Insert record into Ips
class IpsInsert(BaseModel):
    ip_hash: str
    ip: str
    origin_cidr: str

    class Config:
        orm_mode = True


# --- execute_ips(), Issue 559 ---
# Insert record into Ips, input
class IpsInsertInput(BaseModel):
    new_ips: List[IpsInsert]

    class Config:
        orm_mode = True


# --- execute_ips(), Issue 559 ---
# Insert record into Ips, task resp
class IpsInsertTaskResp(BaseModel):
    task_id: str
    status: str
    result: str = None
    error: str = None


# --- query_all_subs(), Issue 560 ---
# Get entire sub_domains table, single output
class SubDomainTable(BaseModel):
    sub_domain_uid: str
    sub_domain: Optional[str] = None
    root_domain_uid_id: Optional[str] = None
    data_source_uid_id: Optional[str] = None
    dns_record_uid_id: Optional[str] = None
    status: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    current: Optional[bool] = None
    identified: Optional[bool] = None

    class Config:
        orm_mode = True
        validate_assignment = True


# --- query_all_subs(), Issue 560 ---
# Get entire sub_domains table, overall output
class SubDomainResult(BaseModel):
    total_pages: int
    current_page: int
    data: List[SubDomainTable]


# --- query_all_subs(), Issue 560 ---
# Get entire sub_domains table, input
class SubDomainTableInput(BaseModel):
    page: int
    per_page: int

    class Config:
        orm_mode = True


# --- query_all_subs(), Issue 560 ---
# Get entire sub_domains table, task resp
class SubDomainTableTaskResp(BaseModel):
    task_id: str
    status: str
    result: SubDomainResult = None
    error: str = None


# --- execute_scorecard(), Issue 632 ---
# Insert record into report_summary_stats, input
class RSSInsertInput(BaseModel):
    organizations_uid: str
    start_date: str
    end_date: str
    ip_count: int
    root_count: int
    sub_count: int
    ports_count: int
    creds_count: int
    breach_count: int
    cred_password_count: int
    domain_alert_count: int
    suspected_domain_count: int
    insecure_port_count: int
    verified_vuln_count: int
    suspected_vuln_count: int
    suspected_vuln_addrs_count: int
    threat_actor_count: int
    dark_web_alerts_count: int
    dark_web_mentions_count: int
    dark_web_executive_alerts_count: int
    dark_web_asset_alerts_count: int
    pe_number_score: int
    pe_letter_grade: str

    class Config:
        orm_mode = True


# --- query_subs(), Issue 633 ---
# Get all subdomains for an org, input
class SubDomainsByOrgInput(BaseModel):
    org_uid: str

    class Config:
        orm_mode = True


# --- query_previous_period(), Issue 634 ---
# Get prev. report period data from report_summary_stats
class RSSPrevPeriod(BaseModel):
    ip_count: Optional[int] = None
    root_count: Optional[int] = None
    sub_count: Optional[int] = None
    cred_password_count: Optional[int] = None
    suspected_vuln_addrs_count: Optional[int] = None
    suspected_vuln_count: Optional[int] = None
    insecure_port_count: Optional[int] = None
    threat_actor_count: Optional[int] = None

    class Config:
        orm_mode = True


# --- query_previous_period(), Issue 634 ---
# Get prev. report period data from report_summary_stats, input
class RSSPrevPeriodInput(BaseModel):
    org_uid: str
    prev_end_date: str

    class Config:
        orm_mode = True


# ---------- General PE Score Schemas ----------
# --- generalized input schema, Issue 635 ---
# Input date range schema for all PE score endpoints
class PEScoreDateRangeInput(BaseModel):
    start_date: str
    end_date: str

    class Config:
        orm_mode = True


# --- reported orgs schema, Issue 635 ---
# List of reported organizations schema
class ReportedOrgs(BaseModel):
    organizations_uid: str

    class Config:
        orm_mode = True


# --- reported orgs schema, Issue 635 ---
# List of reported organizations schema
class ReportedOrgsCyhy(BaseModel):
    organizations_uid: str
    cyhy_db_name: str

    class Config:
        orm_mode = True


# ---------- PE Score Historical Data ----------
# --- pescore_hist_domain_alert(), Issue 635 ---
# Get pescore_hist_domain_alert data for the specified period
class PEScoreHistDomainAlert(BaseModel):
    organizations_uid: str
    date: str

    class Config:
        orm_mode = True


# --- pescore_hist_domain_alert(), Issue 635 ---
# Get pescore_hist_domain_alert data for the specified period, consolidated resp
class PEScoreHistDomainAlertResp(BaseModel):
    reported_orgs: List[ReportedOrgsCyhy]
    hist_domain_alert_data: List[PEScoreHistDomainAlert]

    class Config:
        orm_mode = True


# --- pescore_hist_domain_alert(), Issue 635 ---
# Get pescore_hist_domain_alert data for the specified period, task resp
class PEScoreHistDomainAlertTaskResp(BaseModel):
    task_id: str
    status: str
    result: PEScoreHistDomainAlertResp = None
    error: str = None


# --- pescore_hist_darkweb_alert(), Issue 635 ---
# Get pescore_hist_darkweb_alert data for the specified period
class PEScoreHistDarkwebAlert(BaseModel):
    organizations_uid: str
    date: str

    class Config:
        orm_mode = True


# --- pescore_hist_darkweb_alert(), Issue 635 ---
# Get pescore_hist_darkweb_alert data for the specified period, consolidated resp
class PEScoreHistDarkwebAlertResp(BaseModel):
    reported_orgs: List[ReportedOrgsCyhy]
    hist_darkweb_alert_data: List[PEScoreHistDarkwebAlert]

    class Config:
        orm_mode = True


# --- pescore_hist_darkweb_alert(), Issue 635 ---
# Get pescore_hist_darkweb_alert data for the specified period, task resp
class PEScoreHistDarkwebAlertTaskResp(BaseModel):
    task_id: str
    status: str
    result: PEScoreHistDarkwebAlertResp = None
    error: str = None


# --- pescore_hist_darkweb_ment(), Issue 635 ---
# Get pescore_hist_darkweb_ment data for the specified period
class PEScoreHistDarkwebMent(BaseModel):
    organizations_uid: str
    date: str
    count: int

    class Config:
        orm_mode = True


# --- pescore_hist_darkweb_ment(), Issue 635 ---
# Get pescore_hist_darkweb_ment data for the specified period, consolidated resp
class PEScoreHistDarkwebMentResp(BaseModel):
    reported_orgs: List[ReportedOrgsCyhy]
    hist_darkweb_ment_data: List[PEScoreHistDarkwebMent]

    class Config:
        orm_mode = True


# --- pescore_hist_darkweb_ment(), Issue 635 ---
# Get pescore_hist_darkweb_ment data for the specified period, task resp
class PEScoreHistDarkwebMentTaskResp(BaseModel):
    task_id: str
    status: str
    result: PEScoreHistDarkwebMentResp = None
    error: str = None


# --- pescore_hist_cred(), Issue 635 ---
# Get pescore_hist_cred data for the specified period
class PEScoreHistCred(BaseModel):
    organizations_uid: str
    mod_date: str
    no_password: int
    password_included: int

    class Config:
        orm_mode = True


# --- pescore_hist_cred(), Issue 635 ---
# Get pescore_hist_cred data for the specified period, consolidated resp
class PEScoreHistCredResp(BaseModel):
    reported_orgs: List[ReportedOrgsCyhy]
    hist_cred_data: List[PEScoreHistCred]

    class Config:
        orm_mode = True


# --- pescore_hist_cred(), Issue 635 ---
# Get pescore_hist_cred data for the specified period, task resp
class PEScoreHistCredTaskResp(BaseModel):
    task_id: str
    status: str
    result: PEScoreHistCredResp = None
    error: str = None


# ---------- PE Score Base Metrics Data ----------
# --- pescore_base_metrics(), Issue 635 ---
# Get data for CRED component of pescore_base_metrics
class PEScoreCred(BaseModel):
    organizations_uid: str
    password_included: int
    no_password: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for BREACH component of pescore_base_metrics
class PEScoreBreach(BaseModel):
    organizations_uid: str
    num_breaches: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DOMAIN SUSPECTED component of pescore_base_metrics
class PEScoreDomainSus(BaseModel):
    organizations_uid: str
    num_sus_domain: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DOMAIN ALERT component of pescore_base_metrics
class PEScoreDomainAlert(BaseModel):
    organizations_uid: str
    num_alert_domain: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for VERIF VULN component of pescore_base_metrics
class PEScoreVulnVerif(BaseModel):
    organizations_uid: str
    num_verif_vulns: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for UNVERIF VULN component of pescore_base_metrics
class PEScoreVulnUnverif(BaseModel):
    organizations_uid: str
    num_assets_unverif_vulns: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for PORT component of pescore_base_metrics
class PEScoreVulnPort(BaseModel):
    organizations_uid: str
    num_risky_ports: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DARKWEB ALERT component of pescore_base_metrics
class PEScoreDarkwebAlert(BaseModel):
    organizations_uid: str
    num_dw_alerts: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DARKWEB MENTION component of pescore_base_metrics
class PEScoreDarkwebMent(BaseModel):
    organizations_uid: str
    num_dw_mentions: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DARKWEB THREAT component of pescore_base_metrics
class PEScoreDarkwebThreat(BaseModel):
    organizations_uid: str
    num_dw_threats: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DARKWEB INVITE component of pescore_base_metrics
class PEScoreDarkwebInv(BaseModel):
    organizations_uid: str
    num_dw_invites: int

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for ATTACKSURFACE component of pescore_base_metrics
class PEScoreAttackSurface(BaseModel):
    organizations_uid: str
    cyhy_db_name: str
    num_ports: Optional[int] = None
    num_root_domain: Optional[int] = None
    num_sub_domain: Optional[int] = None
    num_ips: Optional[int] = None
    num_cidrs: Optional[int] = None
    num_ports_protocols: Optional[int] = None
    num_software: Optional[int] = None
    num_foreign_ips: Optional[int] = None

    class Config:
        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get all base metric data for PE score
class PEScoreBaseMetrics(BaseModel):
    reported_orgs: List[ReportedOrgs]
    cred_data: List[PEScoreCred]
    breach_data: List[PEScoreBreach]
    domain_sus_data: List[PEScoreDomainSus]
    domain_alert_data: List[PEScoreDomainAlert]
    vuln_verif_data: List[PEScoreVulnVerif]
    vuln_unverif_data: List[PEScoreVulnUnverif]
    vuln_port_data: List[PEScoreVulnPort]
    darkweb_alert_data: List[PEScoreDarkwebAlert]
    darkweb_ment_data: List[PEScoreDarkwebMent]
    darkweb_threat_data: List[PEScoreDarkwebThreat]
    darkweb_inv_data: List[PEScoreDarkwebInv]
    attacksurface_data: List[PEScoreAttackSurface]


# --- pescore_base_metrics(), Issue 635 ---
# Get all base metric data for PE score, task resp
class PEScoreBaseMetricsTaskResp(BaseModel):
    task_id: str
    status: str
    result: PEScoreBaseMetrics = None
    error: str = None


# --- get_new_cves_list(), Issue 636 ---
# Get any detected CVEs that aren't in the cve_info table yet
class VwPEScoreCheckNewCVE(BaseModel):
    cve_name: str

    class Config:
        orm_mode = True


# --- upsert_new_cves(), Issue 637 ---
# Upsert new CVEs into cve_info
class CVEInfoInsert(BaseModel):
    cve_name: str
    cvss_2_0: float
    cvss_2_0_severity: str
    cvss_2_0_vector: str
    cvss_3_0: float
    cvss_3_0_severity: str
    cvss_3_0_vector: str
    dve_score: float

    class Config:
        orm_mode = True


# --- upsert_new_cves(), Issue 637 ---
# Upsert new CVEs into cve_info, input
class CVEInfoInsertInput(BaseModel):
    new_cves: List[CVEInfoInsert]

    class Config:
        orm_mode = True


# --- upsert_new_cves(), Issue 637 ---
# Upsert new CVEs into cve_info, task resp
class CVEInfoInsertTaskResp(BaseModel):
    task_id: str
    status: str
    result: str = None
    error: str = None


# --- get_intelx_breaches(), Issue 641 ---
# Get IntelX breaches
class CredBreachIntelX(BaseModel):
    breach_name: str
    credential_breaches_uid: str

    class Config:
        orm_mode = True


# --- get_intelx_breaches(), Issue 641 ---
# Get IntelX breaches, input
class CredBreachIntelXInput(BaseModel):
    source_uid: str

    class Config:
        orm_mode = True


# --- get_intelx_breaches(), Issue 641 ---
# Get IntelX breaches, task resp
class CredBreachIntelXTaskResp(BaseModel):
    task_id: str
    status: str
    result: List[CredBreachIntelX] = None
    error: str = None
