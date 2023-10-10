"""Pydantic models used by FastAPI."""
# Standard Python Libraries

# Standard Python Libraries
from datetime import date, datetime

# from pydantic.types import UUID1, UUID
from typing import Any, List, Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel, EmailStr, Field

# from pydantic.schema import Optional

"""
Developer Note: If there comes an instance as in class Cidrs where there are
foreign keys. The data type will not be what is stated in the database. What is
happening is the data base is making a query back to the foreign key table and
returning it as the column in its entirety i.e. select * from <table>, so it
will error and not be able to report on its data type. In these scenario's use
the data type "Any" to see what the return is.
"""


class OrgType(BaseModel):
    """OrgType schema."""

    org_type_uid: UUID

    class Config:
        """Config Class for OrgType."""

        orm_mode = True


class OrganizationBase(BaseModel):
    """OrganizationBase schema schema class."""

    organizations_uid: UUID
    name: str
    cyhy_db_name: Optional[str] = None
    org_type_uid: Any
    report_on: bool
    password: Optional[str]
    date_first_reported: Optional[datetime]
    parent_org_uid: Any
    premium_report: Optional[bool] = None
    agency_type: Optional[str] = None
    demo: bool = False

    class Config:
        """Organization base schema schema config."""

        orm_mode = True
        validate_assignment = True


class Organization(OrganizationBase):
    """Organization schema schema class."""

    pass

    class Config:
        """Organization schema schema config."""

        orm_mode = True


class SubDomainBase(BaseModel):
    """SubDomainBase schema schema."""

    sub_domain_uid: UUID
    sub_domain: str
    root_domain_uid: Optional[Any]
    data_source_uid: Optional[Any]
    dns_record_uid: Optional[Any] = None
    status: bool = False

    class Config:
        """SubDomainBase schema schema config."""

        orm_mode = True
        validate_assignment = True


class PshttDomainToRun(BaseModel):
    """PshttDomainsToRun schema class."""

    sub_domain_uid: str
    sub_domain: str
    organizations_uid: str
    name: str

    class Config:
        """PshttDomainsToRun config."""

        orm_mode = True
        validate_assignment = True


class PshttDomainToRunTaskResp(BaseModel):
    """PshttDomainsToRunTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[PshttDomainToRun]] = None
    error: Optional[str] = None


class PshttDataBase(BaseModel):
    """PshttDataBase schema class."""

    pshtt_results_uid: UUID
    organizations_uid: Optional[Any]
    sub_domain_uid: Optional[Any]
    data_source_uid: Optional[Any]
    sub_domain: str
    date_scanned: str  # date
    base_domain: str
    base_domain_hsts_preloaded: bool
    canonical_url: str
    defaults_to_https: bool
    domain: str
    domain_enforces_https: bool
    domain_supports_https: bool
    domain_uses_strong_hsts: Optional[bool] = None
    downgrades_https: bool
    htss: bool
    hsts_entire_domain: Optional[bool] = None
    hsts_header: str
    hsts_max_age: Optional[float] = None
    hsts_preload_pending: bool
    hsts_preload_ready: bool
    hsts_preloaded: bool
    https_bad_chain: bool
    https_bad_hostname: bool
    https_cert_chain_length = int
    https_client_auth_required: bool
    https_custom_truststore_trusted: bool
    https_expired_cert: bool
    https_full_connection: bool
    https_live: bool
    https_probably_missing_intermediate_cert: bool
    https_publicly_trusted: bool
    https_self_signed_cert: bool
    https_leaf_cert_expiration_date: Optional[date] = None
    https_leaf_cert_issuer: str
    https_leaf_cert_subject: str
    https_root_cert_issuer: str
    ip: str  # Not sure if there is a better type for this
    live: bool
    notes: str
    redirect: bool
    redirect_to: str
    server_header: str
    server_version: str
    strictly_forces_https: bool
    unknown_error: bool
    valid_https: bool
    ep_http_headers: str  # This field type is a guess.
    ep_http_server_header: str
    ep_http_server_version: str
    ep_https_headers: str  # This field type is a guess.
    ep_https_hsts_header: str
    ep_https_server_header: str
    ep_https_server_version: str
    ep_httpswww_headers: str  # This field type is a guess.
    ep_httpswww_hsts_header: str
    ep_httpswww_server_header: str
    ep_httpswww_server_version: str
    ep_httpwww_headers: str  # This field type is a guess.
    ep_httpwww_server_header: str
    ep_httpwww_server_version: str


class PshttInsert(BaseModel):
    """PshttInsert schema class."""

    organizations_uid: Optional[Any]
    sub_domain_uid: Optional[Any]
    sub_domain: str
    date_scanned: str  # date
    base_domain: Optional[str] = None
    base_domain_hsts_preloaded: Optional[bool] = None
    canonical_url: Optional[str] = None
    defaults_to_https: Optional[bool] = None
    domain: Optional[str] = None
    domain_enforces_https: Optional[bool] = None
    domain_supports_https: Optional[bool] = None
    domain_uses_strong_hsts: Optional[bool] = None
    downgrades_https: Optional[bool] = None
    htss: Optional[bool] = None
    hsts_entire_domain: Optional[bool] = None
    hsts_header: Optional[str] = None
    hsts_max_age: Optional[float] = None
    hsts_preload_pending: Optional[bool] = None
    hsts_preload_ready: Optional[bool] = None
    hsts_preloaded: Optional[bool] = None
    https_bad_chain: Optional[bool] = None
    https_bad_hostname: Optional[bool] = None
    https_cert_chain_length: Optional[int] = None
    https_client_auth_required: Optional[bool] = None
    https_custom_truststore_trusted: Optional[bool] = None
    https_expired_cert: Optional[bool] = None
    https_full_connection: Optional[bool] = None
    https_live: Optional[bool] = None
    https_probably_missing_intermediate_cert: Optional[bool] = None
    https_publicly_trusted: Optional[bool] = None
    https_self_signed_cert: Optional[bool] = None
    https_leaf_cert_expiration_date: Optional[datetime] = None
    https_leaf_cert_issuer: Optional[str] = None
    https_leaf_cert_subject: Optional[str] = None
    https_root_cert_issuer: Optional[str] = None
    ip: Optional[str] = None  # Not sure if there is a better type for this
    live: Optional[bool] = None
    notes: Optional[str] = None
    redirect: Optional[bool] = None
    redirect_to: Optional[str] = None
    server_header: Optional[str] = None
    server_version: Optional[str] = None
    strictly_forces_https: Optional[bool] = None
    unknown_error: Optional[bool] = None
    valid_https: Optional[bool] = None
    ep_http_headers: Optional[str] = None  # This field type is a guess.
    ep_http_server_header: Optional[str] = None
    ep_http_server_version: Optional[str] = None
    ep_https_headers: Optional[str] = None  # This field type is a guess.
    ep_https_hsts_header: Optional[str] = None
    ep_https_server_header: Optional[str] = None
    ep_https_server_version: Optional[str] = None
    ep_httpswww_headers: Optional[str] = None  # This field type is a guess.
    ep_httpswww_hsts_header: Optional[str] = None
    ep_httpswww_server_header: Optional[str] = None
    ep_httpswww_server_version: Optional[str] = None
    ep_httpwww_headers: Optional[str] = None  # This field type is a guess.
    ep_httpwww_server_header: Optional[str] = None
    ep_httpwww_server_version: Optional[str] = None


class VwBreachcomp(BaseModel):
    """VwBreachcomp schema class."""

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
    """VwBreachDetails schema class."""

    organizations_uid: str
    breach_name: str
    mod_date: str
    description: str
    breach_date: str
    password_included: str
    number_of_creds: str


class VwBreachcompCredsbydate(BaseModel):
    """VwBreachcompCredsbydate schema class."""

    organizations_uid: str
    mod_date: str
    no_password: str
    password_included: str


class VwOrgsAttacksurface(BaseModel):
    """VwOrgsAttacksurface schema class."""

    organizations_uid: UUID
    cyhy_db_name: str
    num_ports: str
    num_root_domain: str
    num_sub_domain: str
    num_ips: str

    class Config:
        """VwOrgsAttacksurface schema config class."""

        orm_mode = True


class VwOrgsAttacksurfaceInput(BaseModel):
    """VwOrgsAttacksurfaceInput schema class."""

    organizations_uid: UUID

    class Config:
        """VwOrgsAttacksurfaceInput schema config class."""

        orm_mode = True


class MatVwOrgsAllIps(BaseModel):
    """MatVwOrgsAllIps schema class."""

    organizations_uid: Any
    cyhy_db_name: str
    ip_addresses: List[Optional[str]] = []

    class Config:
        """MatVwOrgsAllIps schema config class."""

        orm_mode = True


class TaskResponse(BaseModel):
    """TaskResponse schema class."""

    task_id: str
    status: str
    result: Optional[List[MatVwOrgsAllIps]] = None
    error: Optional[str] = None


class veMatVwOrgsAllIps(BaseModel):
    """veMatVwOrgsAllIps schema class."""

    cyhy_db_name: Optional[str]

    class Config:
        """veMatVwOrgsAllIps schema config class."""

        orm_mode = True


class veTaskResponse(BaseModel):
    """veTaskResponse schema class."""

    task_id: str
    status: str
    result: Optional[List[veMatVwOrgsAllIps]] = None
    error: Optional[str] = None


class WASDataBase(BaseModel):
    """WASDataBase schema class."""

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
        """WASDataBase schema config class."""

        orm_mode = True
        validate_assignment = True


class WeeklyStatuses(BaseModel):
    """WeeklyStatuses schema class."""

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
        """WeeklyStatuses schema config class."""

        orm_mode = True
        validate_assignment = True


class UserStatuses(BaseModel):
    """UserStatuses schema class."""

    user_fname: str

    class Config:
        """UserStatuses schema config class."""

        orm_mode = True
        validate_assignment = True


class CyhyPortScans(BaseModel):
    """CyhyPortScans schema class."""

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
        """CyhyPortScans schema config class."""

        orm_mode = True
        validate_assignment = True


class CyhyDbAssets(BaseModel):
    """CyhyDbAssets schema class."""

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
        """CyhyDbAssets schema config class."""

        orm_mode = True


class CyhyDbAssetsInput(BaseModel):
    """CyhyDbAssetsInput schema class."""

    org_id: str

    class Config:
        """CyhyDbAssetsInput schema config class."""

        orm_mode = True


class Cidrs(BaseModel):
    """Cidrs schema class."""

    cidr_uid: UUID
    network: Any
    organizations_uid: Any
    data_source_uid: Any
    insert_alert: Optional[str] = None

    class Config:
        """Cidrs schema config class."""

        orm_mode = True


class VwCidrs(BaseModel):
    """VwCidrs schema class."""

    cidr_uid: str
    network: str
    organizations_uid: str
    data_source_uid: str
    insert_alert: Optional[str] = None


class DataSource(BaseModel):
    """DataSource schema class."""

    data_source_uid: str
    name: str
    description: str
    last_run: str

    class Config:
        """DataSource schema config class."""

        orm_mode = True


class UserAPIBase(BaseModel):
    """UserAPIBase schema class."""

    # user_id: int
    refresh_token: str


class UserAPI(UserAPIBase):
    """UserAPI schema class."""

    pass

    class Config:
        """UserAPI schema config class."""

        orm_mode = True


class TokenSchema(BaseModel):
    """TokenSchema schema class."""

    access_token: str
    refresh_token: str


class TokenPayload(BaseModel):
    """TokenPayload schema class."""

    sub: Optional[str] = None
    exp: Optional[int] = None


class UserAuth(BaseModel):
    """UserAuth schema class."""

    # id: UUID = Field(..., description='user UUID')
    # email: EmailStr = Field(..., description="user email")
    username: str = Field(..., description="user name")
    # password: str = Field(..., min_length=5, max_length=24,
    #                       description="user password")


class UserOut(BaseModel):
    """UserOut schema class."""

    id: UUID
    email: str


class SystemUser(UserOut):
    """SystemUser schema class."""

    password: str


# Shared properties
class UserBase(BaseModel):
    """UserBase schema class."""

    email: Optional[EmailStr] = None
    is_active: Optional[bool] = True
    is_superuser: bool = False
    full_name: Optional[str] = None


# Properties to receive via API on creation
class UserCreate(UserBase):
    """UserCreate schema class."""

    email: EmailStr
    password: str


# Properties to receive via API on update
class UserUpdate(UserBase):
    """UserUpdate schema class."""

    password: Optional[str] = None


class UserInDBBase(UserBase):
    """UserInDBBase schema class."""

    id: Optional[int] = None

    class Config:
        """UserInDBBase schema config class."""

        orm_mode = True


# Additional properties to return via API
class User(UserInDBBase):
    """User schema class."""

    pass


# Additional properties stored in DB
class UserInDB(UserInDBBase):
    """UserInDB schema class."""

    hashed_password: str


# ---------- D-Score View Schemas ----------
# vw_dscore_vs_cert schema:
class VwDscoreVSCert(BaseModel):
    """VwDscoreVSCert schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_cert: Optional[int] = None
    num_monitor_cert: Optional[int] = None

    class Config:
        """VwDscoreVSCert schema config class."""

        orm_mode = True


# vw_dscore_vs_cert input schema:
class VwDscoreVSCertInput(BaseModel):
    """VwDscoreVSCertInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscoreVSCertInput schema config class."""

        orm_mode = True


# vw_dscore_vs_cert task response schema:
class VwDscoreVSCertTaskResp(BaseModel):
    """VwDscoreVSCertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscoreVSCert]] = None
    error: Optional[str] = None


# vw_dscore_vs_mail schema:
class VwDscoreVSMail(BaseModel):
    """VwDscoreVSMail schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_valid_dmarc: Optional[int] = None
    num_valid_spf: Optional[int] = None
    num_valid_dmarc_or_spf: Optional[int] = None
    total_mail_domains: Optional[int] = None

    class Config:
        """VwDscoreVSMail schema config class."""

        orm_mode = True


# vw_dscore_vs_mail input schema:
class VwDscoreVSMailInput(BaseModel):
    """VwDscoreVSMailInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscoreVSMailInput schema config class."""

        orm_mode = True


# vw_dscore_vs_mail task response schema:
class VwDscoreVSMailTaskResp(BaseModel):
    """VwDscoreVSMailTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscoreVSMail]] = None
    error: Optional[str] = None


# vw_dscore_pe_ip schema:
class VwDscorePEIp(BaseModel):
    """VwDscorePEIp schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_ip: Optional[int] = None
    num_monitor_ip: Optional[int] = None

    class Config:
        """VwDscorePEIp schema config class."""

        orm_mode = True


# vw_dscore_pe_ip input schema:
class VwDscorePEIpInput(BaseModel):
    """VwDscorePEIpInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscorePEIpInput schema config class."""

        orm_mode = True


# vw_dscore_pe_ip task response schema:
class VwDscorePEIpTaskResp(BaseModel):
    """VwDscorePEIpTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscorePEIp]] = None
    error: Optional[str] = None


# vw_dscore_pe_domain schema:
class VwDscorePEDomain(BaseModel):
    """VwDscorePEDomain schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_domain: Optional[int] = None
    num_monitor_domain: Optional[int] = None

    class Config:
        """VwDscorePEDomain schema config class."""

        orm_mode = True


# vw_dscore_pe_domain input schema:
class VwDscorePEDomainInput(BaseModel):
    """VwDscorePEDomainInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscorePEDomainInput schema config class."""

        orm_mode = True


# vw_dscore_pe_domain task response schema:
class VwDscorePEDomainTaskResp(BaseModel):
    """VwDscorePEDomainTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscorePEDomain]] = None
    error: Optional[str] = None


# vw_dscore_was_webapp schema:
class VwDscoreWASWebapp(BaseModel):
    """VwDscoreWASWebapp schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_webapp: Optional[int] = None
    num_monitor_webapp: Optional[int] = None

    class Config:
        """VwDscoreWASWebapp schema config class."""

        orm_mode = True


# vw_dscore_was_webapp input schema:
class VwDscoreWASWebappInput(BaseModel):
    """VwDscoreWASWebappInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscoreWASWebappInput schema config class."""

        orm_mode = True


# vw_dscore_was_webapp task response schema:
class VwDscoreWASWebappTaskResp(BaseModel):
    """VwDscoreWASWebappTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscoreWASWebapp]] = None
    error: Optional[str] = None


# FCEB status query schema (no view):
class FCEBStatus(BaseModel):
    """FCEBStatus schema class."""

    organizations_uid: str
    fceb: Optional[bool] = None

    class Config:
        """FCEBStatus schema config class."""

        orm_mode = True


# FCEB status query input schema (no view):
class FCEBStatusInput(BaseModel):
    """FCEBStatusInput schema class."""

    specified_orgs: List[str]

    class Config:
        """FCEBStatusInput schema config class."""

        orm_mode = True


# FCEB status query task response schema (no view):
class FCEBStatusTaskResp(BaseModel):
    """FCEBStatusTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[FCEBStatus]] = None
    error: Optional[str] = None


# ---------- I-Score View Schemas ----------
# vw_iscore_vs_vuln schema:
class VwIscoreVSVuln(BaseModel):
    """VwIscoreVSVuln schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None

    class Config:
        """VwIscoreVSVuln schema config class."""

        orm_mode = True


# vw_iscore_vs_vuln input schema:
class VwIscoreVSVulnInput(BaseModel):
    """VwIscoreVSVulnInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwIscoreVSVulnInput schema config class."""

        orm_mode = True


# vw_iscore_vs_vuln task response schema:
class VwIscoreVSVulnTaskResp(BaseModel):
    """VwIscoreVSVulnTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreVSVuln]] = None
    error: Optional[str] = None


# vw_iscore_vs_vuln_prev schema:
class VwIscoreVSVulnPrev(BaseModel):
    """VwIscoreVSVulnPrev schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None
    time_closed: Optional[str] = None

    class Config:
        """VwIscoreVSVulnPrev schema config class."""

        orm_mode = True


# vw_iscore_vs_vuln_prev input schema:
class VwIscoreVSVulnPrevInput(BaseModel):
    """VwIscoreVSVulnPrevInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscoreVSVulnPrevInput schema config class."""

        orm_mode = True


# vw_iscore_vs_vuln_prev task response schema:
class VwIscoreVSVulnPrevTaskResp(BaseModel):
    """VwIscoreVSVulnPrevTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreVSVulnPrev]] = None
    error: Optional[str] = None


# vw_iscore_pe_vuln schema:
class VwIscorePEVuln(BaseModel):
    """VwIscorePEVuln schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None

    class Config:
        """VwIscorePEVuln schema config class."""

        orm_mode = True


# vw_iscore_pe_vuln input schema:
class VwIscorePEVulnInput(BaseModel):
    """VwIscorePEVulnInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscorePEVulnInput schema config class."""

        orm_mode = True


# vw_iscore_pe_vuln task response schema:
class VwIscorePEVulnTaskResp(BaseModel):
    """VwIscorePEVulnTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePEVuln]] = None
    error: Optional[str] = None


# vw_iscore_pe_cred schema:
class VwIscorePECred(BaseModel):
    """VwIscorePECred schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    password_creds: Optional[int] = None
    total_creds: Optional[int] = None

    class Config:
        """VwIscorePECred schema config class."""

        orm_mode = True


# vw_iscore_pe_cred input schema:
class VwIscorePECredInput(BaseModel):
    """VwIscorePECredInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscorePECredInput schema config class."""

        orm_mode = True


# vw_iscore_pe_cred task response schema:
class VwIscorePECredTaskResp(BaseModel):
    """VwIscorePECredTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePECred]] = None
    error: Optional[str] = None


# vw_iscore_pe_breach schema:
class VwIscorePEBreach(BaseModel):
    """VwIscorePEBreach schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    breach_count: Optional[int] = None

    class Config:
        """VwIscorePEBreach schema config class."""

        orm_mode = True


# vw_iscore_pe_breach input schema:
class VwIscorePEBreachInput(BaseModel):
    """VwIscorePEBreachInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscorePEBreachInput schema config class."""

        orm_mode = True


# vw_iscore_pe_breach task response schema:
class VwIscorePEBreachTaskResp(BaseModel):
    """VwIscorePEBreachTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePEBreach]] = None
    error: Optional[str] = None


# vw_iscore_pe_darkweb schema:
class VwIscorePEDarkweb(BaseModel):
    """VwIscorePEDarkweb schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    alert_type: Optional[str] = None
    date: Optional[str] = None
    Count: Optional[int] = None

    class Config:
        """VwIscorePEDarkweb schema config class."""

        orm_mode = True


# vw_iscore_pe_darkweb input schema:
class VwIscorePEDarkwebInput(BaseModel):
    """VwIscorePEDarkwebInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str
    # Don't forget 0001-01-01 dates

    class Config:
        """VwIscorePEDarkwebInput schema config class."""

        orm_mode = True


# vw_iscore_pe_darkweb task response schema:
class VwIscorePEDarkwebTaskResp(BaseModel):
    """VwIscorePEDarkwebTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePEDarkweb]] = None
    error: Optional[str] = None


# vw_iscore_pe_protocol schema:
class VwIscorePEProtocol(BaseModel):
    """VwIscorePEProtocol schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    port: Optional[str] = None
    ip: Optional[str] = None
    protocol: Optional[str] = None
    protocol_type: Optional[str] = None
    date: Optional[str] = None

    class Config:
        """VwIscorePEProtocol schema config class."""

        orm_mode = True


# vw_iscore_pe_protocol input schema:
class VwIscorePEProtocolInput(BaseModel):
    """VwIscorePEProtocolInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscorePEProtocolInput schema config class."""

        orm_mode = True


# vw_iscore_pe_protocol task response schema:
class VwIscorePEProtocolTaskResp(BaseModel):
    """VwIscorePEProtocolTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePEProtocol]] = None
    error: Optional[str] = None


# vw_iscore_was_vuln schema:
class VwIscoreWASVuln(BaseModel):
    """VwIscoreWASVuln schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None
    owasp_category: Optional[str] = None

    class Config:
        """VwIscoreWASVuln schema config class."""

        orm_mode = True


# vw_iscore_was_vuln input schema:
class VwIscoreWASVulnInput(BaseModel):
    """VwIscoreWASVulnInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscoreWASVulnInput schema config class."""

        orm_mode = True


# vw_iscore_was_vuln task response schema:
class VwIscoreWASVulnTaskResp(BaseModel):
    """VwIscoreWASVulnTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreWASVuln]] = None
    error: Optional[str] = None


# vw_iscore_was_vuln_prev schema:
class VwIscoreWASVulnPrev(BaseModel):
    """VwIscoreWASVulnPrev schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    was_total_vulns_prev: Optional[int] = None
    date: Optional[str] = None

    class Config:
        """VwIscoreWASVulnPrev schema config class."""

        orm_mode = True


# vw_iscore_was_vuln_prev input schema:
class VwIscoreWASVulnPrevInput(BaseModel):
    """VwIscoreWASVulnPrevInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscoreWASVulnPrevInput schema config class."""

        orm_mode = True


# vw_iscore_was_vuln_prev task response schema:
class VwIscoreWASVulnPrevTaskResp(BaseModel):
    """VwIscoreWASVulnPrevTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreWASVulnPrev]] = None
    error: Optional[str] = None


# KEV list query schema (no view):
# KEV list query does not use any input parameters
class KEVList(BaseModel):
    """KEVList schema class."""

    kev: str

    class Config:
        """KEVList schema config class."""

        orm_mode = True


# KEV list query task response schema (no view):
class KEVListTaskResp(BaseModel):
    """KEVListTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[KEVList]] = None
    error: Optional[str] = None


# ---------- Misc. Score Schemas ----------
# vw_iscore_orgs_ip_counts schema:
# vw_iscore_orgs_ip_counts does not use any input parameters
class VwIscoreOrgsIpCounts(BaseModel):
    """VwIscoreOrgsIpCounts schema class."""

    organizations_uid: str
    cyhy_db_name: str

    class Config:
        """VwIscoreOrgsIpCounts schema config class."""

        orm_mode = True


# vw_iscore_orgs_ip_counts task response schema:
class VwIscoreOrgsIpCountsTaskResp(BaseModel):
    """VwIscoreOrgsIpCountsTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreOrgsIpCounts]] = None
    error: Optional[str] = None


# --- get_new_orgs(), Issue 605, 606, 607 ---
# Generalized schema for returning all organizations table fields
class OrgsTable(BaseModel):
    """OrgsTable schema class."""

    organizations_uid: str
    name: Optional[str] = None
    cyhy_db_name: Optional[str] = None
    org_type_uid_id: Optional[str] = None
    report_on: Optional[bool] = None
    password: Optional[str] = None
    date_first_reported: Optional[str] = None
    parent_org_uid_id: Optional[str] = None
    premium_report: Optional[bool] = None
    agency_type: Optional[str] = None
    demo: Optional[bool] = None
    scorecard: Optional[bool] = None
    fceb: Optional[bool] = None
    receives_cyhy_report: Optional[bool] = None
    receives_bod_report: Optional[bool] = None
    receives_cybex_report: Optional[bool] = None
    run_scans: Optional[bool] = None
    is_parent: Optional[bool] = None
    ignore_roll_up: Optional[bool] = None
    retired: Optional[bool] = None
    cyhy_period_start: Optional[str] = None
    fceb_child: Optional[bool] = None
    election: Optional[bool] = None
    scorecard_child: Optional[bool] = None

    class Config:
        """OrgsTable schema config class."""

        orm_mode = True


# --- set_org_to_report_on(), Issue 606, 607 ---
# Set specified organization to report_on
class OrgsSetReportOnInput(BaseModel):
    """OrgsSetReportOnInput schema class."""

    cyhy_db_name: str
    premium: bool

    class Config:
        """OrgsSetReportOnInput schema config class."""


# --- query_cyhy_assets(), Issue 608 ---
# Get CyHy database assets for an org (cyhy_db_name)
class CyhyDbAssetsByOrg(BaseModel):
    """CyhyDbAssetsByOrg schema class."""

    field_id: Optional[str] = None
    org_id: Optional[str] = None
    org_name: Optional[str] = None
    contact: Optional[str] = None
    network: Optional[str] = None
    type: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    currently_in_cyhy: Optional[bool] = None

    class Config:
        """CyhyDbAssetsByOrg schema config class."""

        orm_mode = True


# --- query_subs(), Issue 633, 560 ---
# Get entire sub_domains table, single output
class SubDomainTable(BaseModel):
    """SubDomainTable schema class."""

    sub_domain_uid: Optional[str] = None
    sub_domain: Optional[str] = None
    root_domain_uid_id: Optional[str] = None
    data_source_uid_id: Optional[str] = None
    dns_record_uid_id: Optional[str] = None
    status: Optional[bool] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    current: Optional[bool] = None
    identified: Optional[bool] = None

    class Config:
        """SubDomainTable schema config class."""

        orm_mode = True
        validate_assignment = True


# --- query_all_subs(), Issue 633 ---
# Get entire sub_domains table, paged input
class SubDomainPagedInput(BaseModel):
    """SubDomainPagedInput schema class."""

    org_uid: str
    page: int
    per_page: int

    class Config:
        """SubDomainPagedInput schema config class."""

        orm_mode = True


# --- query_subs(), Issue 633, 560 ---
# Get entire sub_domains table, paged output
class SubDomainPagedResult(BaseModel):
    """SubDomainPagedResult schema class."""

    total_pages: int
    current_page: int
    data: List[SubDomainTable]


# --- query_all_subs(), Issue 633, 560 ---
# Get entire sub_domains table, paged task resp
class SubDomainPagedTaskResp(BaseModel):
    """SubDomainPagedTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[SubDomainPagedResult] = None
    error: Optional[str] = None


# --- insert_sixgill_mentions(), Issue 654 ---
# Insert multiple records into the mentions table
class MentionsInsert(BaseModel):
    """MentionsInsert schema class."""

    organizations_uid: str
    data_source_uid: str
    category: str
    collection_date: str
    content: str
    creator: str
    date: str
    sixgill_mention_id: str
    lang: str
    post_id: str
    rep_grade: str
    site: str
    site_grade: str
    sub_category: str
    title: str
    type: str
    url: str
    comments_count: str
    tags: str

    class Config:
        """MentionsInsert schema config class."""

        orm_mode = True


# --- insert_sixgill_mentions(), Issue 654 ---
# Insert multiple records into the mentions table, input
class MentionsInsertInput(BaseModel):
    """MentionsInsertInput schema class."""

    insert_data: List[MentionsInsert]

    class Config:
        """MentionsInsertInput schema config class."""

        orm_mode = True


# --- insert_sixgill_breaches(), Issue 655 ---
# Insert multiple records into the credential_breaches table
class CredBreachesInsert(BaseModel):
    """CredBreachesInsert schema class."""

    breach_name: str
    description: str
    exposed_cred_count: int
    breach_date: str
    modified_date: str
    password_included: bool
    data_source_uid: str

    class Config:
        """CredBreachesInsert schema config class."""

        orm_mode = True


# --- insert_sixgill_breaches(), Issue 655 ---
# Insert multiple records into the credential_breaches table, input
class CredBreachesInsertInput(BaseModel):
    """CredBreachesInsertInput schema class."""

    insert_data: List[CredBreachesInsert]

    class Config:
        """CredBreachesInsertInput schema config class."""

        orm_mode = True


# --- insert_sixgill_topCVEs(), Issue 657 ---
# Insert multiple records into the top_cves table
class TopCVEsInsert(BaseModel):
    """TopCVEsInsert schema class."""

    cve_id: str
    dynamic_rating: Optional[str] = None
    nvd_base_score: Optional[str] = None
    date: str
    summary: Optional[str] = None
    data_source_uid: Optional[str] = None

    class Config:
        """TopCVEsInsert schema config class."""

        orm_mode = True


# --- insert_sixgill_topCVEs(), Issue 657 ---
# Insert multiple records into the top_cves table, input
class TopCVEsInsertInput(BaseModel):
    """TopCVEsInsertInput schema class."""

    insert_data: List[TopCVEsInsert]

    class Config:
        """TopCVEsInsertInput schema config class."""

        orm_mode = True


# --- addRootdomain(), Issue 661 ---
# Insert single root domain into root_domains table, input
class RootDomainsSingleInsertInput(BaseModel):
    """RootDomainsSingleInsertInput schema class."""

    root_domain: str
    pe_org_uid: str
    source_uid: str
    org_name: str

    class Config:
        """RootDomainsSingleInsertInput schema config class."""

        orm_mode = True


# --- addSubdomain(), Issue 662 ---
# Insert single sub domain into sub_domains table, input
class SubDomainsSingleInsertInput(BaseModel):
    """SubDomainsSingleInsertInput schema class."""

    domain: str
    pe_org_uid: str
    root: Optional[bool] = None

    class Config:
        """SubDomainsSingleInsertInput schema config class."""

        orm_mode = True


# ---------- Generalized Schemas ----------
# Generalized 1 org_uid input schema
class GenInputOrgUIDSingle(BaseModel):
    """GenInputOrgUIDSingle schema class."""

    org_uid: str

    class Config:
        """GenInputOrgUIDSingle schema config class."""

        orm_mode = True


# Generalized 1 org cyhy_db_name input schema
class GenInputOrgCyhyNameSingle(BaseModel):
    """GenInputOrgCyhyNameSingle schema class."""

    org_cyhy_name: str

    class Config:
        """GenInputOrgCyhyNameSingle schema config class."""

        orm_mode = True


# Generalized 1 org_uid, 1 date input schema
class GenInputOrgUIDDateSingle(BaseModel):
    """GenInputOrgUIDDateSingle schema class."""

    org_uid: str
    date: str

    class Config:
        """GenInputOrgUIDDateSingle schema config class."""

        orm_mode = True


# Generalized list of org_uids input schema
class GenInputOrgUIDList(BaseModel):
    "GenInputOrgUIDList schema class."
    org_uid_list: List[str]

    class Config:
        """GenInputOrgUIDList"""

        orm_mode = True


class GenInputOrgUIDDateRange(BaseModel):
    """GenInputOrgUIDDateRange schema class."""

    org_uid: str
    start_date: str
    end_date: str

    class Config:
        """GenInputOrgUIDDateRange schema config class."""


# Generalized start/end date input schema
class GenInputDateRange(BaseModel):
    """GenInputDateRange schema class."""

    start_date: str
    end_date: str

    class Config:
        """GenInputDateRange schema config class."""

        orm_mode = True


# Generalized list of org_uids and start/end date input schema
class GenInputOrgUIDListDateRange(BaseModel):
    """GenInputOrgUIDListDateRange schema class."""

    org_uid_list: List[str]
    start_date: str
    end_date: str

    class Config:
        """GenInputOrgUIDListDateRange schema config class."""

        orm_mode = True
