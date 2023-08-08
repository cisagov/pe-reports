"""Pydantic models used by FastAPI."""
# Standard Python Libraries
from datetime import date, datetime

# from pydantic.types import UUID1, UUID
from typing import Any, List
from uuid import UUID

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
    hsts_header: Optional[str] = None
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
    https_leaf_cert_issuer: Optional[str] = None
    https_leaf_cert_subject: Optional[str] = None
    https_root_cert_issuer: Optional[str] = None
    ip: Optional[str] = None  # Not sure if there is a better type for this
    live: bool
    notes: Optional[str] = None
    redirect: bool
    redirect_to: Optional[str] = None
    server_header: Optional[str] = None
    server_version: Optional[str] = None
    strictly_forces_https: bool
    unknown_error: bool
    valid_https: bool
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
