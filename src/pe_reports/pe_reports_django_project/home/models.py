# Create your models here.
# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
# Standard Python Libraries
import uuid

# Third-Party Libraries
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models


class Users(models.Model):
    id = models.UUIDField(primary_key=True)
    email = models.CharField(unique=True, max_length=64, blank=True, null=True)
    username = models.CharField(unique=True, max_length=64, blank=True, null=True)
    admin = models.IntegerField(blank=True, null=True)
    role = models.IntegerField(blank=True, null=True)
    password_hash = models.CharField(max_length=128, blank=True, null=True)
    api_key = models.CharField(unique=True, max_length=128, blank=True, null=True)

    class Meta:
        managed = False
        db_table = "Users"


class AlembicVersion(models.Model):
    version_num = models.CharField(primary_key=True, max_length=32)

    class Meta:
        managed = False
        db_table = "alembic_version"


class Alerts(models.Model):
    alerts_uid = models.UUIDField(primary_key=True)
    alert_name = models.TextField(blank=True, null=True)
    content = models.TextField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    sixgill_id = models.TextField(unique=True, blank=True, null=True)
    read = models.TextField(blank=True, null=True)
    severity = models.TextField(blank=True, null=True)
    site = models.TextField(blank=True, null=True)
    threat_level = models.TextField(blank=True, null=True)
    threats = models.TextField(blank=True, null=True)
    title = models.TextField(blank=True, null=True)
    user_id = models.TextField(blank=True, null=True)
    category = models.TextField(blank=True, null=True)
    lang = models.TextField(blank=True, null=True)
    organizations_uid = models.ForeignKey(
        "Organizations", on_delete=models.CASCADE, db_column="organizations_uid"
    )
    data_source_uid = models.ForeignKey(
        "DataSource", on_delete=models.CASCADE, db_column="data_source_uid"
    )
    content_snip = models.TextField(blank=True, null=True)
    asset_mentioned = models.TextField(blank=True, null=True)
    asset_type = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "alerts"


class Alias(models.Model):
    alias_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey(
        "Organizations", on_delete=models.CASCADE, db_column="organizations_uid"
    )
    alias = models.TextField(unique=True)

    class Meta:
        managed = False
        db_table = "alias"


class AssetHeaders(models.Model):
    field_id = models.UUIDField(
        db_column="_id", primary_key=True
    )  # Field renamed because it started with '_'.
    organizations_uid = models.UUIDField()
    sub_url = models.TextField()
    tech_detected = models.TextField()  # This field type is a guess.
    interesting_header = models.TextField()  # This field type is a guess.
    ssl2 = models.TextField(blank=True, null=True)  # This field type is a guess.
    tls1 = models.TextField(blank=True, null=True)  # This field type is a guess.
    certificate = models.TextField(blank=True, null=True)  # This field type is a guess.
    scanned = models.BooleanField(blank=True, null=True)
    ssl_scanned = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "asset_headers"
        unique_together = (("organizations_uid", "sub_url"),)


class AuthGroup(models.Model):
    name = models.CharField(unique=True, max_length=150)

    class Meta:
        managed = False
        db_table = "auth_group"


class AuthGroupPermissions(models.Model):
    id = models.BigAutoField(primary_key=True)
    group = models.ForeignKey(AuthGroup, on_delete=models.CASCADE)
    permission = models.ForeignKey("AuthPermission", on_delete=models.CASCADE)

    class Meta:
        managed = False
        db_table = "auth_group_permissions"
        unique_together = (("group", "permission"),)


class AuthPermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey("DjangoContentType", on_delete=models.CASCADE)
    codename = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = "auth_permission"
        unique_together = (("content_type", "codename"),)


class AuthUser(models.Model):
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(blank=True, null=True)
    is_superuser = models.BooleanField()
    username = models.CharField(unique=True, max_length=150)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    email = models.CharField(max_length=254)
    is_staff = models.BooleanField()
    is_active = models.BooleanField()
    date_joined = models.DateTimeField()

    class Meta:
        managed = False
        db_table = "auth_user"


class AuthUserGroups(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(AuthUser, on_delete=models.CASCADE)
    group = models.ForeignKey(AuthGroup, on_delete=models.CASCADE)

    class Meta:
        managed = False
        db_table = "auth_user_groups"
        unique_together = (("user", "group"),)


class AuthUserUserPermissions(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(AuthUser, on_delete=models.CASCADE)
    permission = models.ForeignKey(AuthPermission, on_delete=models.CASCADE)

    class Meta:
        managed = False
        db_table = "auth_user_user_permissions"
        unique_together = (("user", "permission"),)


class Cidrs(models.Model):
    cidr_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    network = models.TextField()  # This field type is a guess.
    organizations_uid = models.ForeignKey(
        "Organizations",
        on_delete=models.CASCADE,
        db_column="organizations_uid",
        blank=True,
        null=True,
    )
    data_source_uid = models.ForeignKey(
        "DataSource",
        on_delete=models.CASCADE,
        db_column="data_source_uid",
        blank=True,
        null=True,
    )
    insert_alert = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "cidrs"
        unique_together = (("organizations_uid", "network"),)


class CredentialBreaches(models.Model):
    credential_breaches_uid = models.UUIDField(primary_key=True)
    breach_name = models.TextField(unique=True)
    description = models.TextField(blank=True, null=True)
    exposed_cred_count = models.BigIntegerField(blank=True, null=True)
    breach_date = models.DateField(blank=True, null=True)
    added_date = models.DateTimeField(blank=True, null=True)
    modified_date = models.DateTimeField(blank=True, null=True)
    data_classes = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    password_included = models.BooleanField(blank=True, null=True)
    is_verified = models.BooleanField(blank=True, null=True)
    is_fabricated = models.BooleanField(blank=True, null=True)
    is_sensitive = models.BooleanField(blank=True, null=True)
    is_retired = models.BooleanField(blank=True, null=True)
    is_spam_list = models.BooleanField(blank=True, null=True)
    data_source_uid = models.ForeignKey(
        "DataSource", on_delete=models.CASCADE, db_column="data_source_uid"
    )

    class Meta:
        managed = False
        db_table = "credential_breaches"


class CredentialExposures(models.Model):
    credential_exposures_uid = models.UUIDField(primary_key=True)
    email = models.TextField()
    organizations_uid = models.ForeignKey(
        "Organizations", on_delete=models.CASCADE, db_column="organizations_uid"
    )
    root_domain = models.TextField(blank=True, null=True)
    sub_domain = models.TextField(blank=True, null=True)
    breach_name = models.TextField(blank=True, null=True)
    modified_date = models.DateTimeField(blank=True, null=True)
    credential_breaches_uid = models.ForeignKey(
        CredentialBreaches,
        on_delete=models.CASCADE,
        db_column="credential_breaches_uid",
    )
    data_source_uid = models.ForeignKey(
        "DataSource", on_delete=models.CASCADE, db_column="data_source_uid"
    )
    name = models.TextField(blank=True, null=True)
    login_id = models.TextField(blank=True, null=True)
    phone = models.TextField(blank=True, null=True)
    password = models.TextField(blank=True, null=True)
    hash_type = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "credential_exposures"
        unique_together = (("breach_name", "email"),)


class CveInfo(models.Model):
    cve_uuid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    cve_name = models.TextField(unique=True, blank=True, null=True)
    cvss_2_0 = models.DecimalField(
        max_digits=1000, decimal_places=1000, blank=True, null=True
    )
    cvss_2_0_severity = models.TextField(blank=True, null=True)
    cvss_2_0_vector = models.TextField(blank=True, null=True)
    cvss_3_0 = models.DecimalField(
        max_digits=1000, decimal_places=1000, blank=True, null=True
    )
    cvss_3_0_severity = models.TextField(blank=True, null=True)
    cvss_3_0_vector = models.TextField(blank=True, null=True)
    dve_score = models.DecimalField(
        max_digits=1000, decimal_places=1000, blank=True, null=True
    )

    class Meta:
        managed = False
        db_table = "cve_info"


class CyhyContacts(models.Model):
    field_id = models.UUIDField(
        db_column="_id", primary_key=True, default=uuid.uuid1()
    )  # Field renamed because it started with '_'.
    org_id = models.TextField()
    org_name = models.TextField()
    phone = models.TextField(blank=True, null=True)
    contact_type = models.TextField()
    email = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    date_pulled = models.DateField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "cyhy_contacts"
        unique_together = (("org_id", "contact_type", "email", "name"),)


class CyhyDbAssets(models.Model):
    field_id = models.UUIDField(
        db_column="_id", primary_key=True, default=uuid.uuid1()
    )  # Field renamed because it started with '_'.
    org_id = models.TextField(blank=True, null=True)
    org_name = models.TextField(blank=True, null=True)
    contact = models.TextField(blank=True, null=True)
    network = models.GenericIPAddressField(blank=True, null=True)
    type = models.TextField(blank=True, null=True)
    first_seen = models.DateField(blank=True, null=True)
    last_seen = models.DateField(blank=True, null=True)
    currently_in_cyhy = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "cyhy_db_assets"
        unique_together = (("org_id", "network"),)


class CyhyPortScans(models.Model):
    cyhy_port_scans_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey(
        "Organizations", models.DO_NOTHING, db_column="organizations_uid"
    )
    cyhy_id = models.TextField(unique=True, blank=True, null=True)
    cyhy_time = models.DateTimeField(blank=True, null=True)
    service_name = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    product = models.TextField(blank=True, null=True)
    cpe = models.TextField(blank=True, null=True)
    first_seen = models.DateField(blank=True, null=True)
    last_seen = models.DateField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    state = models.TextField(blank=True, null=True)
    agency_type = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "cyhy_port_scans"


class DataapiApiuser(models.Model):
    id = models.BigAutoField(primary_key=True)
    apikey = models.CharField(
        db_column="apiKey", max_length=200, blank=True, null=True
    )  # Field name made lowercase.
    user = models.OneToOneField(AuthUser, on_delete=models.CASCADE)
    refresh_token = models.CharField(max_length=200, blank=True, null=True)

    class Meta:
        managed = False
        db_table = "dataAPI_apiuser"


class DataSource(models.Model):
    data_source_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    name = models.TextField()
    description = models.TextField()
    last_run = models.DateField()

    class Meta:
        managed = False
        db_table = "data_source"


class DjangoAdminLog(models.Model):
    action_time = models.DateTimeField()
    object_id = models.TextField(blank=True, null=True)
    object_repr = models.CharField(max_length=200)
    action_flag = models.SmallIntegerField()
    change_message = models.TextField()
    content_type = models.ForeignKey(
        "DjangoContentType", on_delete=models.CASCADE, blank=True, null=True
    )
    user = models.ForeignKey(AuthUser, on_delete=models.CASCADE)

    class Meta:
        managed = False
        db_table = "django_admin_log"


class DjangoContentType(models.Model):
    app_label = models.CharField(max_length=100)
    model = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = "django_content_type"
        unique_together = (("app_label", "model"),)


class DjangoMigrations(models.Model):
    id = models.BigAutoField(primary_key=True)
    app = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    applied = models.DateTimeField()

    class Meta:
        managed = False
        db_table = "django_migrations"


class DjangoSession(models.Model):
    session_key = models.CharField(primary_key=True, max_length=40)
    session_data = models.TextField()
    expire_date = models.DateTimeField()

    class Meta:
        managed = False
        db_table = "django_session"


class DnsRecords(models.Model):
    dns_record_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    domain_name = models.TextField(blank=True, null=True)
    domain_type = models.TextField(blank=True, null=True)
    created_date = models.DateTimeField(blank=True, null=True)
    updated_date = models.DateTimeField(blank=True, null=True)
    expiration_date = models.DateTimeField(blank=True, null=True)
    name_servers = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    whois_server = models.TextField(blank=True, null=True)
    registrar_name = models.TextField(blank=True, null=True)
    status = models.TextField(blank=True, null=True)
    clean_text = models.TextField(blank=True, null=True)
    raw_text = models.TextField(blank=True, null=True)
    registrant_name = models.TextField(blank=True, null=True)
    registrant_organization = models.TextField(blank=True, null=True)
    registrant_street = models.TextField(blank=True, null=True)
    registrant_city = models.TextField(blank=True, null=True)
    registrant_state = models.TextField(blank=True, null=True)
    registrant_post_code = models.TextField(blank=True, null=True)
    registrant_country = models.TextField(blank=True, null=True)
    registrant_email = models.TextField(blank=True, null=True)
    registrant_phone = models.TextField(blank=True, null=True)
    registrant_phone_ext = models.TextField(blank=True, null=True)
    registrant_fax = models.TextField(blank=True, null=True)
    registrant_fax_ext = models.TextField(blank=True, null=True)
    registrant_raw_text = models.TextField(blank=True, null=True)
    administrative_name = models.TextField(blank=True, null=True)
    administrative_organization = models.TextField(blank=True, null=True)
    administrative_street = models.TextField(blank=True, null=True)
    administrative_city = models.TextField(blank=True, null=True)
    administrative_state = models.TextField(blank=True, null=True)
    administrative_post_code = models.TextField(blank=True, null=True)
    administrative_country = models.TextField(blank=True, null=True)
    administrative_email = models.TextField(blank=True, null=True)
    administrative_phone = models.TextField(blank=True, null=True)
    administrative_phone_ext = models.TextField(blank=True, null=True)
    administrative_fax = models.TextField(blank=True, null=True)
    administrative_fax_ext = models.TextField(blank=True, null=True)
    administrative_raw_text = models.TextField(blank=True, null=True)
    technical_name = models.TextField(blank=True, null=True)
    technical_organization = models.TextField(blank=True, null=True)
    technical_street = models.TextField(blank=True, null=True)
    technical_city = models.TextField(blank=True, null=True)
    technical_state = models.TextField(blank=True, null=True)
    technical_post_code = models.TextField(blank=True, null=True)
    technical_country = models.TextField(blank=True, null=True)
    technical_email = models.TextField(blank=True, null=True)
    technical_phone = models.TextField(blank=True, null=True)
    technical_phone_ext = models.TextField(blank=True, null=True)
    technical_fax = models.TextField(blank=True, null=True)
    technical_fax_ext = models.TextField(blank=True, null=True)
    technical_raw_text = models.TextField(blank=True, null=True)
    billing_name = models.TextField(blank=True, null=True)
    billing_organization = models.TextField(blank=True, null=True)
    billing_street = models.TextField(blank=True, null=True)
    billing_city = models.TextField(blank=True, null=True)
    billing_state = models.TextField(blank=True, null=True)
    billing_post_code = models.TextField(blank=True, null=True)
    billing_country = models.TextField(blank=True, null=True)
    billing_email = models.TextField(blank=True, null=True)
    billing_phone = models.TextField(blank=True, null=True)
    billing_phone_ext = models.TextField(blank=True, null=True)
    billing_fax = models.TextField(blank=True, null=True)
    billing_fax_ext = models.TextField(blank=True, null=True)
    billing_raw_text = models.TextField(blank=True, null=True)
    zone_name = models.TextField(blank=True, null=True)
    zone_organization = models.TextField(blank=True, null=True)
    zone_street = models.TextField(blank=True, null=True)
    zone_city = models.TextField(blank=True, null=True)
    zone_state = models.TextField(blank=True, null=True)
    zone_post_code = models.TextField(blank=True, null=True)
    zone_country = models.TextField(blank=True, null=True)
    zone_email = models.TextField(blank=True, null=True)
    zone_phone = models.TextField(blank=True, null=True)
    zone_phone_ext = models.TextField(blank=True, null=True)
    zone_fax = models.TextField(blank=True, null=True)
    zone_fax_ext = models.TextField(blank=True, null=True)
    zone_raw_text = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "dns_records"


class DomainAlerts(models.Model):
    domain_alert_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    sub_domain_uid = models.ForeignKey(
        "SubDomains", on_delete=models.CASCADE, db_column="sub_domain_uid"
    )
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )
    organizations_uid = models.UUIDField()
    alert_type = models.TextField(blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    previous_value = models.TextField(blank=True, null=True)
    new_value = models.TextField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "domain_alerts"
        unique_together = (("alert_type", "sub_domain_uid", "date", "new_value"),)


class DomainPermutations(models.Model):
    suspected_domain_uid = models.UUIDField(default=uuid.uuid1())
    organizations_uid = models.ForeignKey(
        "Organizations", on_delete=models.CASCADE, db_column="organizations_uid"
    )
    domain_permutation = models.TextField(blank=True, null=True)
    ipv4 = models.TextField(blank=True, null=True)
    ipv6 = models.TextField(blank=True, null=True)
    mail_server = models.TextField(blank=True, null=True)
    name_server = models.TextField(blank=True, null=True)
    fuzzer = models.TextField(blank=True, null=True)
    date_observed = models.DateField(blank=True, null=True)
    ssdeep_score = models.TextField(blank=True, null=True)
    malicious = models.BooleanField(blank=True, null=True)
    blocklist_attack_count = models.IntegerField(blank=True, null=True)
    blocklist_report_count = models.IntegerField(blank=True, null=True)
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )
    sub_domain_uid = models.ForeignKey(
        "SubDomains",
        on_delete=models.CASCADE,
        db_column="sub_domain_uid",
        blank=True,
        null=True,
    )
    dshield_record_count = models.IntegerField(blank=True, null=True)
    dshield_attack_count = models.IntegerField(blank=True, null=True)
    date_active = models.DateField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "domain_permutations"
        unique_together = (("domain_permutation", "organizations_uid"),)


class DotgovDomains(models.Model):
    dotgov_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    domain_name = models.TextField(unique=True)
    domain_type = models.TextField(blank=True, null=True)
    agency = models.TextField(blank=True, null=True)
    organization = models.TextField(blank=True, null=True)
    city = models.TextField(blank=True, null=True)
    state = models.TextField(blank=True, null=True)
    security_contact_email = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "dotgov_domains"


class Executives(models.Model):
    executives_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey(
        "Organizations", on_delete=models.CASCADE, db_column="organizations_uid"
    )
    executives = models.TextField()

    class Meta:
        managed = False
        db_table = "executives"


class Ips(models.Model):
    ip_hash = models.TextField(primary_key=True)
    ip = models.GenericIPAddressField(unique=True)
    origin_cidr = models.ForeignKey(
        Cidrs, on_delete=models.CASCADE, db_column="origin_cidr", blank=True, null=True
    )
    shodan_results = models.BooleanField(blank=True, null=True)
    live = models.BooleanField(blank=True, null=True)
    date_last_live = models.DateTimeField(blank=True, null=True)
    last_reverse_lookup = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "ips"


class IpsSubs(models.Model):
    ips_subs_uid = models.UUIDField(primary_key=True)
    ip_hash = models.ForeignKey(Ips, on_delete=models.CASCADE, db_column="ip_hash")
    sub_domain_uid = models.ForeignKey(
        "SubDomains", on_delete=models.CASCADE, db_column="sub_domain_uid"
    )

    class Meta:
        managed = False
        # db_table = 'ips_subs'
        unique_together = (("ip_hash", "sub_domain_uid"),)


class Mentions(models.Model):
    mentions_uid = models.UUIDField(primary_key=True)
    category = models.TextField(blank=True, null=True)
    collection_date = models.TextField(blank=True, null=True)
    content = models.TextField(blank=True, null=True)
    creator = models.TextField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    sixgill_mention_id = models.TextField(unique=True, blank=True, null=True)
    post_id = models.TextField(blank=True, null=True)
    lang = models.TextField(blank=True, null=True)
    rep_grade = models.TextField(blank=True, null=True)
    site = models.TextField(blank=True, null=True)
    site_grade = models.TextField(blank=True, null=True)
    title = models.TextField(blank=True, null=True)
    type = models.TextField(blank=True, null=True)
    url = models.TextField(blank=True, null=True)
    comments_count = models.TextField(blank=True, null=True)
    sub_category = models.TextField(blank=True, null=True)
    tags = models.TextField(blank=True, null=True)
    organizations_uid = models.UUIDField()
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )
    title_translated = models.TextField(blank=True, null=True)
    content_translated = models.TextField(blank=True, null=True)
    detected_lang = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "mentions"


class OrgIdMap(models.Model):
    cyhy_id = models.TextField(blank=True, null=True)
    pe_org_id = models.TextField(blank=True, null=True)
    merge_orgs = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "org_id_map"
        unique_together = (("cyhy_id", "pe_org_id"),)


class OrgType(models.Model):
    org_type_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    org_type = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "org_type"


class Organizations(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    name = models.TextField()
    cyhy_db_name = models.TextField(unique=True, blank=True, null=True)
    org_type_uid = models.ForeignKey(
        OrgType,
        on_delete=models.CASCADE,
        db_column="org_type_uid",
        blank=True,
        null=True,
    )
    report_on = models.BooleanField(blank=True, null=True)
    password = models.TextField(blank=True, null=True)
    date_first_reported = models.DateTimeField(blank=True, null=True)
    parent_org_uid = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        db_column="parent_org_uid",
        blank=True,
        null=True,
    )
    premium_report = models.BooleanField(blank=True, null=True)
    agency_type = models.TextField(blank=True, null=True)
    demo = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "organizations"


class PshttResults(models.Model):
    pshtt_results_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    organizations_uid = models.ForeignKey(
        Organizations, on_delete=models.CASCADE, db_column="organizations_uid"
    )
    sub_domain_uid = models.ForeignKey(
        "SubDomains", on_delete=models.CASCADE, db_column="sub_domain_uid"
    )
    data_source_uid = models.UUIDField()
    sub_domain = models.TextField()
    scanned = models.BooleanField(blank=True, null=True)
    base_domain = models.TextField(blank=True, null=True)
    base_domain_hsts_preloaded = models.BooleanField(blank=True, null=True)
    canonical_url = models.TextField(blank=True, null=True)
    defaults_to_https = models.BooleanField(blank=True, null=True)
    domain = models.TextField(blank=True, null=True)
    domain_enforces_https = models.BooleanField(blank=True, null=True)
    domain_supports_https = models.BooleanField(blank=True, null=True)
    domain_uses_strong_hsts = models.BooleanField(blank=True, null=True)
    downgrades_https = models.BooleanField(blank=True, null=True)
    htss = models.BooleanField(blank=True, null=True)
    hsts_entire_domain = models.BooleanField(blank=True, null=True)
    hsts_header = models.TextField(blank=True, null=True)
    hsts_max_age = models.DecimalField(
        max_digits=1000, decimal_places=1000, blank=True, null=True
    )
    hsts_preload_pending = models.BooleanField(blank=True, null=True)
    hsts_preload_ready = models.BooleanField(blank=True, null=True)
    hsts_preloaded = models.BooleanField(blank=True, null=True)
    https_bad_chain = models.BooleanField(blank=True, null=True)
    https_bad_hostname = models.BooleanField(blank=True, null=True)
    https_cert_chain_length = models.IntegerField(blank=True, null=True)
    https_client_auth_required = models.BooleanField(blank=True, null=True)
    https_custom_truststore_trusted = models.BooleanField(blank=True, null=True)
    https_expired_cert = models.BooleanField(blank=True, null=True)
    https_full_connection = models.BooleanField(blank=True, null=True)
    https_live = models.BooleanField(blank=True, null=True)
    https_probably_missing_intermediate_cert = models.BooleanField(
        blank=True, null=True
    )
    https_publicly_trusted = models.BooleanField(blank=True, null=True)
    https_self_signed_cert = models.BooleanField(blank=True, null=True)
    ip = models.GenericIPAddressField(blank=True, null=True)
    live = models.BooleanField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    redirect = models.BooleanField(blank=True, null=True)
    redirect_to = models.TextField(blank=True, null=True)
    server_header = models.TextField(blank=True, null=True)
    server_version = models.TextField(blank=True, null=True)
    strictly_forces_https = models.BooleanField(blank=True, null=True)
    unknown_error = models.BooleanField(blank=True, null=True)
    valid_https = models.BooleanField(blank=True, null=True)
    ep_http_headers = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    ep_http_ip = models.GenericIPAddressField(blank=True, null=True)
    ep_http_live = models.BooleanField(blank=True, null=True)
    ep_http_notes = models.TextField(blank=True, null=True)
    ep_http_redirect = models.BooleanField(blank=True, null=True)
    ep_http_redirect_eventually_to = models.TextField(blank=True, null=True)
    ep_http_redirect_eventually_to_external = models.BooleanField(blank=True, null=True)
    ep_http_redirect_eventually_to_http = models.BooleanField(blank=True, null=True)
    ep_http_redirect_eventually_to_https = models.BooleanField(blank=True, null=True)
    ep_http_redirect_eventually_to_subdomain = models.BooleanField(
        blank=True, null=True
    )
    ep_http_redirect_immediately_to = models.TextField(blank=True, null=True)
    ep_http_redirect_immediately_to_external = models.BooleanField(
        blank=True, null=True
    )
    ep_http_redirect_immediately_to_http = models.BooleanField(blank=True, null=True)
    ep_http_redirect_immediately_to_https = models.BooleanField(blank=True, null=True)
    ep_http_redirect_immediately_to_subdomain = models.BooleanField(
        blank=True, null=True
    )
    ep_http_redirect_immediately_to_www = models.BooleanField(blank=True, null=True)
    ep_http_server_header = models.TextField(blank=True, null=True)
    ep_http_server_version = models.TextField(blank=True, null=True)
    ep_http_status = models.IntegerField(blank=True, null=True)
    ep_http_unknown_error = models.BooleanField(blank=True, null=True)
    ep_http_url = models.TextField(blank=True, null=True)
    ep_https_headers = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    ep_https_hsts = models.BooleanField(blank=True, null=True)
    ep_https_hsts_all_subdomains = models.BooleanField(blank=True, null=True)
    ep_https_hsts_header = models.TextField(blank=True, null=True)
    ep_https_hsts_max_age = models.DecimalField(
        max_digits=1000, decimal_places=1000, blank=True, null=True
    )
    ep_https_hsts_preload = models.BooleanField(blank=True, null=True)
    ep_https_https_bad_chain = models.BooleanField(blank=True, null=True)
    ep_https_https_bad_hostname = models.BooleanField(blank=True, null=True)
    ep_https_https_cert_chain_len = models.IntegerField(blank=True, null=True)
    ep_https_https_client_auth_required = models.BooleanField(blank=True, null=True)
    ep_https_https_custom_trusted = models.BooleanField(blank=True, null=True)
    ep_https_https_expired_cert = models.BooleanField(blank=True, null=True)
    ep_https_https_vull_connection = models.BooleanField(blank=True, null=True)
    ep_https_https_missing_intermediate_cert = models.BooleanField(
        blank=True, null=True
    )
    ep_https_https_public_trusted = models.BooleanField(blank=True, null=True)
    ep_https_https_self_signed_cert = models.BooleanField(blank=True, null=True)
    ep_https_https_valid = models.BooleanField(blank=True, null=True)
    ep_https_ip = models.GenericIPAddressField(blank=True, null=True)
    ep_https_live = models.BooleanField(blank=True, null=True)
    ep_https_notes = models.TextField(blank=True, null=True)
    ep_https_redirect = models.BooleanField(blank=True, null=True)
    ep_https_redireect_eventually_to = models.TextField(blank=True, null=True)
    ep_https_redirect_eventually_to_external = models.BooleanField(
        blank=True, null=True
    )
    ep_https_redirect_eventually_to_http = models.BooleanField(blank=True, null=True)
    ep_https_redirect_eventually_to_https = models.BooleanField(blank=True, null=True)
    ep_https_redirect_eventually_to_subdomain = models.BooleanField(
        blank=True, null=True
    )
    ep_https_redirect_immediately_to = models.TextField(blank=True, null=True)
    ep_https_redirect_immediately_to_external = models.BooleanField(
        blank=True, null=True
    )
    ep_https_redirect_immediately_to_http = models.BooleanField(blank=True, null=True)
    ep_https_redirect_immediately_to_https = models.BooleanField(blank=True, null=True)
    ep_https_redirect_immediately_to_subdomain = models.BooleanField(
        blank=True, null=True
    )
    ep_https_redirect_immediately_to_www = models.BooleanField(blank=True, null=True)
    ep_https_server_header = models.TextField(blank=True, null=True)
    ep_https_server_version = models.TextField(blank=True, null=True)
    ep_https_status = models.IntegerField(blank=True, null=True)
    ep_https_unknown_error = models.BooleanField(blank=True, null=True)
    ep_https_url = models.TextField(blank=True, null=True)
    ep_httpswww_headers = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    ep_httpswww_hsts = models.BooleanField(blank=True, null=True)
    ep_httpswww_hsts_all_subdomains = models.BooleanField(blank=True, null=True)
    ep_httpswww_hsts_header = models.TextField(blank=True, null=True)
    ep_httpswww_hsts_max_age = models.DecimalField(
        max_digits=1000, decimal_places=1000, blank=True, null=True
    )
    ep_httpswww_hsts_preload = models.BooleanField(blank=True, null=True)
    ep_httpswww_https_bad_chain = models.BooleanField(blank=True, null=True)
    ep_httpswww_https_bad_hostname = models.BooleanField(blank=True, null=True)
    ep_httpswww_https_cert_chain_len = models.IntegerField(blank=True, null=True)
    ep_httpswww_https_client_auth_required = models.BooleanField(blank=True, null=True)
    ep_httpswww_https_custom_trusted = models.BooleanField(blank=True, null=True)
    ep_httpswww_https_expired_cert = models.BooleanField(blank=True, null=True)
    ep_httpswww_https_full_connection = models.BooleanField(blank=True, null=True)
    ep_httpswww_https_missing_intermediate_cert = models.BooleanField(
        blank=True, null=True
    )
    ep_httpswww_https_public_trusted = models.BooleanField(blank=True, null=True)
    ep_httpswww_https_self_signed_cert = models.BooleanField(blank=True, null=True)
    ep_httpswww_https_valid = models.BooleanField(blank=True, null=True)
    ep_httpswww_ip = models.GenericIPAddressField(blank=True, null=True)
    ep_httpswww_live = models.BooleanField(blank=True, null=True)
    ep_httpswww_notes = models.TextField(blank=True, null=True)
    ep_httpswww_redirect = models.BooleanField(blank=True, null=True)
    ep_httpswww_redirect_eventually_to = models.TextField(blank=True, null=True)
    ep_httpswww_redirect_eventually_to_external = models.BooleanField(
        blank=True, null=True
    )
    ep_httpswww_redirect_eventually_to_http = models.BooleanField(blank=True, null=True)
    ep_httpswww_redirect_eventually_to_https = models.BooleanField(
        blank=True, null=True
    )
    ep_httpswww_redirect_eventually_to_subdomain = models.BooleanField(
        blank=True, null=True
    )
    ep_httpswww_redirect_immediately_to = models.TextField(blank=True, null=True)
    ep_httpswww_redirect_immediately_to_external = models.BooleanField(
        blank=True, null=True
    )
    ep_httpswww_redirect_immediately_to_http = models.BooleanField(
        blank=True, null=True
    )
    ep_httpswww_redirect_immediately_to_https = models.BooleanField(
        blank=True, null=True
    )
    ep_httpswww_redirect_immediately_to_subdomain = models.BooleanField(
        blank=True, null=True
    )
    ep_httpswww_redirect_immediately_to_www = models.BooleanField(blank=True, null=True)
    ep_httpswww_server_header = models.TextField(blank=True, null=True)
    ep_httpswww_server_version = models.TextField(blank=True, null=True)
    ep_httpswww_status = models.IntegerField(blank=True, null=True)
    ep_httpswww_unknown_error = models.BooleanField(blank=True, null=True)
    ep_httpswww_url = models.TextField(blank=True, null=True)
    ep_httpwww_headers = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    ep_httpwww_ip = models.GenericIPAddressField(blank=True, null=True)
    ep_httpwww_live = models.BooleanField(blank=True, null=True)
    ep_httpwww_notes = models.TextField(blank=True, null=True)
    ep_httpwww_redirect = models.BooleanField(blank=True, null=True)
    ep_httpwww_redirect_eventually_to = models.TextField(blank=True, null=True)
    ep_httpwww_redirect_eventually_to_external = models.BooleanField(
        blank=True, null=True
    )
    ep_httpwww_redirect_eventually_to_http = models.BooleanField(blank=True, null=True)
    ep_httpwww_redirect_eventually_to_https = models.BooleanField(blank=True, null=True)
    ep_httpwww_redirect_eventually_to_subdomain = models.BooleanField(
        blank=True, null=True
    )
    ep_httpwww_redirect_immediately_to = models.TextField(blank=True, null=True)
    ep_httpwww_redirect_immediately_to_external = models.BooleanField(
        blank=True, null=True
    )
    ep_httpwww_redirect_immediately_to_http = models.BooleanField(blank=True, null=True)
    ep_httpwww_redirect_immediately_to_https = models.BooleanField(
        blank=True, null=True
    )
    ep_httpwww_redirect_immediately_to_subdomain = models.BooleanField(
        blank=True, null=True
    )
    ep_httpwww_redirect_immediately_to_www = models.BooleanField(blank=True, null=True)
    ep_httpwww_server_header = models.TextField(blank=True, null=True)
    ep_httpwww_server_version = models.TextField(blank=True, null=True)
    ep_httpwww_status = models.IntegerField(blank=True, null=True)
    ep_httpwww_unknown_error = models.BooleanField(blank=True, null=True)
    ep_httpwww_url = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "pshtt_results"
        unique_together = (("organizations_uid", "sub_domain_uid"),)


class ReportSummaryStats(models.Model):
    report_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    organizations_uid = models.ForeignKey(
        Organizations, on_delete=models.CASCADE, db_column="organizations_uid"
    )
    start_date = models.DateField()
    end_date = models.DateField(blank=True, null=True)
    ip_count = models.IntegerField(blank=True, null=True)
    root_count = models.IntegerField(blank=True, null=True)
    sub_count = models.IntegerField(blank=True, null=True)
    ports_count = models.IntegerField(blank=True, null=True)
    creds_count = models.IntegerField(blank=True, null=True)
    breach_count = models.IntegerField(blank=True, null=True)
    cred_password_count = models.IntegerField(blank=True, null=True)
    domain_alert_count = models.IntegerField(blank=True, null=True)
    suspected_domain_count = models.IntegerField(blank=True, null=True)
    insecure_port_count = models.IntegerField(blank=True, null=True)
    verified_vuln_count = models.IntegerField(blank=True, null=True)
    suspected_vuln_count = models.IntegerField(blank=True, null=True)
    suspected_vuln_addrs_count = models.IntegerField(blank=True, null=True)
    threat_actor_count = models.IntegerField(blank=True, null=True)
    dark_web_alerts_count = models.IntegerField(blank=True, null=True)
    dark_web_mentions_count = models.IntegerField(blank=True, null=True)
    dark_web_executive_alerts_count = models.IntegerField(blank=True, null=True)
    dark_web_asset_alerts_count = models.IntegerField(blank=True, null=True)
    pe_number_score = models.TextField(blank=True, null=True)
    pe_letter_grade = models.TextField(blank=True, null=True)
    pe_percent_score = models.DecimalField(
        max_digits=1000, decimal_places=1000, blank=True, null=True
    )

    class Meta:
        managed = False
        db_table = "report_summary_stats"
        unique_together = (("organizations_uid", "start_date"),)


class RootDomains(models.Model):
    root_domain_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    organizations_uid = models.ForeignKey(
        Organizations, on_delete=models.CASCADE, db_column="organizations_uid"
    )
    root_domain = models.TextField()
    ip_address = models.TextField(blank=True, null=True)
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )
    enumerate_subs = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "root_domains"
        unique_together = (("root_domain", "organizations_uid"),)


class TeamMembers(models.Model):
    team_member_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    team_member_fname = models.TextField()
    team_member_lname = models.TextField()
    team_member_email = models.TextField()
    team_member_ghID = models.TextField(blank=False, null=False)
    team_member_phone = models.TextField(blank=True, null=True)
    team_member_role = models.TextField(blank=True, null=True)
    team_member_notes = models.TextField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = "team_members"


class ShodanAssets(models.Model):
    shodan_asset_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    organizations_uid = models.ForeignKey(
        Organizations, on_delete=models.CASCADE, db_column="organizations_uid"
    )
    organization = models.TextField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(blank=True, null=True)
    product = models.TextField(blank=True, null=True)
    server = models.TextField(blank=True, null=True)
    tags = models.TextField(blank=True, null=True)  # This field type is a guess.
    domains = models.TextField(blank=True, null=True)  # This field type is a guess.
    hostnames = models.TextField(blank=True, null=True)  # This field type is a guess.
    isn = models.TextField(blank=True, null=True)
    asn = models.IntegerField(blank=True, null=True)
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )

    class Meta:
        managed = False
        db_table = "shodan_assets"
        unique_together = (
            ("organizations_uid", "ip", "port", "protocol", "timestamp"),
        )


class ShodanInsecureProtocolsUnverifiedVulns(models.Model):
    insecure_product_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    organizations_uid = models.ForeignKey(
        Organizations, on_delete=models.CASCADE, db_column="organizations_uid"
    )
    organization = models.TextField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    type = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    potential_vulns = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    mitigation = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(blank=True, null=True)
    product = models.TextField(blank=True, null=True)
    server = models.TextField(blank=True, null=True)
    tags = models.TextField(blank=True, null=True)  # This field type is a guess.
    domains = models.TextField(blank=True, null=True)  # This field type is a guess.
    hostnames = models.TextField(blank=True, null=True)  # This field type is a guess.
    isn = models.TextField(blank=True, null=True)
    asn = models.IntegerField(blank=True, null=True)
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )

    class Meta:
        managed = False
        db_table = "shodan_insecure_protocols_unverified_vulns"
        unique_together = (
            ("organizations_uid", "ip", "port", "protocol", "timestamp"),
        )


class ShodanVulns(models.Model):
    shodan_vuln_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    organizations_uid = models.ForeignKey(
        Organizations, on_delete=models.CASCADE, db_column="organizations_uid"
    )
    organization = models.TextField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(blank=True, null=True)
    cve = models.TextField(blank=True, null=True)
    severity = models.TextField(blank=True, null=True)
    cvss = models.DecimalField(
        max_digits=1000, decimal_places=1000, blank=True, null=True
    )
    summary = models.TextField(blank=True, null=True)
    product = models.TextField(blank=True, null=True)
    attack_vector = models.TextField(blank=True, null=True)
    av_description = models.TextField(blank=True, null=True)
    attack_complexity = models.TextField(blank=True, null=True)
    ac_description = models.TextField(blank=True, null=True)
    confidentiality_impact = models.TextField(blank=True, null=True)
    ci_description = models.TextField(blank=True, null=True)
    integrity_impact = models.TextField(blank=True, null=True)
    ii_description = models.TextField(blank=True, null=True)
    availability_impact = models.TextField(blank=True, null=True)
    ai_description = models.TextField(blank=True, null=True)
    tags = models.TextField(blank=True, null=True)  # This field type is a guess.
    domains = models.TextField(blank=True, null=True)  # This field type is a guess.
    hostnames = models.TextField(blank=True, null=True)  # This field type is a guess.
    isn = models.TextField(blank=True, null=True)
    asn = models.IntegerField(blank=True, null=True)
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )
    type = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    potential_vulns = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    mitigation = models.TextField(blank=True, null=True)
    server = models.TextField(blank=True, null=True)
    is_verified = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "shodan_vulns"
        unique_together = (
            ("organizations_uid", "ip", "port", "protocol", "timestamp"),
        )


class SubDomains(models.Model):
    sub_domain_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    sub_domain = models.TextField()
    root_domain_uid = models.ForeignKey(
        RootDomains, on_delete=models.CASCADE, db_column="root_domain_uid"
    )
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )
    dns_record_uid = models.ForeignKey(
        DnsRecords,
        on_delete=models.CASCADE,
        db_column="dns_record_uid",
        blank=True,
        null=True,
    )
    status = models.BooleanField(blank=True, null=True)
    first_seen = models.DateField(blank=True, null=True)
    last_seen = models.DateField(blank=True, null=True)
    current = models.BooleanField(blank=True, null=True)
    identified = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "sub_domains"
        unique_together = (("sub_domain", "root_domain_uid"),)


class TopCves(models.Model):
    top_cves_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    cve_id = models.TextField(blank=True, null=True)
    dynamic_rating = models.TextField(blank=True, null=True)
    nvd_base_score = models.TextField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    summary = models.TextField(blank=True, null=True)
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )

    class Meta:
        managed = False
        db_table = "top_cves"
        unique_together = (("cve_id", "date"),)


class TopicTotals(models.Model):
    cound_uuid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    organizations_uid = models.UUIDField()
    content_count = models.IntegerField()
    count_date = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "topic_totals"


class UniqueSoftware(models.Model):
    field_id = models.UUIDField(
        db_column="_id", primary_key=True, default=uuid.uuid1()
    )  # Field renamed because it started with '_'.
    software_name = models.TextField()

    class Meta:
        managed = False
        db_table = "unique_software"


class WasTrackerCustomerdata(models.Model):
    customer_id = models.UUIDField(
        db_column="customer_id", primary_key=True, default=uuid.uuid1
    )
    tag = models.TextField()
    customer_name = models.TextField()
    testing_sector = models.TextField()
    ci_type = models.TextField()
    jira_ticket = models.TextField()
    ticket = models.TextField()
    next_scheduled = models.TextField()
    last_scanned = models.TextField()
    frequency = models.TextField()
    comments_notes = models.TextField()
    was_report_poc = models.TextField()
    was_report_email = models.TextField()
    onboarding_date = models.TextField()
    no_of_web_apps = models.IntegerField()
    no_web_apps_last_updated = models.TextField(blank=True, null=True)
    elections = models.TextField(blank=True, null=True)
    fceb = models.TextField()
    special_report = models.TextField()
    report_password = models.TextField()
    child_tags = models.TextField()

    class Meta:
        managed = False
        db_table = "was_tracker_customerdata"


class WebAssets(models.Model):
    asset_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    asset_type = models.TextField()
    asset = models.TextField()
    ip_type = models.TextField(blank=True, null=True)
    verified = models.BooleanField(blank=True, null=True)
    organizations_uid = models.ForeignKey(
        Organizations, on_delete=models.CASCADE, db_column="organizations_uid"
    )
    asset_origin = models.TextField(blank=True, null=True)
    report_on = models.BooleanField(blank=True, null=True)
    last_scanned = models.DateTimeField(blank=True, null=True)
    report_status_reason = models.TextField(blank=True, null=True)
    data_source_uid = models.ForeignKey(
        DataSource, on_delete=models.CASCADE, db_column="data_source_uid"
    )

    class Meta:
        managed = False
        db_table = "web_assets"
        unique_together = (("asset", "organizations_uid"),)


class WeeklyStatuses(models.Model):
    weekly_status_uid = models.UUIDField(primary_key=True, default=uuid.uuid1())
    user_status = models.TextField(blank=True)
    key_accomplishments = models.TextField(blank=True, null=True)
    ongoing_task = models.TextField()
    upcoming_task = models.TextField()
    obstacles = models.TextField(blank=True, null=True)
    non_standard_meeting = models.TextField(blank=True, null=True)
    deliverables = models.TextField(blank=True, null=True)
    pto = models.TextField(blank=True, null=True)
    week_ending = models.DateField()
    notes = models.TextField(blank=True, null=True)
    statusComplete = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = True
        db_table = "weekly_statuses"


class VwBreachcompCredsbydate(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    mod_date = models.DateField(blank=True, null=True)
    no_password = models.BigIntegerField(blank=True, null=True)
    password_included = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_breachcomp_credsbydate"


# class VwDarkwebMentionsbydate(models.Model):
#     organizations_uid = models.UUIDField(primary_key=True)
#     date = models.DateField(blank=True, null=True)
#     count = models.BigIntegerField(db_column='Count', blank=True, null=True)  # Field name made lowercase.
#
#     class Meta:
#         managed = False  # Created from a view. Don't remove.
#         db_table = 'vw_darkweb_mentionsbydate'


class VwDarkwebMentionsbydate(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    date = models.DateField(blank=True, null=True)
    count = models.BigIntegerField(
        db_column="Count", blank=True, null=True
    )  # Field name made lowercase.

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_mentionsbydate"


class VwShodanvulnsSuspected(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    organization = models.TextField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    type = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    potential_vulns = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    mitigation = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(blank=True, null=True)
    product = models.TextField(blank=True, null=True)
    server = models.TextField(blank=True, null=True)
    tags = models.TextField(blank=True, null=True)  # This field type is a guess.
    domains = models.TextField(blank=True, null=True)  # This field type is a guess.
    hostnames = models.TextField(blank=True, null=True)  # This field type is a guess.
    isn = models.TextField(blank=True, null=True)
    asn = models.IntegerField(blank=True, null=True)
    data_source = models.TextField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_shodanvulns_suspected"


class VwShodanvulnsVerified(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    organization = models.TextField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(blank=True, null=True)
    cve = models.TextField(blank=True, null=True)
    severity = models.TextField(blank=True, null=True)
    cvss = models.DecimalField(
        max_digits=1000, decimal_places=1000, blank=True, null=True
    )
    summary = models.TextField(blank=True, null=True)
    product = models.TextField(blank=True, null=True)
    attack_vector = models.TextField(blank=True, null=True)
    av_description = models.TextField(blank=True, null=True)
    attack_complexity = models.TextField(blank=True, null=True)
    ac_description = models.TextField(blank=True, null=True)
    confidentiality_impact = models.TextField(blank=True, null=True)
    ci_description = models.TextField(blank=True, null=True)
    integrity_impact = models.TextField(blank=True, null=True)
    ii_description = models.TextField(blank=True, null=True)
    availability_impact = models.TextField(blank=True, null=True)
    ai_description = models.TextField(blank=True, null=True)
    tags = models.TextField(blank=True, null=True)  # This field type is a guess.
    domains = models.TextField(blank=True, null=True)  # This field type is a guess.
    hostnames = models.TextField(blank=True, null=True)  # This field type is a guess.
    isn = models.TextField(blank=True, null=True)
    asn = models.IntegerField(blank=True, null=True)
    data_source = models.TextField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_shodanvulns_verified"


class VwBreachcompBreachdetails(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    breach_name = models.TextField(blank=True, null=True)
    mod_date = models.DateField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    breach_date = models.DateField(blank=True, null=True)
    password_included = models.BooleanField(blank=True, null=True)
    number_of_creds = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_breachcomp_breachdetails"


class VwDarkwebSocmediaMostactposts(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    date = models.DateField(blank=True, null=True)
    title = models.TextField(
        db_column="Title", blank=True, null=True
    )  # Field name made lowercase.
    comments_count = models.IntegerField(
        db_column="Comments Count", blank=True, null=True
    )  # Field name made lowercase. Field renamed to remove unsuitable characters.

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_socmedia_mostactposts"


class VwDarkwebMostactposts(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    date = models.DateField(blank=True, null=True)
    title = models.TextField(
        db_column="Title", blank=True, null=True
    )  # Field name made lowercase.
    comments_count = models.IntegerField(
        db_column="Comments Count", blank=True, null=True
    )  # Field name made lowercase. Field renamed to remove unsuitable characters.

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_mostactposts"


class VwDarkwebAssetalerts(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    date = models.DateField(blank=True, null=True)
    site = models.TextField(
        db_column="Site", blank=True, null=True
    )  # Field name made lowercase.
    title = models.TextField(
        db_column="Title", blank=True, null=True
    )  # Field name made lowercase.
    events = models.BigIntegerField(
        db_column="Events", blank=True, null=True
    )  # Field name made lowercase.

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_assetalerts"


class VwDarkwebExecalerts(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    date = models.DateField(blank=True, null=True)
    site = models.TextField(
        db_column="Site", blank=True, null=True
    )  # Field name made lowercase.
    title = models.TextField(
        db_column="Title", blank=True, null=True
    )  # Field name made lowercase.
    events = models.BigIntegerField(
        db_column="Events", blank=True, null=True
    )  # Field name made lowercase.

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_execalerts"


class VwDarkwebThreatactors(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    date = models.DateField(blank=True, null=True)
    creator = models.TextField(
        db_column="Creator", blank=True, null=True
    )  # Field name made lowercase.
    grade = models.DecimalField(
        db_column="Grade", max_digits=1000, decimal_places=1000, blank=True, null=True
    )  # Field name made lowercase.

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_threatactors"


class VwDarkwebPotentialthreats(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    date = models.DateField(blank=True, null=True)
    site = models.TextField(
        db_column="Site", blank=True, null=True
    )  # Field name made lowercase.
    threats = models.TextField(
        db_column="Threats", blank=True, null=True
    )  # Field name made lowercase.

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_potentialthreats"


class VwDarkwebSites(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    date = models.DateField(blank=True, null=True)
    site = models.TextField(
        db_column="Site", blank=True, null=True
    )  # Field name made lowercase.

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_sites"


class VwDarkwebInviteonlymarkets(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    date = models.DateField(blank=True, null=True)
    site = models.TextField(
        db_column="Site", blank=True, null=True
    )  # Field name made lowercase.

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_inviteonlymarkets"


class VwDarkwebTopcves(models.Model):
    top_cves_uid = models.UUIDField(primary_key=True)
    cve_id = models.TextField(blank=True, null=True)
    dynamic_rating = models.TextField(blank=True, null=True)
    nvd_base_score = models.TextField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    summary = models.TextField(blank=True, null=True)
    data_source_uid = models.UUIDField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_darkweb_topcves"


class VwCidrs(models.Model):
    cidr_uid = models.UUIDField(primary_key=True)
    network = models.TextField(blank=True, null=True)  # This field type is a guess.
    organizations_uid = models.UUIDField(blank=True, null=True)
    data_source_uid = models.UUIDField(blank=True, null=True)
    insert_alert = models.TextField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_cidrs"


class VwBreachcomp(models.Model):
    credential_exposures_uid = models.UUIDField(primary_key=True)
    email = models.TextField(blank=True, null=True)
    breach_name = models.TextField(blank=True, null=True)
    organizations_uid = models.UUIDField(blank=True, null=True)
    root_domain = models.TextField(blank=True, null=True)
    sub_domain = models.TextField(blank=True, null=True)
    hash_type = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    login_id = models.TextField(blank=True, null=True)
    password = models.TextField(blank=True, null=True)
    phone = models.TextField(blank=True, null=True)
    data_source_uid = models.UUIDField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    breach_date = models.DateField(blank=True, null=True)
    added_date = models.DateTimeField(blank=True, null=True)
    modified_date = models.DateTimeField(blank=True, null=True)
    data_classes = models.TextField(
        blank=True, null=True
    )  # This field type is a guess.
    password_included = models.BooleanField(blank=True, null=True)
    is_verified = models.BooleanField(blank=True, null=True)
    is_fabricated = models.BooleanField(blank=True, null=True)
    is_sensitive = models.BooleanField(blank=True, null=True)
    is_retired = models.BooleanField(blank=True, null=True)
    is_spam_list = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_breachcomp"


class VwOrgsTotalDomains(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    cyhy_db_name = models.TextField(blank=True, null=True)
    num_root_domain = models.BigIntegerField(blank=True, null=True)
    num_sub_domain = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_orgs_total_domains"


class VwOrgsContactInfo(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    cyhy_db_name = models.TextField(blank=True, null=True)
    agency_name = models.TextField(blank=True, null=True)
    contact_type = models.TextField(blank=True, null=True)
    contact_name = models.TextField(blank=True, null=True)
    email = models.TextField(blank=True, null=True)
    phone = models.TextField(blank=True, null=True)
    date_pulled = models.DateField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_orgs_contact_info"


class VwOrgsTotalIps(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    cyhy_db_name = models.TextField(blank=True, null=True)
    num_ips = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_orgs_total_ips"


class MatVwOrgsAllIps(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    cyhy_db_name = models.TextField(blank=True, null=True)
    ip_addresses = ArrayField(
        models.GenericIPAddressField(blank=True, null=True), blank=True, null=True
    )

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "mat_vw_orgs_all_ips"


class VwOrgsAttacksurface(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    cyhy_db_name = models.TextField(blank=True, null=True)
    num_ports = models.BigIntegerField(blank=True, null=True)
    num_root_domain = models.BigIntegerField(blank=True, null=True)
    num_sub_domain = models.BigIntegerField(blank=True, null=True)
    num_ips = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_orgs_attacksurface"


class VwOrgsTotalPorts(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    cyhy_db_name = models.TextField(blank=True, null=True)
    num_ports = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_orgs_total_ports"


# ---------- D-Score View Models ----------
# D-Score VS Cert View
class VwDscoreVSCert(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    num_ident_cert = models.BigIntegerField(blank=True, null=True)
    num_monitor_cert = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_dscore_vs_cert"


# D-Score VS Mail View
class VwDscoreVSMail(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    num_valid_dmarc = models.BigIntegerField(blank=True, null=True)
    num_valid_spf = models.BigIntegerField(blank=True, null=True)
    num_valid_dmarc_or_spf = models.BigIntegerField(blank=True, null=True)
    total_mail_domains = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_dscore_vs_mail"


# D-Score PE IP View
class VwDscorePEIp(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    num_ident_ip = models.BigIntegerField(blank=True, null=True)
    num_monitor_ip = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_dscore_pe_ip"


# D-Score PE Domain View
class VwDscorePEDomain(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    num_ident_domain = models.BigIntegerField(blank=True, null=True)
    num_monitor_domain = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_dscore_pe_domain"


# D-Score WAS Webapp View
class VwDscoreWASWebapp(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    num_ident_webapp = models.BigIntegerField(blank=True, null=True)
    num_monitor_webapp = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_dscore_was_webapp"


# ---------- I-Score View Models ----------
# I-Score VS Vuln View
class VwIscoreVSVuln(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    cve_name = models.CharField(blank=True, null=True)
    cvss_score = models.FloatField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_iscore_vs_vuln"


# I-Score VS Vuln Previous View
class VwIscoreVSVulnPrev(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    cve_name = models.CharField(blank=True, null=True)
    cvss_score = models.FloatField(blank=True, null=True)
    time_closed = models.DateField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_iscore_vs_vuln_prev"


# I-Score PE Vuln View
class VwIscorePEVuln(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    cve_name = models.CharField(blank=True, null=True)
    cvss_score = models.FloatField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_iscore_pe_vuln"


# I-Score PE Cred View
class VwIscorePECred(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    password_creds = models.BigIntegerField(blank=True, null=True)
    total_creds = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_iscore_pe_cred"


# I-Score PE Breach View
class VwIscorePEBreach(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    breach_count = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_iscore_pe_breach"


# I-Score PE Darkweb View
class VwIscorePEDarkweb(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    alert_type = models.CharField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    Count = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_iscore_pe_darkweb"


# I-Score PE Protocol View
class VwIscorePEProtocol(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    port = models.CharField(blank=True, null=True)
    ip = models.CharField(blank=True, null=True)
    protocol = models.CharField(blank=True, null=True)
    protocol_type = models.CharField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_iscore_pe_protocol"


# I-Score WAS Vuln View
class VwIscoreWASVuln(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    cve_name = models.CharField(blank=True, null=True)
    cvss_score = models.FloatField(blank=True, null=True)
    owasp_category = models.CharField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_iscore_was_vuln"


# I-Score WAS Vuln Previous View
class VwIscoreWASVulnPrev(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    parent_org_uid = models.UUIDField(blank=True, null=True)
    was_total_vulns_prev = models.BigIntegerField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)

    class Meta:
        managed = False  # Created from a view. Don't remove.
        db_table = "vw_iscore_was_vuln_prev"


# cyhy_kevs table model (needed for kev_list endpoint)
class CyhyKevs(models.Model):
    cyhy_kevs_uid = models.UUIDField(primary_key=True)
    kev = models.CharField(blank=True, null=True)
    first_seen = models.DateField(blank=True, null=True)
    last_seen = models.DateField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "cyhy_kevs"


# ---------- Misc. Score Related Models ----------
# vw_iscore_orgs_ip_counts view model (used for XS/S/M/L/XL orgs endpoints)
class VwIscoreOrgsIpCounts(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    cyhy_db_name = models.CharField(blank=True, null=True)
    ip_count = models.BigIntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "vw_iscore_orgs_ip_counts"


# Github issues connected to this model:
# - Issue 636
class VwPEScoreCheckNewCVE(models.Model):
    cve_name = models.CharField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = "vw_pescore_check_new_cve"
