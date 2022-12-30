# Create your models here.
# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models
from django.conf import settings


class Users(models.Model):
    id = models.UUIDField(primary_key=True)
    email = models.CharField(unique=True, max_length=64, blank=True, null=True)
    username = models.CharField(unique=True, max_length=64, blank=True, null=True)
    admin = models.IntegerField(blank=True, null=True)
    role = models.IntegerField(blank=True, null=True)
    password_hash = models.CharField(max_length=128, blank=True, null=True)
    api_key = models.CharField(unique=True, max_length=128, blank=True, null=True)
    refresh_token = models.CharField(unique=True, max_length=128, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Users'


class Usersapi(models.Model):
    id = models.UUIDField(primary_key=True)
    email = models.CharField(unique=True, max_length=64, blank=True, null=True)
    username = models.CharField(unique=True, max_length=64, blank=True, null=True)
    password_hash = models.CharField(max_length=255, blank=True, null=True)
    api_key = models.CharField(unique=True, max_length=255, blank=True, null=True)
    refresh_token = models.CharField(unique=True, max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'UsersAPI'


class AlembicVersion(models.Model):
    version_num = models.CharField(primary_key=True, max_length=32)

    class Meta:
        managed = False
        db_table = 'alembic_version'


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
    organizations_uid = models.ForeignKey('Organizations', models.DO_NOTHING, db_column='organizations_uid')

    class Meta:
        managed = False
        db_table = 'alerts'


class Alias(models.Model):
    alias_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey('Organizations', models.DO_NOTHING, db_column='organizations_uid')
    alias = models.TextField(unique=True)

    class Meta:
        managed = False
        db_table = 'alias'


class AssetHeaders(models.Model):
    sub_url = models.TextField()
    tech_detected = models.TextField()  # This field type is a guess.
    interesting_header = models.TextField()  # This field type is a guess.
    field_id = models.UUIDField(db_column='_id', primary_key=True)  # Field renamed because it started with '_'.

    class Meta:
        managed = False
        db_table = 'asset_headers'


class CybersixExposedCredentials(models.Model):
    csg_exposed_credentials_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey('Organizations', models.DO_NOTHING, db_column='organizations_uid')
    breach_date = models.DateField(blank=True, null=True)
    breach_id = models.IntegerField(blank=True, null=True)
    breach_name = models.TextField()
    create_time = models.DateTimeField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    domain = models.TextField(blank=True, null=True)
    email = models.TextField()
    password = models.TextField(blank=True, null=True)
    hash_type = models.TextField(blank=True, null=True)
    login_id = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    phone = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'cybersix_exposed_credentials'
        unique_together = (('email', 'breach_id'),)


class DnstwistDomainMasq(models.Model):
    suspected_domain_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey('Organizations', models.DO_NOTHING, db_column='organizations_uid')
    domain_permutation = models.TextField(unique=True, blank=True, null=True)
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

    class Meta:
        managed = False
        db_table = 'dnstwist_domain_masq'


class Executives(models.Model):
    executives_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey('Organizations', models.DO_NOTHING, db_column='organizations_uid')
    executives = models.TextField()

    class Meta:
        managed = False
        db_table = 'executives'


class HibpBreaches(models.Model):
    hibp_breaches_uid = models.UUIDField(primary_key=True)
    breach_name = models.TextField(unique=True)
    description = models.TextField(blank=True, null=True)
    exposed_cred_count = models.BigIntegerField(blank=True, null=True)
    breach_date = models.DateField(blank=True, null=True)
    added_date = models.DateTimeField(blank=True, null=True)
    modified_date = models.DateTimeField(blank=True, null=True)
    data_classes = models.TextField(blank=True, null=True)  # This field type is a guess.
    password_included = models.BooleanField(blank=True, null=True)
    is_verified = models.BooleanField(blank=True, null=True)
    is_fabricated = models.BooleanField(blank=True, null=True)
    is_sensitive = models.BooleanField(blank=True, null=True)
    is_retired = models.BooleanField(blank=True, null=True)
    is_spam_list = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'hibp_breaches'


class HibpExposedCredentials(models.Model):
    hibp_exposed_credentials_uid = models.UUIDField(primary_key=True)
    email = models.TextField()
    organizations_uid = models.ForeignKey('Organizations', models.DO_NOTHING, db_column='organizations_uid')
    root_domain = models.TextField(blank=True, null=True)
    sub_domain = models.TextField(blank=True, null=True)
    breach_name = models.TextField(blank=True, null=True)
    modified_date = models.DateTimeField(blank=True, null=True)
    breach = models.ForeignKey(HibpBreaches, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'hibp_exposed_credentials'
        unique_together = (('email', 'breach_name'),)


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

    class Meta:
        managed = False
        db_table = 'mentions'


class Organizations(models.Model):
    organizations_uid = models.UUIDField(primary_key=True)
    name = models.TextField(unique=True)
    cyhy_db_name = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'organizations'


class RootDomains(models.Model):
    root_domain_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey(Organizations, models.DO_NOTHING, db_column='organizations_uid')
    organization_name = models.TextField()
    root_domain = models.TextField()
    ip_address = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'root_domains'
        unique_together = (('root_domain', 'organizations_uid'),)


class ShodanAssets(models.Model):
    shodan_asset_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey(Organizations, models.DO_NOTHING, db_column='organizations_uid')
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

    class Meta:
        managed = False
        db_table = 'shodan_assets'
        unique_together = (('organizations_uid', 'ip', 'port', 'protocol', 'timestamp'),)


class ShodanInsecureProtocolsUnverifiedVulns(models.Model):
    insecure_product_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey(Organizations, models.DO_NOTHING, db_column='organizations_uid')
    organization = models.TextField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    type = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    potential_vulns = models.TextField(blank=True, null=True)  # This field type is a guess.
    mitigation = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(blank=True, null=True)
    product = models.TextField(blank=True, null=True)
    server = models.TextField(blank=True, null=True)
    tags = models.TextField(blank=True, null=True)  # This field type is a guess.
    domains = models.TextField(blank=True, null=True)  # This field type is a guess.
    hostnames = models.TextField(blank=True, null=True)  # This field type is a guess.
    isn = models.TextField(blank=True, null=True)
    asn = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'shodan_insecure_protocols_unverified_vulns'
        unique_together = (('organizations_uid', 'ip', 'port', 'protocol', 'timestamp'),)


class ShodanVerifiedVulns(models.Model):
    verified_vuln_uid = models.UUIDField(primary_key=True)
    organizations_uid = models.ForeignKey(Organizations, models.DO_NOTHING, db_column='organizations_uid')
    organization = models.TextField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(blank=True, null=True)
    cve = models.TextField(blank=True, null=True)
    severity = models.TextField(blank=True, null=True)
    cvss = models.DecimalField(max_digits=65535, decimal_places=65535, blank=True, null=True)
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

    class Meta:
        managed = False
        db_table = 'shodan_verified_vulns'
        unique_together = (('organizations_uid', 'ip', 'port', 'protocol', 'timestamp'),)


class SubDomains(models.Model):
    sub_domain_uid = models.UUIDField(primary_key=True)
    sub_domain = models.TextField()
    root_domain_uid = models.UUIDField()
    root_domain = models.TextField()

    class Meta:
        managed = False
        db_table = 'sub_domains'


class SubDomainsWebAssets(models.Model):
    sub_domain_uid = models.OneToOneField(SubDomains, models.DO_NOTHING, db_column='sub_domain_uid', primary_key=True)
    asset_uid = models.ForeignKey('WebAssets', models.DO_NOTHING, db_column='asset_uid')

    class Meta:
        managed = False
        db_table = 'sub_domains_web_assets'
        unique_together = (('sub_domain_uid', 'asset_uid'),)


class TopCves(models.Model):
    top_cves_uid = models.UUIDField(primary_key=True)
    cve_id = models.TextField(blank=True, null=True)
    dynamic_rating = models.TextField(blank=True, null=True)
    nvd_base_score = models.TextField(blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    summary = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'top_cves'
        unique_together = (('cve_id', 'date'),)


class UniqueSoftware(models.Model):
    field_id = models.UUIDField(db_column='_id', primary_key=True)  # Field renamed because it started with '_'.
    software_name = models.TextField()

    class Meta:
        managed = False
        db_table = 'unique_software'


class WebAssets(models.Model):
    asset_uid = models.UUIDField(primary_key=True)
    asset_type = models.TextField()
    asset = models.TextField(unique=True)
    ip_type = models.TextField(blank=True, null=True)
    verified = models.BooleanField(blank=True, null=True)
    organizations_uid = models.ForeignKey(Organizations, models.DO_NOTHING, db_column='organizations_uid')
    asset_origin = models.TextField(blank=True, null=True)
    report_on = models.BooleanField(blank=True, null=True)
    last_scanned = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'web_assets'
