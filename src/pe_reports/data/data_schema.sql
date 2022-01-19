-- PostgreSQL database dump
--

-- Draft Database Schema to store scan data
-- Includes Domain Masquerading, Credentals Exposed, Inffered Vulns, and Dark Web data


BEGIN;
-- Enable uuid extension in Postgres
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- Organization Assets --
-- Organization's Table
CREATE TABLE IF NOT EXISTS public.organizations
(
    organizations_uid uuid default uuid_generate_v1() NOT NULL,
    name text NOT NULL,
    cyhy_db_name text,
    UNIQUE(name),
    PRIMARY KEY (organizations_uid)
);

-- Organization's Root Domains Table
CREATE TABLE IF NOT EXISTS public.root_domains
(
    root_domain_uid uuid default uuid_generate_v1() NOT NULL,
    data_source_uid uuid NOT NULL,
    organizations_uid uuid NOT NULL,
    organization_name text NOT NULL,
    root_domain text NOT NULL,
    ip_address text,
    UNIQUE(root_domain, organizations_uid),
    PRIMARY KEY (root_domain_uid)
);

-- Organization's Sub Domains Table
CREATE TABLE IF NOT EXISTS public.sub_domains
(
    sub_domain_uid uuid default uuid_generate_v1() NOT NULL,
    data_source_uid uuid NOT NULL,
    sub_domain text NOT NULL,
    root_domain_uid uuid NOT NULL,
    root_domain text NOT NULL,
    UNIQUE(sub_domain, root_domain_uid),
    PRIMARY KEY (sub_domain_uid)
);

-- Organization's Sub Domains web_assets Link Table
CREATE TABLE IF NOT EXISTS Sub_domains_Web_assets
(
    sub_domain_uid uuid NOT NULL,
    asset_uid uuid NOT NULL,
    PRIMARY KEY (sub_domain_uid, asset_uid)
);

-- Organization's IPs Table
CREATE TABLE IF NOT EXISTS public.web_assets
(
    asset_uid uuid default uuid_generate_v1() NOT NULL,
    data_source_uid uuid NOT NULL,
    asset_type text Not NULL,
    asset text NOT NULL,
    ip_type text,
    verified boolean,
    organizations_uid uuid NOT NULL,
    asset_origin text,
    report_on boolean DEFAULT TRUE,
    last_scanned timestamp,
    UNIQUE(asset),
    PRIMARY KEY (asset_uid)
);

-- Organization's Aliases Table
CREATE TABLE IF NOT EXISTS public.alias
(
    alias_uid uuid default uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    alias text NOT NULL,
    UNIQUE (alias),
    PRIMARY KEY (alias_uid)
);

-- Organization's Evecutives Table
CREATE TABLE IF NOT EXISTS public.executives
(
    executives_uid uuid default uuid_generate_v1() NOT NULL,
    data_source_uid uuid NOT NULL,
    organizations_uid uuid NOT NULL,
    executives text NOT NULL,
    PRIMARY KEY (executives_uid)
);

-- Data source table Table
CREATE TABLE IF NOT EXISTS public.data_source
(
    data_source_uid uuid default uuid_generate_v1() NOT NULL,
    description text NOT NULL,
    last_run date NOT NULL,
    PRIMARY KEY (data_source_uid)
);

-- Reporting Tables ----
-- Domain Masquerading Table
CREATE TABLE IF NOT EXISTS public."domain_permutations"
(
    suspected_domain_uid uuid default uuid_generate_v1() NOT NULL,
    sub_domain_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    "domain_permutation" text,
    "ipv4" text,
    "ipv6" text,
    "mail_server" text,
    "name_server" text,
    fuzzer text,
    "date_observed" date,
    "ssdeep_score" text,
    "malicious" boolean,
    "blocklist_attack_count" integer,
    "blocklist_report_count" integer,
    UNIQUE ("domain_permutation"),
    PRIMARY KEY (suspected_domain_uid)
);

CREATE TABLE IF NOT EXISTS public."domain_alerts"
(
    domain_alert_uid uuid default uuid_generate_v1() NOT NULL,
    sub_domain_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    alert_type text,
    "message" text,
    previous_value text,
    new_value text,
    "date" date,
    UNIQUE (alert_type, sub_domain_uid, date, new_value),
    PRIMARY KEY (domain_alert_uid)
);

-- Dark Web Alerts Table
CREATE TABLE IF NOT EXISTS public.alerts
(
    alerts_uid uuid default uuid_generate_v1() NOT NULL,
    data_source_uid uuid NOT NULL,
    alert_name text,
    content text,
    date date,
    sixgill_id text,
    read text,
    severity text,
    site text,
    threat_level text,
    threats text,
    title text,
    user_id text,
    category text,
    lang text,
    UNIQUE (sixgill_id),
    organizations_uid uuid NOT NULL,
    PRIMARY KEY (alerts_uid)
);

-- Dark Web Mentions Table
CREATE TABLE IF NOT EXISTS public.mentions
(
    mentions_uid uuid default uuid_generate_v1() NOT NULL,
    data_source_uid uuid NOT NULL,
    category text,
    collection_date text,
    content text,
    creator text,
    date date,
    sixgill_mention_id text,
    post_id text,
    lang text,
    rep_grade text,
    site text,
    site_grade text,
    title text,
    type text,
    url text,
    comments_count text,
    sub_category text,
    tags text,
    UNIQUE (sixgill_mention_id),
    organizations_uid uuid NOT NULL,
    PRIMARY KEY (mentions_uid)
);

-- Insecure protocols and unverified vulnerabilities table
CREATE TABLE IF NOT EXISTS public.insecure_protocols_unverified_vulns
(
    insecure_product_uid uuid default uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    organization text,
    ip text,
    port integer,
    protocol text,
    type text,
    name text,
    potential_vulns text[],
    mitigation text,
    timestamp timestamp,
    product text,
    server text,
    tags text[],
    domains text[],
    hostnames text[],
    isn text,
    asn integer,
    UNIQUE (organizations_uid, ip, port, protocol, timestamp),
    PRIMARY KEY (insecure_product_uid)
);
--Veriried Vulnerabilities table
CREATE TABLE IF NOT EXISTS public.verified_vulns
(
    verified_vuln_uid uuid default uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    organization text,
    ip text,
    port text,
    protocol text,
    timestamp timestamp,
    cve text,
    severity text,
    cvss numeric,
    summary text,
    product text,
    attack_vector text,
    av_description text,
    attack_complexity text,
    ac_description text,
    confidentiality_impact text,
    ci_description text,
    integrity_impact text,
    ii_description text,
    availability_impact text,
    ai_description text,
    tags text[],
    domains text[],
    hostnames text[],
    isn text,
    asn integer,
    UNIQUE (organizations_uid, ip, port, protocol, timestamp),
    PRIMARY KEY (verified_vuln_uid)
);
--Shodan Assets and IPs table
CREATE TABLE IF NOT EXISTS public.shodan_assets
(
    shodan_asset_uid uuid default uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    organization text,
    ip text,
    port integer,
    protocol text,
    timestamp timestamp,
    product text,
    server text,
    tags text[],
    domains text[],
    hostnames text[],
    isn text,
    asn integer,
    UNIQUE (organizations_uid, ip, port, protocol, timestamp),
    PRIMARY KEY (shodan_asset_uid)
);

-- Breaches Table
CREATE TABLE IF NOT EXISTS public.credential_breaches
(
    credential_breaches_uid uuid default uuid_generate_v1() NOT NULL,
    breach_name text NOT NULL,
    data_source_uid uuid NOT NULL,
    description text,
    exposed_cred_count bigint,
    breach_date date,
    added_date timestamp without time zone,
    modified_date timestamp without time zone,
    data_classes text[],
    password_included boolean,
    is_verified boolean,
    is_fabricated boolean,
    is_sensitive boolean,
    is_retired boolean,
    is_spam_list boolean,
    UNIQUE (breach_name),
    PRIMARY KEY (credential_breaches_uid)
);

-- Credentials Table
CREATE TABLE IF NOT EXISTS public.credential_exposures
(
    credential_exposures_uid uuid default uuid_generate_v1() NOT NULL,
    data_source_uid uuid NOT NULL,
    email text NOT NULL,
    organizations_uid uuid NOT NULL,
    root_domain text,
    sub_domain text,
    breach_name text,
    modified_date timestamp without time zone,
	breach_id uuid NOT NULL,
    breach_date date,
    sixgill_breach_id integer,
    create_time timestamp without time zone,
    description text,
    password text,
    hash_type text,
    login_id text,
    name text,
    phone text,
    UNIQUE (email, breach_name),
    PRIMARY KEY (credential_exposures_uid)
);

-- Top CVEs
CREATE TABLE IF NOT EXISTS public.top_cves
(
    top_cves_uid uuid default uuid_generate_v1() NOT NULL,
    data_source_uid uuid NOT NULL,
    cve_id text,
    dynamic_rating text,
    nvd_base_score text,
    date date,
    summary text,
    UNIQUE (cve_id, date),
    PRIMARY KEY (top_cves_uid)
);

-- Table Relationships --
-- One to many relation between Organization and Root Domains
ALTER TABLE public.root_domains
 ADD FOREIGN KEY (organizations_uid)
 REFERENCES public.organizations (organizations_uid)
 NOT VALID;

 -- One to many relation between root domains and sub Domains
ALTER TABLE public.sub_domains
 ADD FOREIGN KEY (root_domain_uid)
 REFERENCES public.root_domains (root_domain_uid)
 NOT VALID;

 -- many to many relation between sub domains and IPs
ALTER TABLE public.Sub_domains_Web_assets
ADD FOREIGN KEY (sub_domain_uid)
 REFERENCES public.sub_domains (sub_domain_uid)
 NOT VALID,
ADD FOREIGN KEY (asset_uid)
 REFERENCES public.web_assets (asset_uid)
 NOT VALID;

-- One to many relation between orgs and web_assets
ALTER TABLE public.web_assets
 ADD FOREIGN KEY (organizations_uid)
 REFERENCES public.organizations (organizations_uid)
 NOT VALID;

-- One to many relation between sub_domain and domain permutations
ALTER TABLE public."domain_permutations"
 ADD FOREIGN KEY (sub_domain_uid)
 REFERENCES public.sub_domains (sub_domain_uid)
 NOT VALID;

-- One to many relation between sub_domains and domain alerts
ALTER TABLE public."domain_alerts"
 ADD FOREIGN KEY (sub_domain_uid)
 REFERENCES public.sub_domains (sub_domain_uid)
 NOT VALID;

-- One to many relation between Organization and Shodan Assets
ALTER TABLE public.shodan_assets
    ADD FOREIGN KEY (organizations_uid)
    REFERENCES public.organizations (organizations_uid)
    NOT VALID;

-- One to many relation between Organization and Unverified Vulns
ALTER TABLE public.insecure_protocols_unverified_vulns
    ADD FOREIGN KEY (organizations_uid)
    REFERENCES public.organizations (organizations_uid)
    NOT VALID;

-- One to many relation between Organization and Verified Vulns
ALTER TABLE public.verified_vulns
    ADD FOREIGN KEY (organizations_uid)
    REFERENCES public.organizations (organizations_uid)
    NOT VALID;

-- One to many relation between Breaches and Exposed Credentials
ALTER TABLE public.credential_exposures
    ADD FOREIGN KEY (breach_id)
    REFERENCES public.credential_breaches (credential_breaches_uid)
    NOT VALID;

-- One to many relation between Organization and Exposed Credentials
ALTER TABLE public.credential_exposures
    ADD FOREIGN KEY (organizations_uid)
    REFERENCES public.organizations (organizations_uid)
    NOT VALID;

-- One to many relation between Organization and Aliases
ALTER TABLE public.alias
    ADD FOREIGN KEY (organizations_uid)
    REFERENCES public.organizations (organizations_uid)
    NOT VALID;

-- One to many relation between Organization and Executives
ALTER TABLE public.executives
    ADD FOREIGN KEY (organizations_uid)
    REFERENCES public.organizations (organizations_uid)
    NOT VALID;

-- One to many relation between Organization and SixGill Alert API
ALTER TABLE public.alerts
    ADD FOREIGN KEY (organizations_uid)
    REFERENCES public.organizations (organizations_uid)
    NOT VALID;

-- One to many relationship with data_source and rest of the tables
ALTER TABLE public.domain_permutations
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.domain_alerts
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.alerts
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.mentions
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.insecure_protocols_unverified_vulns
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.verified_vulns
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.shodan_assets
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.credential_breaches
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.credential_exposures
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.top_cves
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.executives
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.alias
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.web_assets
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.sub_domains
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;
ALTER TABLE public.root_domains
    ADD FOREIGN KEY (data_source_uid)
    REFERENCES public.data_source (data_source_uid)
    NOT VALID;

-- One to Many Relationship for Mentions
-- Represented in complex SixGill "query": API.

-- Views --
-- HIBP complete breach view
Create View vw_breach_complete
AS
SELECT creds.credential_exposures_uid,creds.email, creds.breach_name, creds.organizations_uid, creds.root_domain, creds.sub_domain,
    b.description, b.breach_date, b.added_date, b.modified_date,  b.data_classes,
    b.password_included, b.is_verified, b.is_fabricated, b.is_sensitive, b.is_retired, b.is_spam_list

    FROM credential_exposures as creds

    JOIN credential_breaches as b
    ON creds.breach_id = b.credential_breaches_uid;

END;
