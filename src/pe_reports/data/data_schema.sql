--
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
    root_domains text[],
    PRIMARY KEY (organizations_uid)
);

-- Organization's Domains Table
CREATE TABLE IF NOT EXISTS public.domains
(
    domain_uid uuid default uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    root_domain text NOT NULL,
    ip_address text,
    PRIMARY KEY (domain_uid)
);

-- Organization's Aliases Table
CREATE TABLE IF NOT EXISTS public.alias
(
    alias_uid uuid default uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    alias text NOT NULL,
    PRIMARY KEY (alias_uid)
);

-- Organization's Evecutives Table
CREATE TABLE IF NOT EXISTS public.executives
(
    executives_uid uuid default uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    executives text NOT NULL,
    PRIMARY KEY (executives_uid)
);


-- Reporting Tables ----
-- Domain Masquerading Table
CREATE TABLE IF NOT EXISTS public."DNSTwist"
(
    dnstwist_uid uuid default uuid_generate_v1() NOT NULL,
    "discoveredBy" uuid NOT NULL,
    "domain-name" text,
    "dns-a" text,
    "dns-aaaa" text,
    "dns-mx" text,
    "dns-ns" text,
    fuzzer text,
    "date-observed" text,
    "ssdeep-score" text,
    organizations_uid uuid NOT NULL,
    PRIMARY KEY (dnstwist_uid)
);

-- Dark Web Alerts Table
CREATE TABLE public.alerts
(
    alerts_uid uuid default uuid_generate_v1() NOT NULL,
    alert_name text,
    content text,
    date text,
    sixgill_id text,
    read text,
    severity text,
    site text,
    threat_level text,
    threats text,
    title text,
    user_id text,
    organizations_uid uuid NOT NULL,
    PRIMARY KEY (alerts_uid)
);

-- Dark Web Mentions Table
CREATE TABLE public.mentions
(
    mentions_uid uuid default uuid_generate_v1() NOT NULL,
    category text,
    collection_date text,
    content text,
    creator text,
    date text,
    post_id text,
    rep_grade text,
    site text,
    site_grade text,
    title text,
    type text,
    url text,
    tags text,
    comments_count text,
    sub_category text,
    query text,
    organizations_uid uuid NOT NULL,
    PRIMARY KEY (mentions_uid)
);

-- HIBP breaches Table
CREATE TABLE IF NOT EXISTS public.hibp_breaches
(
    hibp_breaches_uid uuid default uuid_generate_v1() NOT NULL,
    breach_id uuid NOT NULL,
    description text,
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
    PRIMARY KEY (hibp_breaches_uid)
);

-- HIBP Exposed Credentials Table
CREATE TABLE IF NOT EXISTS public.hibp_exposed_credentials
(
    hibp_exposed_credentials_uid uuid default uuid_generate_v1() NOT NULL,
    email text NOT NULL,
    organization text,
    root_domain text,
    sub_domain text,
    breach_name text,
	breach_id uuid NOT NULL,
    UNIQUE (email, breach_name),
    PRIMARY KEY (hibp_exposed_credentials_uid)
);

-- Cyber Six Gill Exposed Credentials Table
CREATE TABLE IF NOT EXISTS public.cybersix_exposed_credentials
(
    csg_exposed_credentials_uid uuid default uuid_generate_v1() NOT NULL,
    breach_date date,
    breach_id integer,
    breach_name text NOT NULL,
    create_time timestamp without time zone[],
    description text,
    domain text,
    email text NOT NULL,
    password text,
    hash_type text,
    login_id text,
    name text,
    phone text,
    PRIMARY KEY (csg_exposed_credentials_uid)
);

-- Top CVEs
CREATE TABLE public.top_cves
(
   top_cves_uid uuid default uuid_generate_v1() NOT NULL,
    type text,
    cve text,
    description text,
    PRIMARY KEY (top_cves_uid)
);

-- Table Relationships --
-- One to many relation between Organization and Domains
ALTER TABLE public.domains
 ADD FOREIGN KEY (organizations_uid)
 REFERENCES public.organizations (organizations_uid)
 NOT VALID;

-- One to many relation between Organization and DNSTwist results
ALTER TABLE public."DNSTwist"
 ADD FOREIGN KEY (organizations_uid)
 REFERENCES public.organizations (organizations_uid)
 NOT VALID;

-- One to many relation between Domains and DNSTwist results
ALTER TABLE public."DNSTwist"
 ADD FOREIGN KEY ("discoveredBy")
 REFERENCES public.domains ("domain_uid")
 NOT VALID;

-- One to many relation between Organization and Domains
ALTER TABLE public.hibp_exposed_credentials
    ADD FOREIGN KEY (breach_id)
    REFERENCES public.hibp_breaches (hibp_breaches_uid)
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

-- One to Many Relationship for Mentions
-- Represented in complex SixGill "query": API.

-- Views --
-- HIBP complete breach view
Create View vw_breach_complete
AS
SELECT creds.hibp_exposed_credentials_uid,creds.email, creds.breach_name, creds.organization, creds.root_domain, creds.sub_domain,
    b.description, b.breach_date, b.added_date, b.modified_date,  b.data_classes,
    b.password_included, b.is_verified, b.is_fabricated, b.is_sensitive, b.is_retired, b.is_spam_list

    FROM hibp_exposed_credentials as creds

    JOIN hibp_breaches as b
    ON creds.breach_id = b.breach_id;

END;
