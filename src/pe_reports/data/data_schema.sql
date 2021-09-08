--
-- PostgreSQL database dump
--

-- Draft Database Schema to store scan data
-- Includes Domain Masquerading, Credentals Exposed, Inffered Vulns, and Dark Web data

BEGIN;
-- Organization Assets
-- Alias Table
CREATE TABLE IF NOT EXISTS public.alias
(
    alias_id text NOT NULL,
    organization_id text NOT NULL,
    alias text NOT NULL,
    PRIMARY KEY (alias_id)
);

-- Domains Table
CREATE TABLE IF NOT EXISTS public.domains
(
    domain_id text NOT NULL,
    organization_id text NOT NULL,
    root_domain text NOT NULL,
    ip_address text,
    PRIMARY KEY (domain_id)
);

-- Executives Table
CREATE TABLE IF NOT EXISTS public.executives
(
    executives_id text NOT NULL,
    organization_id text NOT NULL,
    executives text NOT NULL,
    PRIMARY KEY (executives_id)
);

-- Organizations Table
CREATE TABLE IF NOT EXISTS public.organizations
(
    organization_id text NOT NULL,
    name text NOT NULL,
    PRIMARY KEY (organization_id)
);

-- Report Data
-- Dark Web Alerts Table
CREATE TABLE IF NOT EXISTS public.alerts
(
    id text NOT NULL,
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
    organization_id text NOT NULL,
    PRIMARY KEY (id)
);

-- Domain Masquerading Table
CREATE TABLE IF NOT EXISTS public."DNSTwist"
(
    id text NOT NULL,
    "discoveredBy" text NOT NULL,
    "domain-name" text,
    "dns-a" text,
    "dns-aaaa" text,
    "dns-mx" text,
    "dns-ns" text,
    fuzzer text,
    "date-observed" text,
    "ssdeep-score" text,
    organization_id text NOT NULL,
    PRIMARY KEY (id)
);

-- Dark Web Forumns Table
CREATE TABLE IF NOT EXISTS public.forumns
(
    id text NOT NULL,
    friendly_name text,
    description text,
    site text NOT NULL,
    PRIMARY KEY (id)
);

-- Dark Web Mentions Table
CREATE TABLE IF NOT EXISTS public.mentions
(
    id text NOT NULL,
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
    organization_id text NOT NULL,
    PRIMARY KEY (id)
);

-- Dark Web Threats Table
CREATE TABLE IF NOT EXISTS public.dw_threats
(
    id text NOT NULL,
    threat text,
    description text,
    organization_id text NOT NULL,
    PRIMARY KEY (id)
);

-- Top CVEs Table
CREATE TABLE IF NOT EXISTS public.top_cves
(
    id text NOT NULL,
    type text,
    cve text,
    description text,
    PRIMARY KEY (id)
);


-- Database Relationships
-- One to many relation between Organization and Domains
ALTER TABLE public.domains
 ADD FOREIGN KEY (organization_id)
 REFERENCES public.organizations (organization_id)
 NOT VALID;

-- One to many relation between Organization and DNSTwist results
ALTER TABLE public."DNSTwist"
 ADD FOREIGN KEY (organization_id)
 REFERENCES public.organizations (organization_id)
 NOT VALID;

-- One to many relation between Domains and DNSTwist results
ALTER TABLE public."DNSTwist"
 ADD FOREIGN KEY ("discoveredBy")
 REFERENCES public.domains ("domain_id")
 NOT VALID;

-- HIBP breaches table
CREATE TABLE IF NOT EXISTS public.hibp_breaches
(
    breach_name text NOT NULL,
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
    PRIMARY KEY (breach_name)
);

-- HIBP exposed credentials table
CREATE TABLE IF NOT EXISTS public.hibp_exposed_credentials
(
    credential_id serial,
    email text NOT NULL,
    root_domain text,
    sub_domain text,
    breach_name text,
    UNIQUE (email, breach_name),
    PRIMARY KEY (credential_id)
);

ALTER TABLE public.hibp_exposed_credentials
    ADD FOREIGN KEY (breach_name)
    REFERENCES public.hibp_breaches (breach_name)
    NOT VALID;

-- HIBP complete breach view
Create View vw_breach_complete
AS
SELECT creds.credential_id,creds.email, creds.breach_name, creds.root_domain, creds.sub_domain,
    b.description, b.breach_date, b.added_date, b.modified_date,  b.data_classes,
    b.password_included, b.is_verified, b.is_fabricated, b.is_sensitive, b.is_retired, b.is_spam_list

    FROM hibp_exposed_credentials as creds

    JOIN hibp_breaches as b
    ON creds.breach_name = b.breach_name;


-- Cyber Six Gill exposed credentials table
CREATE TABLE IF NOT EXISTS public.cybersix_exposed_credentials
(
    credential_id serial,
    breach_date date,
    "breach_id " integer,
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
    PRIMARY KEY (credential_id)
);

END;
