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
ALTER TABLE public.organizations
    ADD FOREIGN KEY (organization_id)
    REFERENCES public.domains (organization_id)
    NOT VALID;

-- One to many relation between Organization and DNSTwist results
ALTER TABLE public.organizations
    ADD FOREIGN KEY (organization_id)
    REFERENCES public."DNSTwist" (organization_id)
    NOT VALID;

-- One to many relation between Domains and DNSTwist results
ALTER TABLE public.domains
    ADD FOREIGN KEY (domain_id)
    REFERENCES public."DNSTwist" ("discoveredBy")
    NOT VALID;

-- One to many relation between Organization and Aliases
ALTER TABLE public.organizations
    ADD FOREIGN KEY (executives_id)
    REFERENCES public.executives (organization_id)
    NOT VALID;

-- One to many relation between Organization and Aliases
ALTER TABLE public.organization
    ADD FOREIGN KEY (organization_id)
    REFERENCES public.alias (organization_id)
    NOT VALID;

-- One to many relation between Mention "sites" and Forumns
ALTER TABLE public.mentions
    ADD FOREIGN KEY (site)
    REFERENCES public.forums (site)
    NOT VALID;

-- One to many relation between Mention "aliases" and Alias
ALTER TABLE public.alias
    ADD FOREIGN KEY (aliases)
    REFERENCES public.mentions (query)
    NOT VALID;

-- One to many relation between Organization and Alerts
ALTER TABLE public.organization
    ADD FOREIGN KEY (organization_id)
    REFERENCES public.alerts (organization_id)
    NOT VALID;

-- One to many relation between Alerts "threats" and Alerts
ALTER TABLE public.alerts
    ADD FOREIGN KEY (threats)
    REFERENCES public.threats (threat)
    NOT VALID;

END;
