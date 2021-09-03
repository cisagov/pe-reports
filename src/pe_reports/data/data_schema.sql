--
-- PostgreSQL database dump
--

-- Draft Database Schema to store scan data
-- Includes Domain Masquerading, Credentals Exposed, Inffered Vulns, and Dark Web data

BEGIN;

-- Organizations table
CREATE TABLE IF NOT EXISTS public.organizations
(
    organization_id text NOT NULL,
    name text NOT NULL,
    root_domains text[],
    PRIMARY KEY (organization_id)
);

-- Domains table
CREATE TABLE IF NOT EXISTS public.domains
(
    domain_id text NOT NULL,
    organization_id text NOT NULL,
    root_domain text NOT NULL,
    ip_address text,
    PRIMARY KEY (domain_id)
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
