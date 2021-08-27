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

END;
