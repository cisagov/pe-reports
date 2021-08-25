--
-- PostgreSQL database dump
--

-- Draft Database Schema to store scan data
-- Includes Domain Masquerading, Credentals Exposed, Inffered Vulns, and Dark Web data

-- Domain Masquerading Table
CREATE TABLE "DNSTwist" (
    "domain-name" character varying(200),
    "dns-a" character varying(100),
    "dns-aaaa" character varying(100)
    "dns-mx" text,
    "dns-ns" text,
    "fuzzer" text,
    "ssdeep-score" smallint,
    "date-observed" date not null,
);
