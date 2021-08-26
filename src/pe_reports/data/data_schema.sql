--
-- PostgreSQL database dump
--

-- Draft Database Schema to store scan data
-- Includes Domain Masquerading, Credentals Exposed, Inffered Vulns, and Dark Web data

-- Domain Masquerading Table
CREATE TABLE IF NOT EXISTS pe_report."DNSTwist"
(
    id serial NOT NULL,
    original_domain text NOT NULL,
    dnstwist_domain text NOT NULL,
    "dns-a" character(100) NOT NULL,
    "dns-aaaa" character(100),
    "dns-mx" text,
    "dns-ns" text,
    fuzzer text NOT NULL,
    "ssdeep-score" smallint,
    "date-observed" date NOT NULL,
    PRIMARY KEY (id)
);
