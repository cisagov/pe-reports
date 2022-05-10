--
-- PostgreSQL database dump
--
-- Current P&E Database schema as of March 8th, 2022
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';

--
-- Name: Users; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public."Users" (
    id uuid NOT NULL,
    email character varying(64),
    username character varying(64),
    admin integer,
    role integer,
    password_hash character varying(128),
    api_key character varying(128)
);

--
-- Name: alerts; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.alerts (
    alerts_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
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
    organizations_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL
);


--
-- Name: alias; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.alias (
    alias_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    alias text NOT NULL
);


--
-- Name: asset_headers; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.asset_headers (
    _id uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    sub_url text NOT NULL,
    tech_detected text[] NOT NULL,
    interesting_header text[] NOT NULL,
    ssl2 text[],
    tls1 text[],
    certificate json,
    scanned boolean,
    ssl_scanned boolean
);

--
-- Name: credential_breaches; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.credential_breaches (
    credential_breaches_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    breach_name text NOT NULL,
    description text,
    exposed_cred_count bigint,
    breach_date date,
    added_date timestamp,
    modified_date timestamp,
    data_classes text[],
    password_included boolean,
    is_verified boolean,
    is_fabricated boolean,
    is_sensitive boolean,
    is_retired boolean,
    is_spam_list boolean,
    data_source_uid uuid NOT NULL
);

--
-- Name: credential_exposures; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.credential_exposures (
    credential_exposures_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    email text NOT NULL,
    organizations_uid uuid NOT NULL,
    root_domain text,
    sub_domain text,
    breach_name text,
    modified_date timestamp,
    credential_breaches_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    name text,
    login_id text,
    phone text,
    password text,
    hash_type text
);

--
-- Name: cybersix_exposed_credentials; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.cybersix_exposed_credentials (
    csg_exposed_credentials_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    breach_date date,
    breach_id integer,
    breach_name text NOT NULL,
    create_time timestamp,
    description text,
    domain text,
    email text NOT NULL,
    password text,
    hash_type text,
    login_id text,
    name text,
    phone text,
    data_source_uid uuid NOT NULL
);

--
-- Name: cyhy_db_assets; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.cyhy_db_assets (
    _id uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    org_id text,
    org_name text,
    contact text,
    network inet,
    type text
);

--
-- Name: data_source; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.data_source (
    data_source_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    last_run date NOT NULL
);

--
-- Name: domain_alerts; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.domain_alerts (
    domain_alert_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    sub_domain_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    organizations_uid uuid NOT NULL,
    alert_type text,
    message text,
    previous_value text,
    new_value text,
    date date
);

--
-- Name: domain_permutations; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.domain_permutations (
    suspected_domain_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    domain_permutation text,
    ipv4 text,
    ipv6 text,
    mail_server text,
    name_server text,
    fuzzer text,
    date_observed date,
    ssdeep_score text,
    malicious boolean,
    blocklist_attack_count integer,
    blocklist_report_count integer,
    data_source_uid uuid NOT NULL,
    sub_domain_uid uuid
);

--
-- Name: executives; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.executives (
    executives_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    executives text NOT NULL
);

--
-- Name: mentions; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.mentions (
    mentions_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
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
    organizations_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL
);

--
-- Name: organizations; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.organizations (
    organizations_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    name text NOT NULL,
    cyhy_db_name text,
    org_type_uid uuid NOT NULL;
);

--
-- Name: org_type; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE org_type (
org_type_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
org_type text
)

--
-- Name: pshtt_results; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.pshtt_results (
    pshtt_results_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    sub_domain_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    sub_domain text NOT NULL,
    scanned boolean,
    base_domain text,
    base_domain_hsts_preloaded boolean,
    canonical_url text,
    defaults_to_https boolean,
    domain text,
    domain_enforces_https boolean,
    domain_supports_https boolean,
    domain_uses_strong_hsts boolean,
    downgrades_https boolean,
    htss boolean,
    hsts_entire_domain boolean,
    hsts_header text,
    hsts_max_age numeric,
    hsts_preload_pending boolean,
    hsts_preload_ready boolean,
    hsts_preloaded boolean,
    https_bad_chain boolean,
    https_bad_hostname boolean,
    https_cert_chain_length integer,
    https_client_auth_required boolean,
    https_custom_truststore_trusted boolean,
    https_expired_cert boolean,
    https_full_connection boolean,
    https_live boolean,
    https_probably_missing_intermediate_cert boolean,
    https_publicly_trusted boolean,
    https_self_signed_cert boolean,
    ip inet,
    live boolean,
    notes text,
    redirect boolean,
    redirect_to text,
    server_header text,
    server_version text,
    strictly_forces_https boolean,
    unknown_error boolean,
    valid_https boolean,
    ep_http_headers json,
    ep_http_ip inet,
    ep_http_live boolean,
    ep_http_notes text,
    ep_http_redirect boolean,
    ep_http_redirect_eventually_to text,
    ep_http_redirect_eventually_to_external boolean,
    ep_http_redirect_eventually_to_http boolean,
    ep_http_redirect_eventually_to_https boolean,
    ep_http_redirect_eventually_to_subdomain boolean,
    ep_http_redirect_immediately_to text,
    ep_http_redirect_immediately_to_external boolean,
    ep_http_redirect_immediately_to_http boolean,
    ep_http_redirect_immediately_to_https boolean,
    ep_http_redirect_immediately_to_subdomain boolean,
    ep_http_redirect_immediately_to_www boolean,
    ep_http_server_header text,
    ep_http_server_version text,
    ep_http_status integer,
    ep_http_unknown_error boolean,
    ep_http_url text,
    ep_https_headers json,
    ep_https_hsts boolean,
    ep_https_hsts_all_subdomains boolean,
    ep_https_hsts_header text,
    ep_https_hsts_max_age numeric,
    ep_https_hsts_preload boolean,
    ep_https_https_bad_chain boolean,
    ep_https_https_bad_hostname boolean,
    ep_https_https_cert_chain_len integer,
    ep_https_https_client_auth_required boolean,
    ep_https_https_custom_trusted boolean,
    ep_https_https_expired_cert boolean,
    ep_https_https_vull_connection boolean,
    ep_https_https_missing_intermediate_cert boolean,
    ep_https_https_public_trusted boolean,
    ep_https_https_self_signed_cert boolean,
    ep_https_https_valid boolean,
    ep_https_ip inet,
    ep_https_live boolean,
    ep_https_notes text,
    ep_https_redirect boolean,
    ep_https_redireect_eventually_to text,
    ep_https_redirect_eventually_to_external boolean,
    ep_https_redirect_eventually_to_http boolean,
    ep_https_redirect_eventually_to_https boolean,
    ep_https_redirect_eventually_to_subdomain boolean,
    ep_https_redirect_immediately_to text,
    ep_https_redirect_immediately_to_external boolean,
    ep_https_redirect_immediately_to_http boolean,
    ep_https_redirect_immediately_to_https boolean,
    ep_https_redirect_immediately_to_subdomain boolean,
    ep_https_redirect_immediately_to_www boolean,
    ep_https_server_header text,
    ep_https_server_version text,
    ep_https_status integer,
    ep_https_unknown_error boolean,
    ep_https_url text,
    ep_httpswww_headers json,
    ep_httpswww_hsts boolean,
    ep_httpswww_hsts_all_subdomains boolean,
    ep_httpswww_hsts_header text,
    ep_httpswww_hsts_max_age numeric,
    ep_httpswww_hsts_preload boolean,
    ep_httpswww_https_bad_chain boolean,
    ep_httpswww_https_bad_hostname boolean,
    ep_httpswww_https_cert_chain_len integer,
    ep_httpswww_https_client_auth_required boolean,
    ep_httpswww_https_custom_trusted boolean,
    ep_httpswww_https_expired_cert boolean,
    ep_httpswww_https_full_connection boolean,
    ep_httpswww_https_missing_intermediate_cert boolean,
    ep_httpswww_https_public_trusted boolean,
    ep_httpswww_https_self_signed_cert boolean,
    ep_httpswww_https_valid boolean,
    ep_httpswww_ip inet,
    ep_httpswww_live boolean,
    ep_httpswww_notes text,
    ep_httpswww_redirect boolean,
    ep_httpswww_redirect_eventually_to text,
    ep_httpswww_redirect_eventually_to_external boolean,
    ep_httpswww_redirect_eventually_to_http boolean,
    ep_httpswww_redirect_eventually_to_https boolean,
    ep_httpswww_redirect_eventually_to_subdomain boolean,
    ep_httpswww_redirect_immediately_to text,
    ep_httpswww_redirect_immediately_to_external boolean,
    ep_httpswww_redirect_immediately_to_http boolean,
    ep_httpswww_redirect_immediately_to_https boolean,
    ep_httpswww_redirect_immediately_to_subdomain boolean,
    ep_httpswww_redirect_immediately_to_www boolean,
    ep_httpswww_server_header text,
    ep_httpswww_server_version text,
    ep_httpswww_status integer,
    ep_httpswww_unknown_error boolean,
    ep_httpswww_url text,
    ep_httpwww_headers json,
    ep_httpwww_ip inet,
    ep_httpwww_live boolean,
    ep_httpwww_notes text,
    ep_httpwww_redirect boolean,
    ep_httpwww_redirect_eventually_to text,
    ep_httpwww_redirect_eventually_to_external boolean,
    ep_httpwww_redirect_eventually_to_http boolean,
    ep_httpwww_redirect_eventually_to_https boolean,
    ep_httpwww_redirect_eventually_to_subdomain boolean,
    ep_httpwww_redirect_immediately_to text,
    ep_httpwww_redirect_immediately_to_external boolean,
    ep_httpwww_redirect_immediately_to_http boolean,
    ep_httpwww_redirect_immediately_to_https boolean,
    ep_httpwww_redirect_immediately_to_subdomain boolean,
    ep_httpwww_redirect_immediately_to_www boolean,
    ep_httpwww_server_header text,
    ep_httpwww_server_version text,
    ep_httpwww_status integer,
    ep_httpwww_unknown_error boolean,
    ep_httpwww_url text
);

--
-- Name: root_domains; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.root_domains (
    root_domain_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    organization_name text NOT NULL,
    root_domain text NOT NULL,
    ip_address text,
    data_source_uid uuid NOT NULL
);

--
-- Name: shodan_assets; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.shodan_assets (
    shodan_asset_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    organization text,
    ip text,
    port integer,
    protocol text,
    "timestamp" timestamp,
    product text,
    server text,
    tags text[],
    domains text[],
    hostnames text[],
    isn text,
    asn integer,
    data_source_uid uuid NOT NULL
);

--
-- Name: shodan_insecure_protocols_unverified_vulns; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.shodan_insecure_protocols_unverified_vulns (
    insecure_product_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    organization text,
    ip text,
    port integer,
    protocol text,
    type text,
    name text,
    potential_vulns text[],
    mitigation text,
    "timestamp" timestamp,
    product text,
    server text,
    tags text[],
    domains text[],
    hostnames text[],
    isn text,
    asn integer,
    data_source_uid uuid NOT NULL
);

--
-- Name: shodan_vulns; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.shodan_vulns (
    shodan_vuln_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    organization text,
    ip text,
    port text,
    protocol text,
    event_time timestamp,
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
    data_source_uid uuid NOT NULL,
    type text,
    name text,
    potential_vulns text[],
    mitigation text,
    server text,
    is_verified boolean
);

--
-- Name: sub_domains; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.sub_domains (
    sub_domain_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    sub_domain text NOT NULL,
    root_domain_uid uuid NOT NULL,
    root_domain text NOT NULL,
    data_source_uid uuid NOT NULL
);

--
-- Name: sub_domains_web_assets; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.sub_domains_web_assets (
    sub_domain_uid uuid NOT NULL,
    asset_uid uuid NOT NULL
);

--
-- Name: top_cves; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.top_cves (
    top_cves_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    cve_id text,
    dynamic_rating text,
    nvd_base_score text,
    date date,
    summary text,
    data_source_uid uuid NOT NULL
);

--
-- Name: unique_software; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.unique_software (
    _id uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    software_name text NOT NULL
);

--
-- Name: web_assets; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.web_assets (
    asset_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    asset_type text NOT NULL,
    asset text NOT NULL,
    ip_type text,
    verified boolean,
    organizations_uid uuid NOT NULL,
    asset_origin text,
    report_on boolean DEFAULT true,
    last_scanned timestamp,
    report_status_reason text,
    data_source_uid uuid NOT NULL
);

ALTER TABLE public.web_assets OWNER TO pe;

--
-- Name: Users Users_api_key_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public."Users"
    ADD CONSTRAINT "Users_api_key_key" UNIQUE (api_key);


--
-- Name: Users Users_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public."Users"
    ADD CONSTRAINT "Users_pkey" PRIMARY KEY (id);


--
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (alerts_uid);


--
-- Name: alerts alerts_sixgill_id_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_sixgill_id_key UNIQUE (sixgill_id);


--
-- Name: alias alias_alias_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.alias
    ADD CONSTRAINT alias_alias_key UNIQUE (alias);


--
-- Name: alias alias_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.alias
    ADD CONSTRAINT alias_pkey PRIMARY KEY (alias_uid);


--
-- Name: asset_headers asset_headers_organizations_uid_sub_url_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.asset_headers
    ADD CONSTRAINT asset_headers_organizations_uid_sub_url_key UNIQUE (organizations_uid, sub_url);


--
-- Name: asset_headers asset_headers_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.asset_headers
    ADD CONSTRAINT asset_headers_pkey PRIMARY KEY (_id);


--
-- Name: credential_exposures credential_exposure_unique_constraint; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.credential_exposures
    ADD CONSTRAINT credential_exposure_unique_constraint UNIQUE (breach_name, email, name);


--
-- Name: cybersix_exposed_credentials cybersix_exposed_credentials_email_breach_id_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cybersix_exposed_credentials
    ADD CONSTRAINT cybersix_exposed_credentials_email_breach_id_key UNIQUE (email, breach_id);


--
-- Name: cybersix_exposed_credentials cybersix_exposed_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cybersix_exposed_credentials
    ADD CONSTRAINT cybersix_exposed_credentials_pkey PRIMARY KEY (csg_exposed_credentials_uid);


--
-- Name: cyhy_db_assets cyhy_db_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cyhy_db_assets
    ADD CONSTRAINT cyhy_db_assets_pkey PRIMARY KEY (_id);


--
-- Name: data_source data_source_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.data_source
    ADD CONSTRAINT data_source_pkey PRIMARY KEY (data_source_uid);


--
-- Name: domain_alerts domain_alerts_alert_type_sub_domain_uid_date_new_value_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.domain_alerts
    ADD CONSTRAINT domain_alerts_alert_type_sub_domain_uid_date_new_value_key UNIQUE (alert_type, sub_domain_uid, date, new_value);


--
-- Name: domain_alerts domain_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.domain_alerts
    ADD CONSTRAINT domain_alerts_pkey PRIMARY KEY (domain_alert_uid);


--
-- Name: domain_permutations domain_permutations_domain_permutation_organizations_uid_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.domain_permutations
    ADD CONSTRAINT domain_permutations_domain_permutation_organizations_uid_key UNIQUE (domain_permutation, organizations_uid);


--
-- Name: executives executives_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.executives
    ADD CONSTRAINT executives_pkey PRIMARY KEY (executives_uid);


--
-- Name: credential_breaches hibp_breaches_breach_name_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.credential_breaches
    ADD CONSTRAINT hibp_breaches_breach_name_key UNIQUE (breach_name);


--
-- Name: credential_breaches hibp_breaches_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.credential_breaches
    ADD CONSTRAINT hibp_breaches_pkey PRIMARY KEY (credential_breaches_uid);


--
-- Name: credential_exposures hibp_exposed_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.credential_exposures
    ADD CONSTRAINT hibp_exposed_credentials_pkey PRIMARY KEY (credential_exposures_uid);


--
-- Name: mentions mentions_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.mentions
    ADD CONSTRAINT mentions_pkey PRIMARY KEY (mentions_uid);


--
-- Name: mentions mentions_sixgill_mention_id_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.mentions
    ADD CONSTRAINT mentions_sixgill_mention_id_key UNIQUE (sixgill_mention_id);


--
-- Name: organizations organizations_name_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_name_key UNIQUE (name);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (organizations_uid);

--
-- Name: organizations organizations_org_type_uid_fkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_org_type_uid_fkey FOREIGN KEY (org_type_uid) REFERENCES public.org_type(org_type_uid) NOT VALID;

--
-- Name: organizations org_type_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--
ALTER TABLE ONLY public.org_type
    ADD CONSTRAINT org_type_pkey PRIMARY KEY (org_type_uid);

--
-- Name: pshtt_results pshtt_results_organizations_uid_sub_domain_uid_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.pshtt_results
    ADD CONSTRAINT pshtt_results_organizations_uid_sub_domain_uid_key UNIQUE (organizations_uid, sub_domain_uid);


--
-- Name: pshtt_results pshtt_results_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.pshtt_results
    ADD CONSTRAINT pshtt_results_pkey PRIMARY KEY (pshtt_results_uid);


--
-- Name: root_domains root_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.root_domains
    ADD CONSTRAINT root_domains_pkey PRIMARY KEY (root_domain_uid);


--
-- Name: root_domains root_domains_root_domain_organizations_uid_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.root_domains
    ADD CONSTRAINT root_domains_root_domain_organizations_uid_key UNIQUE (root_domain, organizations_uid);


--
-- Name: shodan_assets shodan_assets_organizations_uid_ip_port_protocol_timestamp_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_assets
    ADD CONSTRAINT shodan_assets_organizations_uid_ip_port_protocol_timestamp_key UNIQUE (organizations_uid, ip, port, protocol, "timestamp");


--
-- Name: shodan_assets shodan_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_assets
    ADD CONSTRAINT shodan_assets_pkey PRIMARY KEY (shodan_asset_uid);


--
-- Name: shodan_insecure_protocols_unverified_vulns shodan_insecure_protocols_unv_organizations_uid_ip_port_pro_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_insecure_protocols_unverified_vulns
    ADD CONSTRAINT shodan_insecure_protocols_unv_organizations_uid_ip_port_pro_key UNIQUE (organizations_uid, ip, port, protocol, "timestamp");


--
-- Name: shodan_insecure_protocols_unverified_vulns shodan_insecure_protocols_unverified_vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_insecure_protocols_unverified_vulns
    ADD CONSTRAINT shodan_insecure_protocols_unverified_vulns_pkey PRIMARY KEY (insecure_product_uid);


--
-- Name: shodan_vulns shodan_vulns_organizations_uid_ip_port_protocol_ti_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_vulns
    ADD CONSTRAINT shodan_vulns_organizations_uid_ip_port_protocol_ti_key UNIQUE (organizations_uid, ip, port, protocol, "timestamp");


--
-- Name: shodan_vulns shodan_vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_vulns
    ADD CONSTRAINT shodan_vulns_pkey PRIMARY KEY (shodan_vuln_uid);


--
-- Name: sub_domains sub_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_pkey PRIMARY KEY (sub_domain_uid);


--
-- Name: sub_domains sub_domains_sub_domain_root_domain_uid_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_sub_domain_root_domain_uid_key UNIQUE (sub_domain, root_domain_uid);


--
-- Name: sub_domains_web_assets sub_domains_web_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains_web_assets
    ADD CONSTRAINT sub_domains_web_assets_pkey PRIMARY KEY (sub_domain_uid, asset_uid);


--
-- Name: top_cves top_cves_cve_id_date_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.top_cves
    ADD CONSTRAINT top_cves_cve_id_date_key UNIQUE (cve_id, date);


--
-- Name: top_cves top_cves_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.top_cves
    ADD CONSTRAINT top_cves_pkey PRIMARY KEY (top_cves_uid);


--
-- Name: unique_software unique_software_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.unique_software
    ADD CONSTRAINT unique_software_pkey PRIMARY KEY (_id);


--
-- Name: web_assets web_assets_asset_organizations_uid_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.web_assets
    ADD CONSTRAINT web_assets_asset_organizations_uid_key UNIQUE (asset, organizations_uid);


--
-- Name: web_assets web_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.web_assets
    ADD CONSTRAINT web_assets_pkey PRIMARY KEY (asset_uid);


--
-- Name: ix_Users_email; Type: INDEX; Schema: public; Owner: pe
--

CREATE UNIQUE INDEX "ix_Users_email" ON public."Users" USING btree (email);


--
-- Name: ix_Users_username; Type: INDEX; Schema: public; Owner: pe
--

CREATE UNIQUE INDEX "ix_Users_username" ON public."Users" USING btree (username);


--
-- Name: alerts alerts_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: alerts alerts_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: alias alias_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.alias
    ADD CONSTRAINT alias_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: credential_breaches credential_breaches_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.credential_breaches
    ADD CONSTRAINT credential_breaches_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: credential_exposures credential_exposures_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.credential_exposures
    ADD CONSTRAINT credential_exposures_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: cybersix_exposed_credentials cybersix_exposed_credentials_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cybersix_exposed_credentials
    ADD CONSTRAINT cybersix_exposed_credentials_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: domain_permutations dnstwist_domain_masq_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.domain_permutations
    ADD CONSTRAINT dnstwist_domain_masq_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: domain_alerts domain_alerts_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.domain_alerts
    ADD CONSTRAINT domain_alerts_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: domain_alerts domain_alerts_sub_domain_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.domain_alerts
    ADD CONSTRAINT domain_alerts_sub_domain_uid_fkey FOREIGN KEY (sub_domain_uid) REFERENCES public.sub_domains(sub_domain_uid) NOT VALID;


--
-- Name: domain_permutations domain_permutations_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.domain_permutations
    ADD CONSTRAINT domain_permutations_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: domain_permutations domain_permutations_sub_domain_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.domain_permutations
    ADD CONSTRAINT domain_permutations_sub_domain_uid_fkey FOREIGN KEY (sub_domain_uid) REFERENCES public.sub_domains(sub_domain_uid) NOT VALID;


--
-- Name: executives executives_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.executives
    ADD CONSTRAINT executives_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: credential_exposures hibp_exposed_credentials_breach_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.credential_exposures
    ADD CONSTRAINT hibp_exposed_credentials_breach_id_fkey FOREIGN KEY (credential_breaches_uid) REFERENCES public.credential_breaches(credential_breaches_uid) NOT VALID;


--
-- Name: credential_exposures hibp_exposed_credentials_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.credential_exposures
    ADD CONSTRAINT hibp_exposed_credentials_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: mentions mentions_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.mentions
    ADD CONSTRAINT mentions_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: pshtt_results pshtt_results_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.pshtt_results
    ADD CONSTRAINT pshtt_results_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: pshtt_results pshtt_results_sub_domain_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.pshtt_results
    ADD CONSTRAINT pshtt_results_sub_domain_uid_fkey FOREIGN KEY (sub_domain_uid) REFERENCES public.sub_domains(sub_domain_uid) NOT VALID;


--
-- Name: root_domains root_domains_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.root_domains
    ADD CONSTRAINT root_domains_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: root_domains root_domains_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.root_domains
    ADD CONSTRAINT root_domains_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: shodan_assets shodan_assets_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_assets
    ADD CONSTRAINT shodan_assets_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: shodan_assets shodan_assets_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_assets
    ADD CONSTRAINT shodan_assets_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: shodan_insecure_protocols_unverified_vulns shodan_insecure_protocols_unverified_vul_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_insecure_protocols_unverified_vulns
    ADD CONSTRAINT shodan_insecure_protocols_unverified_vul_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: shodan_insecure_protocols_unverified_vulns shodan_insecure_protocols_unverified_vulns_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_insecure_protocols_unverified_vulns
    ADD CONSTRAINT shodan_insecure_protocols_unverified_vulns_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: shodan_vulns shodan_vulns_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_vulns
    ADD CONSTRAINT shodan_vulns_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: shodan_vulns shodan_vulns_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_vulns
    ADD CONSTRAINT shodan_vulns_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: sub_domains sub_domains_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: sub_domains sub_domains_root_domain_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_root_domain_uid_fkey FOREIGN KEY (root_domain_uid) REFERENCES public.root_domains(root_domain_uid) NOT VALID;


--
-- Name: sub_domains_web_assets sub_domains_web_assets_asset_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains_web_assets
    ADD CONSTRAINT sub_domains_web_assets_asset_uid_fkey FOREIGN KEY (asset_uid) REFERENCES public.web_assets(asset_uid) NOT VALID;


--
-- Name: sub_domains_web_assets sub_domains_web_assets_sub_domain_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains_web_assets
    ADD CONSTRAINT sub_domains_web_assets_sub_domain_uid_fkey FOREIGN KEY (sub_domain_uid) REFERENCES public.sub_domains(sub_domain_uid) NOT VALID;


--
-- Name: top_cves top_cves_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.top_cves
    ADD CONSTRAINT top_cves_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: web_assets web_assets_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.web_assets
    ADD CONSTRAINT web_assets_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: web_assets web_assets_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.web_assets
    ADD CONSTRAINT web_assets_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: new_breachcomp; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_breachcomp AS
    SELECT creds.credential_exposures_uid,
    creds.email,
    creds.breach_name,
    creds.organizations_uid,
    creds.root_domain,
    creds.sub_domain,
    creds.hash_type,
    creds.name,
    creds.login_id,
    creds.password,
    creds.phone,
    creds.data_source_uid,
    b.description,
    b.breach_date,
    b.added_date,
    b.modified_date,
    b.data_classes,
    b.password_included,
    b.is_verified,
    b.is_fabricated,
    b.is_sensitive,
    b.is_retired,
    b.is_spam_list
    FROM (public.credential_exposures creds
        JOIN public.credential_breaches b ON ((creds.credential_breaches_uid = b.credential_breaches_uid)));

--
-- Name: vw_breachcomp_credsbydate; Type: VIEW; Schema: public; Owner: pe
--
CREATE VIEW vw_breachcomp_credsbydate AS
SELECT
organizations_uid,
DATE(modified_date) mod_date,
SUM(CASE password_included WHEN false THEN 1 ELSE 0 END) AS no_password,
SUM(CASE password_included WHEN True THEN 1 ELSE 0 END) AS password_included
FROM vw_breachcomp
GROUP BY organizations_uid,
mod_date
ORDER BY mod_date DESC

--
-- Name: vw_breachcomp_breachdetails; Type: VIEW; Schema: public; Owner: pe
--
CREATE VIEW vw_breachcomp_breachdetails as
SELECT
vb.organizations_uid,
vb.breach_name,
DATE(vb.modified_date) mod_date,
vb.description,
vb.breach_date,
vb.password_included,
COUNT(vb.email) number_of_creds
FROM
vw_breachcomp vb
GROUP BY
vb.organizations_uid,
vb.breach_name,
mod_date,
vb.description,
vb.breach_date,
vb.password_included
ORDER BY mod_date DESC

--
-- Name: vw_shodanvulns_suspected; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_shodanvulns_suspected AS
	SELECT
    sv.organizations_uid,
    sv.organization,
    sv.ip,
    sv.port,
    sv.protocol,
    sv.type,
    sv."name",
    sv.potential_vulns,
	sv.mitigation,
    sv."timestamp",
    sv.product,
    sv."server",
    sv.tags,
    sv.domains,
    sv.hostnames,
    sv.isn,
    sv.asn,
    ds."name" as "data_source"
	FROM shodan_vulns sv
	    JOIN data_source ds
	ON ds.data_source_uid = sv.data_source_uid
	WHERE is_verified = false

--
-- Name: vw_shodanvulns_verified; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_shodanvulns_verified AS
	SELECT
    sv.organizations_uid,
    sv.organization,
    sv.ip,
    sv.port,
    sv.protocol,
    sv."timestamp",
    sv.cve,
    sv.severity,
    sv.cvss,
	sv.summary,
    sv.product,
    sv.attack_vector,
    sv.av_description ,
    sv.attack_complexity,
    sv.ac_description,
    sv.confidentiality_impact,
    sv.ci_description,
	sv.integrity_impact,
    sv.ii_description,
    sv.availability_impact,
    sv.ai_description,
    sv.tags,
    sv.domains,
    sv.hostnames,
    sv.isn,
    sv.asn,
    ds."name" as "data_source"
	FROM shodan_vulns sv
	    JOIN data_source as ds
	ON ds.data_source_uid = sv.data_source_uid
	WHERE is_verified = true

--
-- Name: vw_darkweb_mentionsbydate; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_mentionsbydate AS
SELECT
organizations_uid,
DATE(m."date"),
count(*) as "Count"
FROM mentions m
GROUP BY organizations_uid,
m."date"
ORDER BY m."date" desc;

--
-- Name: vw_darkweb_socmedia_mostactposts; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_socmedia_mostactposts AS
select m.organizations_uid,
m."date",
m.title "Title",
case
	when m.comments_count = 'NaN'
		then 1
	when m.comments_count = '0.0'
		then 1
	else m.comments_count::numeric::integer
	end "Comments Count"
from mentions m
where m.site not like 'forum%' and m.site not like 'market%'
ORDER BY "Comments Count" desc;

--
-- Name: vw_darkweb_mostactposts; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_mostactposts AS
select m.organizations_uid,
m."date",
m.title "Title",
case
	when m.comments_count = 'NaN'
		then 1
	when m.comments_count = '0.0'
		then 1
	when m.comments_count is null
		then 1
	else m.comments_count::numeric::integer
	end "Comments Count"
from mentions m
where m.site like 'forum%' or m.site like 'market%'
ORDER BY "Comments Count" desc;

--
-- Name: vw_darkweb_assetalerts; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_assetalerts AS
select a.organizations_uid,
max(a."date") as "date",
a.site as "Site",
a.title as "Title",
count(*) as "Events"
from alerts a
where a.alert_name not like '%executive%'
and a.site notnull and a.site != 'NaN'
GROUP BY a.site,
a.title, a.organizations_uid
ORDER BY "Events" desc;

--
-- Name: vw_darkweb_execalerts; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_execalerts AS
select a.organizations_uid,
max(a."date") as "date",
a.site as "Site",
a.title as "Title",
count(*) as "Events"
from alerts a
where a.alert_name like '%executive%'
and a.site notnull and a.site != 'NaN'
GROUP BY a.site,
a.title, a.organizations_uid
ORDER BY "Events" desc;

--
-- Name: vw_darkweb_threatactors; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_threatactors AS
select m.organizations_uid,
m."date",
m.creator as "Creator",
round(m.rep_grade::numeric ,3) as "Grade"
from mentions m
ORDER BY "Grade" desc;

--
-- Name: vw_darkweb_potentialthreats; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_potentialthreats AS
select a.organizations_uid,
a."date" as "date",
a.site as "Site",
btrim(a.threats,'{}') as "Threats"
from alerts a
where a.site notnull and a.site != 'NaN' and a.site != '';

--
-- Name: vw_darkweb_sites; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_sites AS
select m.organizations_uid,
m."date",
m.site as "Site"
from mentions m;

--
-- Name: vw_darkweb_inviteonlymarkets; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_inviteonlymarkets AS
select a.organizations_uid,
a."date" as "date",
a.site as "Site"
from alerts a
where a.site like 'market%'
and a.site notnull and a.site != 'NaN' and a.site != '';

--
-- Name: vw_darkweb_topcves; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW vw_darkweb_topcves AS
select *
from top_cves tc
ORDER BY tc."date" DESC LIMIT 10;

--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: postgres
--

GRANT ALL ON SCHEMA public TO crossfeed;


--
-- Fill table with DHS
--

INSERT INTO organizations (name, cyhy_db_name)
VALUES ('Department of Homeland Security', 'DHS');


--
-- PostgreSQL database dump complete
--
