--
-- PostgreSQL database dump
--

-- Dumped from database version 11.16
-- Dumped by pg_dump version 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: get_cred_metrics(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.get_cred_metrics(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, password_creds bigint, total_creds bigint, num_breaches bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		cred_metrics.organizations_uid,
		cred_metrics.password_creds,
		cred_metrics.total_creds,
		breach_metrics.num_breaches
	FROM
		(
			SELECT
				reported_orgs.organizations_uid,
				CAST(COALESCE(creds.password_included, 0) as bigint) password_creds,
				CAST(COALESCE(creds.no_password + creds.password_included, 0) as bigint) total_creds
			FROM
				(
					/* Orgs we're reporting on */
					SELECT
						organizations.organizations_uid
					FROM
						public.organizations
					WHERE
						report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						vw_breachcomp_credsbydate.organizations_uid,
						SUM(no_password) as no_password,
						SUM(password_included) as password_included
					FROM
						public.vw_breachcomp_credsbydate
					WHERE
						mod_date BETWEEN start_date AND end_date
					GROUP BY
						vw_breachcomp_credsbydate.organizations_uid
				) creds
				ON reported_orgs.organizations_uid = creds.organizations_uid
		) cred_metrics
		INNER JOIN
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(breaches.num_breaches, 0) num_breaches
			FROM
				(
					/* Orgs we're reporting on */
					SELECT
						organizations.organizations_uid
					FROM
						public.organizations
					WHERE
						report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						vw_breachcomp.organizations_uid,
						COUNT(DISTINCT breach_name) as num_breaches
					FROM
						public.vw_breachcomp
					WHERE
						modified_date BETWEEN start_date AND end_date
					GROUP BY
						vw_breachcomp.organizations_uid
				) breaches
				ON reported_orgs.organizations_uid = breaches.organizations_uid
		) breach_metrics
		ON
		cred_metrics.organizations_uid = breach_metrics.organizations_uid;
END; $$;


ALTER FUNCTION public.get_cred_metrics(start_date date, end_date date) OWNER TO pe;

--
-- Name: get_darkweb_metrics(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.get_darkweb_metrics(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, num_dw_alerts bigint, num_dw_mentions bigint, num_dw_threats bigint, num_dw_invites bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		dw_alert_metrics.organizations_uid,
		dw_alert_metrics.num_dw_alerts,
		CAST(dw_mention_metrics.num_dw_mentions as bigint) AS num_dw_mentions,
		dw_threat_metrics.num_dw_threats,
		dw_invite_metrics.num_dw_invites
	FROM
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(alerts.num_dw_alerts, 0) AS num_dw_alerts
			FROM
				(
					/* Orgs we're reporting on */
					SELECT
						organizations.organizations_uid
					FROM
						public.organizations
					WHERE
						report_on = True
				) reported_orgs
				LEFT JOIN
				(
					/* Get count of dark web alerts for the report period*/
					SELECT
						alerts.organizations_uid,
						COUNT(*) num_dw_alerts
					FROM
						public.alerts
					WHERE
						date BETWEEN start_date AND end_date
					GROUP BY
						alerts.organizations_uid
				) alerts
				ON reported_orgs.organizations_uid = alerts.organizations_uid
		) dw_alert_metrics
		INNER JOIN
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(mentions.num_dw_mentions, 0) AS num_dw_mentions
			FROM
				(
					/* Orgs we're reporting on */
					SELECT
						organizations.organizations_uid
					FROM
						public.organizations
					WHERE
						report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						vw_darkweb_mentionsbydate.organizations_uid,
						SUM(public.vw_darkweb_mentionsbydate."Count") as num_dw_mentions
					FROM
						public.vw_darkweb_mentionsbydate
					WHERE
						date BETWEEN start_date AND end_date
					GROUP BY
						vw_darkweb_mentionsbydate.organizations_uid
				) mentions
				ON reported_orgs.organizations_uid = mentions.organizations_uid
		) dw_mention_metrics
		ON
		dw_alert_metrics.organizations_uid = dw_mention_metrics.organizations_uid
		INNER JOIN
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(threats.num_dw_threats, 0) AS num_dw_threats
			FROM
				(
					/* Orgs we're reporting on */
					SELECT
						organizations.organizations_uid
					FROM
						public.organizations
					WHERE
						report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						vw_darkweb_potentialthreats.organizations_uid,
						COUNT(*) as num_dw_threats
					FROM
						public.vw_darkweb_potentialthreats
					WHERE
						date BETWEEN start_date AND end_date
					GROUP BY
						vw_darkweb_potentialthreats.organizations_uid
				) threats
				ON reported_orgs.organizations_uid = threats.organizations_uid
		) dw_threat_metrics
		ON
		dw_alert_metrics.organizations_uid = dw_threat_metrics.organizations_uid
		INNER JOIN
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(invites.num_dw_invites, 0) AS num_dw_invites
			FROM
				(
					/* Orgs we're reporting on */
					SELECT
						organizations.organizations_uid
					FROM
						public.organizations
					WHERE
						report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						vw_darkweb_inviteonlymarkets.organizations_uid,
						COUNT(*) as num_dw_invites
					FROM
						public.vw_darkweb_inviteonlymarkets
					WHERE
						date BETWEEN start_date AND end_date
					GROUP BY
						vw_darkweb_inviteonlymarkets.organizations_uid
				) invites
				ON reported_orgs.organizations_uid = invites.organizations_uid
		) dw_invite_metrics
		ON
		dw_alert_metrics.organizations_uid = dw_invite_metrics.organizations_uid;
END; $$;


ALTER FUNCTION public.get_darkweb_metrics(start_date date, end_date date) OWNER TO pe;

--
-- Name: get_domain_metrics(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.get_domain_metrics(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, num_sus_domain bigint, num_alert_domain bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		domain_sus_metrics.organizations_uid,
		domain_sus_metrics.num_sus_domain,
		domain_alert_metrics.num_alert_domain
	FROM
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(domain_sus.num_sus_domain, 0) num_sus_domain
			FROM
				(
					/* Orgs we're reporting on */
					SELECT
						organizations.organizations_uid
					FROM
						public.organizations
					WHERE
						report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						domain_permutations.organizations_uid,
						COUNT(*) as num_sus_domain
					FROM
						public.domain_permutations
					WHERE
						date_active BETWEEN start_date AND end_date
						AND
						malicious = True
					GROUP BY
						domain_permutations.organizations_uid
				) domain_sus
				ON reported_orgs.organizations_uid = domain_sus.organizations_uid
		) domain_sus_metrics
		INNER JOIN
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(domain_alerts.num_alert_domain, 0) num_alert_domain
			FROM
				(
					/* Orgs we're reporting on */
					SELECT
						organizations.organizations_uid
					FROM
						public.organizations
					WHERE
						report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						domain_alerts.organizations_uid,
						COUNT(*) as num_alert_domain
					FROM
						public.domain_alerts
					WHERE
						date BETWEEN start_date AND end_date
					GROUP BY
						domain_alerts.organizations_uid
				) domain_alerts
				ON reported_orgs.organizations_uid = domain_alerts.organizations_uid
		) domain_alert_metrics
		ON
		domain_sus_metrics.organizations_uid = domain_alert_metrics.organizations_uid;
END; $$;


ALTER FUNCTION public.get_domain_metrics(start_date date, end_date date) OWNER TO pe;

--
-- Name: get_vuln_metrics(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.get_vuln_metrics(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, num_verif_vulns bigint, num_assets_unverif_vulns bigint, num_insecure_ports bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		verif_vuln_metrics.organizations_uid,
		verif_vuln_metrics.num_verif_vulns,
		assets_unverif_vuln_metrics.num_assets_unverif_vulns,
		insecure_port_metrics.num_insecure_ports
	FROM
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(verif_vulns.num_verif_vulns, 0) AS num_verif_vulns
			FROM
				(
					/* Orgs we're reporting on */
					SELECT
						organizations.organizations_uid
					FROM
						public.organizations
					WHERE
						report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						cve_ip_combos.organizations_uid,
						COUNT(*) as num_verif_vulns
					FROM
						(
							SELECT DISTINCT
								vw_shodanvulns_verified.organizations_uid,
								cve,
								ip
							FROM
								public.vw_shodanvulns_verified
							WHERE
								timestamp BETWEEN start_date AND end_date
						) cve_ip_combos
					GROUP BY
						cve_ip_combos.organizations_uid
				) verif_vulns
				ON
				reported_orgs.organizations_uid = verif_vulns.organizations_uid
		) verif_vuln_metrics
		INNER JOIN
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(assets_unverif_vulns.num_assets_unverif_vuln, 0) AS num_assets_unverif_vulns
			FROM
				(
					/* Orgs we're reporting on */
						SELECT
							organizations.organizations_uid
						FROM
							public.organizations
						WHERE
							report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						cve_ip_combos.organizations_uid,
						COUNT(*) as num_assets_unverif_vuln
					FROM
						(
							SELECT DISTINCT
								vw_shodanvulns_suspected.organizations_uid,
								potential_vulns,
								ip
							FROM
								public.vw_shodanvulns_suspected
							WHERE
								timestamp BETWEEN start_date AND end_date
								AND
								vw_shodanvulns_suspected.type != 'Insecure Protocol'
						) cve_ip_combos
					GROUP BY
						cve_ip_combos.organizations_uid
				) assets_unverif_vulns
				ON
				reported_orgs.organizations_uid = assets_unverif_vulns.organizations_uid
		) assets_unverif_vuln_metrics
		ON
		verif_vuln_metrics.organizations_uid = assets_unverif_vuln_metrics.organizations_uid
		INNER JOIN
		(
			SELECT
				reported_orgs.organizations_uid,
				COALESCE(insecure_ports.num_risky_port, 0) AS num_insecure_ports
			FROM
				(
					/* Orgs we're reporting on */
						SELECT
							organizations.organizations_uid
						FROM
							public.organizations
						WHERE
							report_on = True
				) reported_orgs
				LEFT JOIN
				(
					SELECT
						risky_ports.organizations_uid,
						COUNT(port) as num_risky_port
					FROM
						(
							SELECT DISTINCT
								vw_shodanvulns_suspected.organizations_uid,
								protocol,
								ip,
								port
							FROM
								public.vw_shodanvulns_suspected
							WHERE
								vw_shodanvulns_suspected.type = 'Insecure Protocol'
								AND
								(protocol != 'http' AND protocol != 'smtp')
								AND
								timestamp BETWEEN start_date AND end_date
						) risky_ports
					GROUP BY
						risky_ports.organizations_uid
				) insecure_ports
				ON
				reported_orgs.organizations_uid = insecure_ports.organizations_uid
		) insecure_port_metrics
		ON
		verif_vuln_metrics.organizations_uid = insecure_port_metrics.organizations_uid;
END; $$;


ALTER FUNCTION public.get_vuln_metrics(start_date date, end_date date) OWNER TO pe;

--
-- Name: insert_cidr(cidr, uuid, text); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.insert_cidr(arg_net cidr, arg_org_uid uuid, arg_data_src text) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
declare
	parent_uid uuid := null;
	comp_cidr_uid uuid := null;
	comp_net cidr;
	comp_uid uuid := null;
	comp_parent_uid uuid := null;
	comp_cyhy_id text := null;
	save_to_db boolean := true;
	ds_uid uuid := null;
	new_cidr_uid uuid := null;
	in_cidrs record;
	cidrs_in record;
begin
		select o.parent_org_uid into parent_uid from organizations o where o.organizations_uid = arg_org_uid;
		select ds.data_source_uid into ds_uid from data_source ds where ds.name = arg_data_src;
		-- Check if any cidrs equal the provided cidr
		select ct.cidr_uid, o.organizations_uid , ct.network, o.parent_org_uid, o."cyhy_db_name"  as parent_id from cidrs ct
		join organizations o on ct.organizations_uid = o.organizations_uid
		where ct.network = arg_net into comp_cidr_uid, comp_uid, comp_net, comp_parent_uid, comp_cyhy_id;

		if (comp_net is not null) then
			--if the other cidr's org is our cidr's parent org
			if (comp_uid = parent_uid) then
				-- point to cidr to the new child org
				update cidrs set organizations_uid = arg_org_uid where organizations_uid = comp_uid and network = arg_net;
				new_cidr_uid := comp_cidr_uid;
				save_to_db := false;
			--if our cidr's org is the parent to the other cidr's org
			elseif (arg_org_uid = comp_parent_uid) then
				-- do nothing
				raise notice 'This cidr already exists in a child organization';
				save_to_db := false;
				--return comp_cidr_uid;
			-- if there is a duplicate for the same org
			elseif (arg_org_uid = comp_uid) then
			new_cidr_uid := comp_cidr_uid;
			save_to_db :=false;
			--if the orgs are not related
			else
				insert into cidrs (network, organizations_uid, insert_alert, data_source_uid)
				values (arg_net, arg_org_uid, 'Cidr duplicate between unrelated org. This cidr is also found in the following org. org_cyhy_id:' || comp_cyhy_id || ' org_uid: ' || comp_uid , ds_uid)
				returning cidr_uid into new_cidr_uid;
				save_to_db := false;
			end if;
		end if;

		-- Check if the cidr is contained in an existing cidr block
		if exists(select ct.network from cidrs ct where arg_net << ct.network) then

			for in_cidrs in select o.organizations_uid , tct.network, o.parent_org_uid  from cidrs tct
			join organizations o on o.organizations_uid = tct.organizations_uid where arg_net << ct.network loop
				-- Our cidr is found in an existing cidr for the same org
				--do nothing
				if (in_cidrs.organizations_uid = arg_org_uid) then
					raise notice 'This cidr is containeed in another cidr for the same organization';
					save_to_db := false;
				-- Our cidr is found in an existing cidr related to our parent org
				-- add cidr
				elseif (in_cidrs.organizations_uid = parent_uid) then
					if (cidr_uid is null) then
						insert into cidrs (network, organizations_uid , data_source_uid) values (arg_net, arg_org_uid, ds_uid)
						on conflict (organizations_uid, network )
						do nothing
						returning cidr_uid into new_cidr_uid;
						save_to_db := false;
					end if;
					--UPDATE IPS THAT BELONG TO THIS CIDR TO POINT HERE *******************************************
					update ips
					set origin_cidr = new_cidr_uid
					where ip << arg_net
					and origin_cidr = in_cidrs.network;
				-- Our cidr is found in an existing cidr related to our child org
				-- don't add cidr
				elseif (arg_org_uid = in_cidrs.parent_org_uid) then
					save_to_db := false;
				--Our cidr is found in an existing cidr unrelated to our org
				-- insert with an insert warning
				else
					insert into cidrs (network, organizations_uid, insert_alert, data_source_uid)
					values (arg_net, arg_org_uid, 'This cidr range is contained in another cidr owned by the following unrelated org. org_uid:' || in_cidrs.organizations_uid , ds_uid)
					on conflict (organizations_uid, network)
					DO UPDATE SET insert_alert = test_cidr_table.insert_alert || ", " || in_cidrs.organizations_uid
					returning cidr_uid into new_cidr_uid;
					save_to_db := false;
				end if;

			end loop;
		end if;

		-- Check if any cidrs are contained within it
		if exists(select ct.network from cidrs ct where ct.network << arg_net ) then
			for cidrs_in in select cidr_uid, o.organizations_uid , tct.network, o.parent_org_uid  from cidrs tct
			join organizations o on o.organizations_uid = tct.organizations_uid where ct.network << arg_net  loop
				-- an existing cidr is found in our cidr for the same org
				-- update existing cidr to current cidr
				if (cidrs_in.organizations_uid = arg_org_uid) then
					if (new_cidr_uid is null) then
						insert into cidrs (network, organizations_uid , data_source_uid) values (arg_net, arg_org_uid, ds_uid)
						on conflict (organizations_uid, network )
						do nothing
						returning cidr_uid into new_cidr_uid;
						save_to_db := false;
					end if;
					--update all ips to point to this new cidr block
					update ips
					set origin_cidr = new_cidr_uid
					where ip << arg_net
					and origin_cidr = cidrs_in.network;
					--delete the old cidr
					DELETE FROM cidrs
					WHERE network = cidrs_in.network
					and organizations_uid = arg_org_uid;
				-- an existing cidr related to our parent org is found in our cidr
				-- update existing cidr to our org and cidr
				elseif (in_cidrs.organizations_uid = parent_uid) then
					if (new_cidr_uid is null) then
						insert into cidrs (network, organizations_uid , data_source_uid) values (arg_net, arg_org_uid, ds_uid)
						on conflict (organizations_uid, network )
						do nothing
						returning cidr_uid into new_cidr_uid;
						save_to_db := false;
					end if;
					--update all ips to point to this new cidr block
					update ips
					set origin_cidr = new_cidr_uid
					where ip << arg_net
					and origin_cidr = cidrs_in.network;
					--delete the old cidr
					DELETE FROM cidrs
					WHERE network = cidrs_in.network
					and organizations_uid = arg_org_uid;
				-- an existing cidr is found in our cidr related to our child org
				-- add new cidr to our org
				elseif (arg_org_uid = in_cidrs.parent_org_uid) then
					if (new_cidr_uid is null) then
						insert into cidrs (network, organizations_uid , data_source_uid) values (arg_net, arg_org_uid, ds_uid)
						on conflict (organizations_uid, network )
						do nothing
						returning cidr_uid into new_cidr_uid;
						save_to_db := false;
					end if;

					update ips
					set origin_cidr = cidrs_in.cidr_uid
					where ip << cidrs_in.network
					and origin_cidr = arg_net;
				--an existing cidr unrelated to our org is found in our cidr
				-- insert with an insert warning
				else
					insert into cidrs (network, organizations_uid, insert_alert, data_source_uid)
					values (arg_net, arg_org_uid, 'another cidr owned by the following unrelated org is contained in this cidr range  . org_uid:' || cidrs_in.organizations_uid , ds_uid)
					on conflict (organizations_uid, network)
					DO UPDATE SET insert_alert = test_cidr_table.insert_alert || ", " || cidrs_in.organizations_uid
					returning cidr_uid into new_cidr_uid;
					save_to_db := false;
				end if;

			end loop;

			save_to_db := false;
		end if;

		if (save_to_db = true) then
			insert into cidrs (network, organizations_uid , data_source_uid) values (arg_net, arg_org_uid, ds_uid) returning cidr_uid into new_cidr_uid;
		end if;

 	return new_cidr_uid;
end;
$$;


ALTER FUNCTION public.insert_cidr(arg_net cidr, arg_org_uid uuid, arg_data_src text) OWNER TO pe;

--
-- Name: insert_sub_domain(text, uuid, text, text, uuid); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.insert_sub_domain(sub_d text, org_uid uuid, data_src text, root_d text DEFAULT NULL::text, root_d_uid uuid DEFAULT NULL::uuid) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
declare
	sub_id uuid;
	ds_uid uuid := null;
begin
		select sub_domain_uid into sub_id from sub_domains sd
		join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
		where sd.sub_domain = sub_d
		and rd.organizations_uid = org_uid;
		if (sub_id is null) then
			-- If the root_domain_uid is not provided look it up using the provided root_domain
			if (root_d_uid is null and root_d is not null) then
				begin
					select rd.root_domain_uid into root_d_uid from root_domains rd where rd.root_domain = root_d and rd.organizations_uid = org_uid;
					raise notice 'uid found: %', root_d_uid;
				end;
			else
					raise notice 'uid provided: %', root_d_uid;
			end if;
			--query the data_source_uid based on the provided data source name
			select ds.data_source_uid into ds_uid from data_source ds where ds.name = data_src;
			-- If the root_domain_uid is still null create a new root domain and return the root_domain_uid
			if (root_d_uid is null) then
				begin
					insert into root_domains (organizations_uid, root_domain, data_source_uid, enumerate_subs) values (org_uid, root_d, ds_uid, false) on conflict (organizations_uid, root_domain) do nothing;
					select rd.root_domain_uid into root_d_uid from root_domains rd where rd.root_domain = root_d;
				end;
			end if;
			-- query to see if the sub_domain already exists in the database
			select sub_domain_uid into sub_id from sub_domains where sub_domain = sub_d and root_domain_uid = root_d_uid;
			-- if the sub_domain is not already in the database then create it and return the sub_uid
			if (sub_id is null) then
				--add subdomain here
				insert into sub_domains (sub_domain, root_domain_uid, data_source_uid) values (sub_d, root_d_uid, ds_uid) on conflict (sub_domain, root_domain_uid) do nothing returning sub_domain_uid into sub_id;
				raise notice 'uid out of if: %', root_d_uid;
	 		end if;
	 	end if;
 	return sub_id;
end;
$$;


ALTER FUNCTION public.insert_sub_domain(sub_d text, org_uid uuid, data_src text, root_d text, root_d_uid uuid) OWNER TO pe;

--
-- Name: link_ips_and_subs(text, inet, uuid, text, text, uuid, text); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.link_ips_and_subs(arg_ip_hash text, arg_ip inet, arg_org_uid uuid, arg_sub_domain text, arg_data_src text, arg_root_uid uuid DEFAULT NULL::uuid, arg_root text DEFAULT NULL::text) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
declare
	sub_id uuid;
	ds_uid uuid := null;
	i_s_uid uuid := null;
begin
		--select ds.data_source_uid into ds_uid from data_source ds where ds.name = arg_data_src;

		insert into ips(ip_hash, ip)
       	values (arg_ip_hash, arg_ip)
           on conflict (ip) do nothing;

        --insert into sub_domains (sub_domain, root_domain_uid, data_source_uid)
      	--values (arg_sub_domain, arg_root_uid, ds_uid)
        --on conflict (sub_domain, root_domain_uid) do nothing
        --returning sub_domain_uid into sub_id;
       if (arg_root is null) then
       	select insert_sub_domain(sub_d=> arg_sub_domain, org_uid => arg_org_uid, data_src => arg_data_src,root_d_uid => arg_root_uid ) into sub_id;
       else
       	select insert_sub_domain(sub_d=> arg_sub_domain, org_uid => arg_org_uid, data_src => arg_data_src, root_d => arg_root) into sub_id;
       end if;
       	insert into ips_subs (ip_hash, sub_domain_uid)
       		values(arg_ip_hash, sub_id)
       		on conflict(ip_hash, sub_domain_uid) do nothing
       		returning ips_subs_uid into i_s_uid;-- insert both fk ids into the product_order table

       	return i_s_uid;
end;
$$;


ALTER FUNCTION public.link_ips_and_subs(arg_ip_hash text, arg_ip inet, arg_org_uid uuid, arg_sub_domain text, arg_data_src text, arg_root_uid uuid, arg_root text) OWNER TO pe;

--
-- Name: pes_base_metrics(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.pes_base_metrics(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, cyhy_db_name text, num_breaches bigint, num_total_creds bigint, num_pass_creds bigint, num_alert_domain bigint, num_sus_domain bigint, num_insecure_ports bigint, num_verif_vulns bigint, num_assets_unverif_vulns bigint, num_dw_alerts bigint, num_dw_mentions bigint, num_dw_threats bigint, num_dw_invites bigint, num_ports bigint, num_root_domain bigint, num_sub_domain bigint, num_ips bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		cred_metrics.organizations_uid,
		attacksurface_metrics.cyhy_db_name,
		cred_metrics.num_breaches,
		cred_metrics.total_creds AS num_total_creds,
		cred_metrics.password_creds AS num_pass_creds,
		domain_metrics.num_alert_domain,
		domain_metrics.num_sus_domain,
		vuln_metrics.num_insecure_ports,
		vuln_metrics.num_verif_vulns,
		vuln_metrics.num_assets_unverif_vulns,
		darkweb_metrics.num_dw_alerts,
		darkweb_metrics.num_dw_mentions,
		darkweb_metrics.num_dw_threats,
		darkweb_metrics.num_dw_invites,
		attacksurface_metrics.num_ports,
		attacksurface_metrics.num_root_domain,
		attacksurface_metrics.num_sub_domain,
		attacksurface_metrics.num_ips
	FROM
		(
			SELECT
				*
			FROM
				get_cred_metrics(start_date, end_date)
		) cred_metrics
		INNER JOIN
		(
			SELECT
				*
			FROM
				get_domain_metrics(start_date, end_date)
		) domain_metrics
		ON
		cred_metrics.organizations_uid = domain_metrics.organizations_uid
		INNER JOIN
		(
			SELECT
				*
			FROM
				get_vuln_metrics(start_date, end_date)
		) vuln_metrics
		ON
		cred_metrics.organizations_uid = vuln_metrics.organizations_uid
		INNER JOIN
		(
			SELECT
				*
			FROM
				get_darkweb_metrics(start_date, end_date)
		) darkweb_metrics
		ON
		cred_metrics.organizations_uid = darkweb_metrics.organizations_uid
		INNER JOIN
		(
			SELECT
				*
			FROM
				public.vw_orgs_attacksurface
		) attacksurface_metrics
		ON
		cred_metrics.organizations_uid = attacksurface_metrics.organizations_uid
	ORDER BY
		attacksurface_metrics.cyhy_db_name ASC;
END; $$;


ALTER FUNCTION public.pes_base_metrics(start_date date, end_date date) OWNER TO pe;

--
-- Name: pes_check_new_cve(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.pes_check_new_cve(start_date date, end_date date) RETURNS TABLE(cve_name text)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		current_cves.cve_name
	FROM
		(
			/* Select unverified CVEs */
			SELECT
				reported_orgs.organizations_uid,
				reported_orgs.cyhy_db_name,
				unverif_cve_list.unverif_cve as cve_name
			FROM
				(
					SELECT
						organizations.organizations_uid,
						organizations.cyhy_db_name
					FROM
						public.organizations
					WHERE
						organizations.report_on = True
				) reported_orgs
				INNER JOIN
				(
					SELECT DISTINCT
						vss.organizations_uid,
						UNNEST(vss.potential_vulns) as unverif_cve
					FROM
						public.vw_shodanvulns_suspected vss
					WHERE
						vss."type" != 'Insecure Protocol'
						AND
						vss.timestamp BETWEEN start_date AND end_date
				) unverif_cve_list
				ON
				reported_orgs.organizations_uid = unverif_cve_list.organizations_uid
			UNION
			/* Select verified CVEs */
			SELECT
				reported_orgs.organizations_uid,
				reported_orgs.cyhy_db_name,
				verif_cve_list.cve as cve_name
			FROM
				(
					SELECT
						organizations.organizations_uid,
						organizations.cyhy_db_name
					FROM
						public.organizations
					WHERE
						organizations.report_on = True
				) reported_orgs
				INNER JOIN
				(
					SELECT DISTINCT
						shodan_vulns.organizations_uid,
						shodan_vulns.cve
					FROM
						public.shodan_vulns
					WHERE
						shodan_vulns.timestamp BETWEEN start_date AND end_date
						AND
						shodan_vulns.is_verified = true
				) verif_cve_list
				ON
				reported_orgs.organizations_uid = verif_cve_list.organizations_uid
		) current_cves
		LEFT JOIN
		public.cve_info
		ON
		current_cves.cve_name = cve_info.cve_name
	WHERE
		cve_info.cve_name IS NULL;
END; $$;


ALTER FUNCTION public.pes_check_new_cve(start_date date, end_date date) OWNER TO pe;

--
-- Name: pes_cve_metrics(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.pes_cve_metrics(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, cyhy_db_name text, num_verif_cve bigint, num_verif_low bigint, num_verif_med bigint, num_verif_high bigint, num_verif_crit bigint, max_verif_cvss numeric, num_unverif_cve bigint, num_unverif_low bigint, num_unverif_med bigint, num_unverif_high bigint, num_unverif_crit bigint, max_unverif_cvss numeric)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		reported_orgs.organizations_uid,
		reported_orgs.cyhy_db_name,
		COALESCE(verif.num_verif_cves, 0) as num_verif_cve,
		COALESCE(verif.num_verif_low, 0) as num_verif_low,
		COALESCE(verif.num_verif_med, 0) as num_verif_med,
		COALESCE(verif.num_verif_high, 0) as num_verif_high,
		COALESCE(verif.num_verif_crit, 0) as num_verif_crit,
		COALESCE(verif.max_verif_cvss, 0) as max_verif_cvss,
		COALESCE(unverif.num_unverif_cves, 0) as num_unverif_cve,
		COALESCE(unverif.num_unverif_low, 0) as num_unverif_low,
		COALESCE(unverif.num_unverif_med, 0) as num_unverif_med,
		COALESCE(unverif.num_unverif_high, 0) as num_unverif_high,
		COALESCE(unverif.num_unverif_crit, 0) as num_unverif_crit,
		COALESCE(unverif.max_unverif_cvss, 0) as max_unverif_cvss
	FROM
		(
			SELECT
				organizations.organizations_uid,
				organizations.cyhy_db_name
			FROM
				public.organizations
			WHERE
				organizations.report_on = True
		) reported_orgs
		LEFT JOIN
		(
			/* Aggregated counts for verified CVEs */
			SELECT
				verif_cves.organizations_uid,
				verif_cves.cyhy_db_name,
				COUNT(*) as num_verif_cves,
				COUNT(*) FILTER (WHERE verif_cves.cvss_score < 4) as num_verif_low,
				COUNT(*) FILTER (WHERE verif_cves.cvss_score >= 4 AND verif_cves.cvss_score < 7) as num_verif_med,
				COUNT(*) FILTER (WHERE verif_cves.cvss_score >= 7 AND verif_cves.cvss_score < 9) as num_verif_high,
				COUNT(*) FILTER (WHERE verif_cves.cvss_score >= 9) as num_verif_crit,
				MAX(verif_cves.cvss_score) as max_verif_cvss
			FROM
				(
					SELECT
						reported_orgs.organizations_uid,
						reported_orgs.cyhy_db_name,
						verif_cve_list.cve as cve_name,
						COALESCE(cve_info.cvss_3_0, cve_info.cvss_2_0) as cvss_score,
						cve_info.dve_score
					FROM
						(
							/* Orgs that PE reports on */
							SELECT
								organizations.organizations_uid,
								organizations.cyhy_db_name
							FROM
								public.organizations
							WHERE
								organizations.report_on = True
						) reported_orgs
						INNER JOIN
						(
							/* List of verified CVEs for this report period */
							SELECT DISTINCT
								shodan_vulns.organizations_uid,
								shodan_vulns.cve,
								shodan_vulns.cvss,
								shodan_vulns.severity
							FROM
								public.shodan_vulns
							WHERE
								shodan_vulns.timestamp BETWEEN start_date AND end_date
								AND
								shodan_vulns.is_verified = true
						) verif_cve_list
						ON
						reported_orgs.organizations_uid = verif_cve_list.organizations_uid
						INNER JOIN
						/* CVE information */
						public.cve_info
						ON
						verif_cve_list.cve = cve_info.cve_name
					WHERE
						/* Filter out CVEs that don't have CVSS 2.0 nor 3.0 scores */
						NOT (cve_info.cvss_2_0 IS NULL AND cve_info.cvss_3_0 IS NULL)
					ORDER BY
						reported_orgs.cyhy_db_name
				) verif_cves
			GROUP BY
				verif_cves.organizations_uid,
				verif_cves.cyhy_db_name
		) verif
		ON
		reported_orgs.organizations_uid = verif.organizations_uid
		LEFT JOIN
		(
			/* Aggregated counts for unverified CVEs */
			SELECT
				unverif_cves.organizations_uid,
				unverif_cves.cyhy_db_name,
				COUNT(*) as num_unverif_cves,
				COUNT(*) FILTER (WHERE unverif_cves.cvss_score < 4) as num_unverif_low,
				COUNT(*) FILTER (WHERE unverif_cves.cvss_score >= 4 AND unverif_cves.cvss_score < 7) as num_unverif_med,
				COUNT(*) FILTER (WHERE unverif_cves.cvss_score >= 7 AND unverif_cves.cvss_score < 9) as num_unverif_high,
				COUNT(*) FILTER (WHERE unverif_cves.cvss_score >= 9) as num_unverif_crit,
				MAX(unverif_cves.cvss_score) as max_unverif_cvss
			FROM
				(
					SELECT
						reported_orgs.organizations_uid,
						reported_orgs.cyhy_db_name,
						unverif_cve_list.unverif_cve as cve_name,
						COALESCE(cve_info.cvss_3_0, cve_info.cvss_2_0) as cvss_score,
						cve_info.dve_score
					FROM
						(
							/* Orgs that PE reports on */
							SELECT
								organizations.organizations_uid,
								organizations.cyhy_db_name
							FROM
								public.organizations
							WHERE
								organizations.report_on = True
						) reported_orgs
						INNER JOIN
						(
							/* List of unverified CVEs for this report period */
							SELECT DISTINCT
								vss.organizations_uid,
								UNNEST(vss.potential_vulns) as unverif_cve
							FROM
								public.vw_shodanvulns_suspected vss
							WHERE
								vss."type" != 'Insecure Protocol'
								AND
								vss.timestamp BETWEEN start_date AND end_date
						) unverif_cve_list
						ON
						reported_orgs.organizations_uid = unverif_cve_list.organizations_uid
						INNER JOIN
						/* CVE information */
						public.cve_info
						ON
						unverif_cve_list.unverif_cve = cve_info.cve_name
					WHERE
						/* Filter out CVEs that don't have CVSS 2.0 nor 3.0 scores */
						NOT (cve_info.cvss_2_0 IS NULL AND cve_info.cvss_3_0 IS NULL)
					ORDER BY
						reported_orgs.cyhy_db_name
				) unverif_cves
			GROUP BY
				unverif_cves.organizations_uid,
				unverif_cves.cyhy_db_name
		) unverif
		ON
		reported_orgs.organizations_uid = unverif.organizations_uid
	ORDER BY
		reported_orgs.cyhy_db_name;
END; $$;


ALTER FUNCTION public.pes_cve_metrics(start_date date, end_date date) OWNER TO pe;

--
-- Name: pes_hist_data_domalert(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.pes_hist_data_domalert(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, cyhy_db_name text, mod_date date)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		reported_orgs.organizations_uid,
		reported_orgs.cyhy_db_name,
		domain_alerts.date as mod_date
	FROM
		(
			/* Orgs we're reporting on */
			SELECT
				organizations.organizations_uid,
				organizations.cyhy_db_name
			FROM
				public.organizations
			WHERE
				report_on = True
		) reported_orgs
		LEFT JOIN
		(
			SELECT
				domain_alerts.organizations_uid,
				domain_alerts.date
			FROM
				public.domain_alerts
			WHERE
				domain_alerts.date BETWEEN start_date AND end_date
		) domain_alerts
		ON reported_orgs.organizations_uid = domain_alerts.organizations_uid
	ORDER BY
		reported_orgs.cyhy_db_name,
		domain_alerts.date;
END; $$;


ALTER FUNCTION public.pes_hist_data_domalert(start_date date, end_date date) OWNER TO pe;

--
-- Name: pes_hist_data_dwalert(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.pes_hist_data_dwalert(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, cyhy_db_name text, mod_date date)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		reported_orgs.organizations_uid,
		reported_orgs.cyhy_db_name,
		alerts.date AS mod_date
	FROM
		(
			/* Orgs we're reporting on */
			SELECT
				organizations.organizations_uid,
				organizations.cyhy_db_name
			FROM
				public.organizations
			WHERE
				report_on = True
		) reported_orgs
		LEFT JOIN
		(
			/* Get count of dark web alerts for the report period*/
			SELECT
				alerts.organizations_uid,
				alerts.date
			FROM
				public.alerts
			WHERE
				alerts.date BETWEEN start_date AND end_date
		) alerts
		ON reported_orgs.organizations_uid = alerts.organizations_uid
	ORDER BY
		reported_orgs.cyhy_db_name,
		alerts.date;
END; $$;


ALTER FUNCTION public.pes_hist_data_dwalert(start_date date, end_date date) OWNER TO pe;

--
-- Name: pes_hist_data_dwment(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.pes_hist_data_dwment(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, cyhy_db_name text, date date, num_mentions bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		reported_orgs.organizations_uid,
		reported_orgs.cyhy_db_name,
		dw_mentions.date,
		COALESCE(dw_mentions."Count", 0) as num_mentions
	FROM
		(
			SELECT
				organizations.organizations_uid,
				organizations.cyhy_db_name
			FROM
				public.organizations
			WHERE
				report_on = True
		) reported_orgs
		LEFT JOIN
		(
			SELECT
				*
			FROM
				public.vw_darkweb_mentionsbydate dwm
			WHERE
				dwm.date BETWEEN start_date AND end_date
		) dw_mentions
		ON
		reported_orgs.organizations_uid = dw_mentions.organizations_uid;
END; $$;


ALTER FUNCTION public.pes_hist_data_dwment(start_date date, end_date date) OWNER TO pe;

--
-- Name: pes_hist_data_totcred(date, date); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.pes_hist_data_totcred(start_date date, end_date date) RETURNS TABLE(organizations_uid uuid, cyhy_db_name text, mod_date date, no_password bigint, password_included bigint, total_creds bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
RETURN QUERY
	SELECT
		reported_orgs.organizations_uid,
		reported_orgs.cyhy_db_name,
		cred_dat.mod_date,
		COALESCE(cred_dat.no_password, 0) as no_password,
		COALESCE(cred_dat.password_included, 0) as password_included,
		COALESCE(cred_dat.total_creds, 0) as total_creds
	FROM
		(
			SELECT
				organizations.organizations_uid,
				organizations.cyhy_db_name
			FROM
				public.organizations
			WHERE
				report_on = True
		) reported_orgs
		LEFT JOIN
		(
			SELECT
				*,
				vw_breachcomp_credsbydate.no_password + vw_breachcomp_credsbydate.password_included as total_creds
			FROM
				public.vw_breachcomp_credsbydate
			WHERE
				vw_breachcomp_credsbydate.mod_date BETWEEN start_date AND end_date
		) cred_dat
		ON
		reported_orgs.organizations_uid = cred_dat.organizations_uid
	ORDER BY
		reported_orgs.cyhy_db_name,
		cred_dat.mod_date;
END; $$;


ALTER FUNCTION public.pes_hist_data_totcred(start_date date, end_date date) OWNER TO pe;

--
-- Name: query_breach(text); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.query_breach(b_name text) RETURNS TABLE(breach_name text, description text, exposed_cred_count bigint, breach_date date, added_date timestamp without time zone, modified_date timestamp without time zone, data_classes text[], password_included boolean, is_verified boolean, data_source text)
    LANGUAGE plpgsql
    AS $$
BEGIN
   RETURN QUERY
   SELECT cb.breach_name, cb.description, cb.exposed_cred_count, cb.breach_date,
   			cb.added_date , cb.modified_date, cb.data_classes, cb.password_included ,
   			cb.is_verified , ds.name-- I added parentheses
   FROM  credential_breaches cb
   join data_source ds on ds.data_source_uid = cb.data_source_uid
   where lower(cb.breach_name) = lower(b_name);                    -- potential ambiguity
END
$$;


ALTER FUNCTION public.query_breach(b_name text) OWNER TO pe;

--
-- Name: query_emails(text, text); Type: FUNCTION; Schema: public; Owner: pe
--

CREATE FUNCTION public.query_emails(b_name text, org_id text) RETURNS TABLE(email text, org_name text, org_cyhy_id text, data_source text, name text, login_id text, phone text, password text, hash_type text)
    LANGUAGE plpgsql
    AS $$
BEGIN
   RETURN QUERY
   SELECT c.email, o.name, o.cyhy_db_name, d.name, c.name, c.login_id, c.phone, c.password, c.hash_type -- I added parentheses
   FROM  credential_exposures c
   join organizations o on o.organizations_uid = c.organizations_uid
   join data_source d on d.data_source_uid = c.data_source_uid
    where lower(c.breach_name) = lower(b_name)
    and o.cyhy_db_name = org_id;                    -- potential ambiguity
END
$$;


ALTER FUNCTION public.query_emails(b_name text, org_id text) OWNER TO pe;

SET default_tablespace = '';

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


ALTER TABLE public."Users" OWNER TO pe;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO pe;

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
    data_source_uid uuid NOT NULL,
    content_snip text,
    asset_mentioned text,
    asset_type text
);


ALTER TABLE public.alerts OWNER TO pe;

--
-- Name: alias; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.alias (
    alias_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    alias text NOT NULL
);


ALTER TABLE public.alias OWNER TO pe;

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


ALTER TABLE public.asset_headers OWNER TO pe;

--
-- Name: auth_group; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.auth_group (
    id integer NOT NULL,
    name character varying(150) NOT NULL
);


ALTER TABLE public.auth_group OWNER TO pe;

--
-- Name: auth_group_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public.auth_group ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_group_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: auth_group_permissions; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.auth_group_permissions (
    id bigint NOT NULL,
    group_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.auth_group_permissions OWNER TO pe;

--
-- Name: auth_group_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public.auth_group_permissions ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_group_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: auth_permission; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.auth_permission (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    content_type_id integer NOT NULL,
    codename character varying(100) NOT NULL
);


ALTER TABLE public.auth_permission OWNER TO pe;

--
-- Name: auth_permission_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public.auth_permission ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_permission_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: auth_user; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.auth_user (
    id integer NOT NULL,
    password character varying(128) NOT NULL,
    last_login timestamp with time zone,
    is_superuser boolean NOT NULL,
    username character varying(150) NOT NULL,
    first_name character varying(150) NOT NULL,
    last_name character varying(150) NOT NULL,
    email character varying(254) NOT NULL,
    is_staff boolean NOT NULL,
    is_active boolean NOT NULL,
    date_joined timestamp with time zone NOT NULL
);


ALTER TABLE public.auth_user OWNER TO pe;

--
-- Name: auth_user_groups; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.auth_user_groups (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    group_id integer NOT NULL
);


ALTER TABLE public.auth_user_groups OWNER TO pe;

--
-- Name: auth_user_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public.auth_user_groups ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_user_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: auth_user_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public.auth_user ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: auth_user_user_permissions; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.auth_user_user_permissions (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.auth_user_user_permissions OWNER TO pe;

--
-- Name: auth_user_user_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public.auth_user_user_permissions ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_user_user_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: cidrs; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.cidrs (
    cidr_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    network cidr NOT NULL,
    organizations_uid uuid,
    data_source_uid uuid,
    insert_alert text
);


ALTER TABLE public.cidrs OWNER TO pe;

--
-- Name: credential_breaches; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.credential_breaches (
    credential_breaches_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    breach_name text NOT NULL,
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
    data_source_uid uuid NOT NULL
);


ALTER TABLE public.credential_breaches OWNER TO pe;

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
    modified_date timestamp without time zone,
    credential_breaches_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    name text,
    login_id text,
    phone text,
    password text,
    hash_type text,
    intelx_system_id text
);


ALTER TABLE public.credential_exposures OWNER TO pe;

--
-- Name: cve_info; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.cve_info (
    cve_uuid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    cve_name text,
    cvss_2_0 numeric,
    cvss_2_0_severity text,
    cvss_2_0_vector text,
    cvss_3_0 numeric,
    cvss_3_0_severity text,
    cvss_3_0_vector text,
    dve_score numeric
);


ALTER TABLE public.cve_info OWNER TO pe;

--
-- Name: TABLE cve_info; Type: COMMENT; Schema: public; Owner: pe
--

COMMENT ON TABLE public.cve_info IS 'Table that holds all known CVEs and their associated CVSS 2.0/3.0/DVE info';


--
-- Name: cyhy_contacts; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.cyhy_contacts (
    _id uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    org_id text NOT NULL,
    org_name text NOT NULL,
    phone text,
    contact_type text NOT NULL,
    email text,
    name text,
    date_pulled date
);


ALTER TABLE public.cyhy_contacts OWNER TO pe;

--
-- Name: cyhy_db_assets; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.cyhy_db_assets (
    _id uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    org_id text,
    org_name text,
    contact text,
    network inet,
    type text,
    first_seen date,
    last_seen date,
    currently_in_cyhy boolean
);


ALTER TABLE public.cyhy_db_assets OWNER TO pe;

--
-- Name: dataAPI_apiuser; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public."dataAPI_apiuser" (
    id bigint NOT NULL,
    "apiKey" character varying(200),
    user_id integer NOT NULL,
    refresh_token character varying(200)
);


ALTER TABLE public."dataAPI_apiuser" OWNER TO pe;

--
-- Name: dataAPI_apiuser_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public."dataAPI_apiuser" ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public."dataAPI_apiuser_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
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


ALTER TABLE public.data_source OWNER TO pe;

--
-- Name: django_admin_log; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.django_admin_log (
    id integer NOT NULL,
    action_time timestamp with time zone NOT NULL,
    object_id text,
    object_repr character varying(200) NOT NULL,
    action_flag smallint NOT NULL,
    change_message text NOT NULL,
    content_type_id integer,
    user_id integer NOT NULL,
    CONSTRAINT django_admin_log_action_flag_check CHECK ((action_flag >= 0))
);


ALTER TABLE public.django_admin_log OWNER TO pe;

--
-- Name: django_admin_log_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public.django_admin_log ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.django_admin_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: django_content_type; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.django_content_type (
    id integer NOT NULL,
    app_label character varying(100) NOT NULL,
    model character varying(100) NOT NULL
);


ALTER TABLE public.django_content_type OWNER TO pe;

--
-- Name: django_content_type_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public.django_content_type ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.django_content_type_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: django_migrations; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.django_migrations (
    id bigint NOT NULL,
    app character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    applied timestamp with time zone NOT NULL
);


ALTER TABLE public.django_migrations OWNER TO pe;

--
-- Name: django_migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: pe
--

ALTER TABLE public.django_migrations ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.django_migrations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: django_session; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.django_session (
    session_key character varying(40) NOT NULL,
    session_data text NOT NULL,
    expire_date timestamp with time zone NOT NULL
);


ALTER TABLE public.django_session OWNER TO pe;

--
-- Name: dns_records; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.dns_records (
    dns_record_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    domain_name text,
    domain_type text,
    created_date timestamp without time zone,
    updated_date timestamp without time zone,
    expiration_date timestamp without time zone,
    name_servers text[],
    whois_server text,
    registrar_name text,
    status text,
    clean_text text,
    raw_text text,
    registrant_name text,
    registrant_organization text,
    registrant_street text,
    registrant_city text,
    registrant_state text,
    registrant_post_code text,
    registrant_country text,
    registrant_email text,
    registrant_phone text,
    registrant_phone_ext text,
    registrant_fax text,
    registrant_fax_ext text,
    registrant_raw_text text,
    administrative_name text,
    administrative_organization text,
    administrative_street text,
    administrative_city text,
    administrative_state text,
    administrative_post_code text,
    administrative_country text,
    administrative_email text,
    administrative_phone text,
    administrative_phone_ext text,
    administrative_fax text,
    administrative_fax_ext text,
    administrative_raw_text text,
    technical_name text,
    technical_organization text,
    technical_street text,
    technical_city text,
    technical_state text,
    technical_post_code text,
    technical_country text,
    technical_email text,
    technical_phone text,
    technical_phone_ext text,
    technical_fax text,
    technical_fax_ext text,
    technical_raw_text text,
    billing_name text,
    billing_organization text,
    billing_street text,
    billing_city text,
    billing_state text,
    billing_post_code text,
    billing_country text,
    billing_email text,
    billing_phone text,
    billing_phone_ext text,
    billing_fax text,
    billing_fax_ext text,
    billing_raw_text text,
    zone_name text,
    zone_organization text,
    zone_street text,
    zone_city text,
    zone_state text,
    zone_post_code text,
    zone_country text,
    zone_email text,
    zone_phone text,
    zone_phone_ext text,
    zone_fax text,
    zone_fax_ext text,
    zone_raw_text text
);


ALTER TABLE public.dns_records OWNER TO pe;

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


ALTER TABLE public.domain_alerts OWNER TO pe;

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
    sub_domain_uid uuid,
    dshield_record_count integer,
    dshield_attack_count integer,
    date_active date
);


ALTER TABLE public.domain_permutations OWNER TO pe;

--
-- Name: dotgov_domains; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.dotgov_domains (
    dotgov_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    domain_name text NOT NULL,
    domain_type text,
    agency text,
    organization text,
    city text,
    state text,
    security_contact_email text
);


ALTER TABLE public.dotgov_domains OWNER TO pe;

--
-- Name: executives; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.executives (
    executives_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    executives text NOT NULL
);


ALTER TABLE public.executives OWNER TO pe;

--
-- Name: ips; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.ips (
    ip_hash text NOT NULL,
    ip inet NOT NULL,
    origin_cidr uuid,
    shodan_results boolean,
    live boolean,
    date_last_live timestamp without time zone,
    last_reverse_lookup timestamp without time zone
);


ALTER TABLE public.ips OWNER TO pe;

--
-- Name: ips_subs; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.ips_subs (
    ips_subs_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    ip_hash text NOT NULL,
    sub_domain_uid uuid NOT NULL
);


ALTER TABLE public.ips_subs OWNER TO pe;

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
    data_source_uid uuid NOT NULL,
    title_translated text,
    content_translated text,
    detected_lang text
);


ALTER TABLE public.mentions OWNER TO pe;

--
-- Name: org_id_map; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.org_id_map (
    cyhy_id text,
    pe_org_id text,
    merge_orgs boolean DEFAULT false
);


ALTER TABLE public.org_id_map OWNER TO pe;

--
-- Name: org_type; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.org_type (
    org_type_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    org_type text
);


ALTER TABLE public.org_type OWNER TO pe;

--
-- Name: organizations; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.organizations (
    organizations_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    name text NOT NULL,
    cyhy_db_name text,
    org_type_uid uuid,
    report_on boolean DEFAULT false,
    password text,
    date_first_reported timestamp without time zone,
    parent_org_uid uuid,
    premium_report boolean,
    agency_type text,
    demo boolean DEFAULT false
);


ALTER TABLE public.organizations OWNER TO pe;

--
-- Name: outdated_vw_breach_complete; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.outdated_vw_breach_complete AS
 SELECT creds.credential_exposures_uid AS hibp_exposed_credentials_uid,
    creds.email,
    creds.breach_name,
    creds.organizations_uid,
    creds.root_domain,
    creds.sub_domain,
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


ALTER TABLE public.outdated_vw_breach_complete OWNER TO pe;

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


ALTER TABLE public.pshtt_results OWNER TO pe;

--
-- Name: report_summary_stats; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.report_summary_stats (
    report_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    start_date date NOT NULL,
    end_date date,
    ip_count integer,
    root_count integer,
    sub_count integer,
    ports_count integer,
    creds_count integer,
    breach_count integer,
    cred_password_count integer,
    domain_alert_count integer,
    suspected_domain_count integer,
    insecure_port_count integer,
    verified_vuln_count integer,
    suspected_vuln_count integer,
    suspected_vuln_addrs_count integer,
    threat_actor_count integer,
    dark_web_alerts_count integer,
    dark_web_mentions_count integer,
    dark_web_executive_alerts_count integer,
    dark_web_asset_alerts_count integer,
    pe_number_score text,
    pe_letter_grade text,
    pe_percent_score numeric,
    cidr_count integer,
    port_protocol_count integer,
    software_count integer,
    foreign_ips_count integer
);


ALTER TABLE public.report_summary_stats OWNER TO pe;

--
-- Name: root_domains; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.root_domains (
    root_domain_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    root_domain text NOT NULL,
    ip_address text,
    data_source_uid uuid NOT NULL,
    enumerate_subs boolean DEFAULT true
);


ALTER TABLE public.root_domains OWNER TO pe;

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
    "timestamp" timestamp without time zone,
    product text,
    server text,
    tags text[],
    domains text[],
    hostnames text[],
    isn text,
    asn integer,
    data_source_uid uuid NOT NULL,
    country_code text,
    location text
);


ALTER TABLE public.shodan_assets OWNER TO pe;

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
    "timestamp" timestamp without time zone,
    product text,
    server text,
    tags text[],
    domains text[],
    hostnames text[],
    isn text,
    asn integer,
    data_source_uid uuid NOT NULL
);


ALTER TABLE public.shodan_insecure_protocols_unverified_vulns OWNER TO pe;

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
    "timestamp" timestamp without time zone,
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
    is_verified boolean DEFAULT true
);


ALTER TABLE public.shodan_vulns OWNER TO pe;

--
-- Name: sub_domains; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.sub_domains (
    sub_domain_uid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    sub_domain text NOT NULL,
    root_domain_uid uuid NOT NULL,
    data_source_uid uuid NOT NULL,
    dns_record_uid uuid,
    status boolean DEFAULT false
);


ALTER TABLE public.sub_domains OWNER TO pe;

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


ALTER TABLE public.top_cves OWNER TO pe;

--
-- Name: topic_totals; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.topic_totals (
    cound_uuid uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    organizations_uid uuid NOT NULL,
    content_count integer NOT NULL,
    count_date text DEFAULT to_char((CURRENT_DATE)::timestamp with time zone, 'YYYY-MM-DD'::text)
);


ALTER TABLE public.topic_totals OWNER TO pe;

--
-- Name: unique_software; Type: TABLE; Schema: public; Owner: pe
--

CREATE TABLE public.unique_software (
    _id uuid DEFAULT public.uuid_generate_v1() NOT NULL,
    software_name text NOT NULL
);


ALTER TABLE public.unique_software OWNER TO pe;

--
-- Name: vw_breachcomp; Type: VIEW; Schema: public; Owner: pe
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


ALTER TABLE public.vw_breachcomp OWNER TO pe;

--
-- Name: vw_breachcomp_breachdetails; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_breachcomp_breachdetails AS
 SELECT vb.organizations_uid,
    vb.breach_name,
    date(vb.modified_date) AS mod_date,
    vb.description,
    vb.breach_date,
    vb.password_included,
    count(vb.email) AS number_of_creds
   FROM public.vw_breachcomp vb
  GROUP BY vb.organizations_uid, vb.breach_name, (date(vb.modified_date)), vb.description, vb.breach_date, vb.password_included
  ORDER BY (date(vb.modified_date)) DESC;


ALTER TABLE public.vw_breachcomp_breachdetails OWNER TO pe;

--
-- Name: vw_breachcomp_credsbydate; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_breachcomp_credsbydate AS
 SELECT vw_breachcomp.organizations_uid,
    date(vw_breachcomp.modified_date) AS mod_date,
    sum(
        CASE vw_breachcomp.password_included
            WHEN false THEN 1
            ELSE 0
        END) AS no_password,
    sum(
        CASE vw_breachcomp.password_included
            WHEN true THEN 1
            ELSE 0
        END) AS password_included
   FROM public.vw_breachcomp
  GROUP BY vw_breachcomp.organizations_uid, (date(vw_breachcomp.modified_date))
  ORDER BY (date(vw_breachcomp.modified_date)) DESC;


ALTER TABLE public.vw_breachcomp_credsbydate OWNER TO pe;

--
-- Name: vw_darkweb_assetalerts; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_assetalerts AS
 SELECT a.organizations_uid,
    max(a.date) AS date,
    a.site AS "Site",
    a.title AS "Title",
    count(*) AS "Events"
   FROM public.alerts a
  WHERE ((a.alert_name !~~ '%executive%'::text) AND (a.site IS NOT NULL) AND (a.site <> 'NaN'::text))
  GROUP BY a.site, a.title, a.organizations_uid
  ORDER BY (count(*)) DESC;


ALTER TABLE public.vw_darkweb_assetalerts OWNER TO pe;

--
-- Name: vw_darkweb_execalerts; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_execalerts AS
 SELECT a.organizations_uid,
    max(a.date) AS date,
    a.site AS "Site",
    a.title AS "Title",
    count(*) AS "Events"
   FROM public.alerts a
  WHERE ((a.alert_name ~~ '%executive%'::text) AND (a.site IS NOT NULL) AND (a.site <> 'NaN'::text))
  GROUP BY a.site, a.title, a.organizations_uid
  ORDER BY (count(*)) DESC;


ALTER TABLE public.vw_darkweb_execalerts OWNER TO pe;

--
-- Name: vw_darkweb_inviteonlymarkets; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_inviteonlymarkets AS
 SELECT a.organizations_uid,
    a.date,
    a.site AS "Site"
   FROM public.alerts a
  WHERE ((a.site ~~ 'market%'::text) AND (a.site IS NOT NULL) AND (a.site <> 'NaN'::text) AND (a.site <> ''::text));


ALTER TABLE public.vw_darkweb_inviteonlymarkets OWNER TO pe;

--
-- Name: vw_darkweb_mentionsbydate; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_mentionsbydate AS
 SELECT m.organizations_uid,
    m.date,
    count(*) AS "Count"
   FROM public.mentions m
  GROUP BY m.organizations_uid, m.date
  ORDER BY m.date DESC;


ALTER TABLE public.vw_darkweb_mentionsbydate OWNER TO pe;

--
-- Name: vw_darkweb_mostactposts; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_mostactposts AS
 SELECT m.organizations_uid,
    m.date,
    m.title AS "Title",
        CASE
            WHEN (m.comments_count = 'NaN'::text) THEN 1
            WHEN (m.comments_count = '0.0'::text) THEN 1
            WHEN (m.comments_count IS NULL) THEN 1
            ELSE ((m.comments_count)::numeric)::integer
        END AS "Comments Count"
   FROM public.mentions m
  WHERE ((m.site ~~ 'forum%'::text) OR (m.site ~~ 'market%'::text))
  ORDER BY
        CASE
            WHEN (m.comments_count = 'NaN'::text) THEN 1
            WHEN (m.comments_count = '0.0'::text) THEN 1
            WHEN (m.comments_count IS NULL) THEN 1
            ELSE ((m.comments_count)::numeric)::integer
        END DESC;


ALTER TABLE public.vw_darkweb_mostactposts OWNER TO pe;

--
-- Name: vw_darkweb_potentialthreats; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_potentialthreats AS
 SELECT a.organizations_uid,
    a.date,
    a.site AS "Site",
    btrim(a.threats, '{}'::text) AS "Threats"
   FROM public.alerts a
  WHERE ((a.site IS NOT NULL) AND (a.site <> 'NaN'::text) AND (a.site <> ''::text));


ALTER TABLE public.vw_darkweb_potentialthreats OWNER TO pe;

--
-- Name: vw_darkweb_sites; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_sites AS
 SELECT m.organizations_uid,
    m.date,
    m.site AS "Site"
   FROM public.mentions m;


ALTER TABLE public.vw_darkweb_sites OWNER TO pe;

--
-- Name: vw_darkweb_socmedia_mostactposts; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_socmedia_mostactposts AS
 SELECT m.organizations_uid,
    m.date,
    m.title AS "Title",
        CASE
            WHEN (m.comments_count = 'NaN'::text) THEN 1
            WHEN (m.comments_count = '0.0'::text) THEN 1
            ELSE ((m.comments_count)::numeric)::integer
        END AS "Comments Count"
   FROM public.mentions m
  WHERE ((m.site !~~ 'forum%'::text) AND (m.site !~~ 'market%'::text))
  ORDER BY
        CASE
            WHEN (m.comments_count = 'NaN'::text) THEN 1
            WHEN (m.comments_count = '0.0'::text) THEN 1
            ELSE ((m.comments_count)::numeric)::integer
        END DESC;


ALTER TABLE public.vw_darkweb_socmedia_mostactposts OWNER TO pe;

--
-- Name: vw_darkweb_threatactors; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_threatactors AS
 SELECT m.organizations_uid,
    m.date,
    m.creator AS "Creator",
    round((m.rep_grade)::numeric, 3) AS "Grade"
   FROM public.mentions m
  ORDER BY (round((m.rep_grade)::numeric, 3)) DESC;


ALTER TABLE public.vw_darkweb_threatactors OWNER TO pe;

--
-- Name: vw_darkweb_topcves; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_darkweb_topcves AS
 SELECT tc.top_cves_uid,
    tc.cve_id,
    tc.dynamic_rating,
    tc.nvd_base_score,
    tc.date,
    tc.summary,
    tc.data_source_uid
   FROM public.top_cves tc
  ORDER BY tc.date DESC
 LIMIT 10;


ALTER TABLE public.vw_darkweb_topcves OWNER TO pe;

--
-- Name: vw_orgs_total_cidrs; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_orgs_total_cidrs AS
 SELECT reported_orgs.organizations_uid,
    COALESCE(cidr_counts.count, (0)::bigint) AS count
   FROM (( SELECT organizations.organizations_uid
           FROM public.organizations
          WHERE (organizations.report_on = true)) reported_orgs
     LEFT JOIN ( SELECT c.organizations_uid,
            count(c.network) AS count
           FROM public.cidrs c
          GROUP BY c.organizations_uid) cidr_counts ON ((reported_orgs.organizations_uid = cidr_counts.organizations_uid)));


ALTER TABLE public.vw_orgs_total_cidrs OWNER TO pe;

--
-- Name: vw_orgs_total_domains; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_orgs_total_domains AS
 SELECT root_table.organizations_uid,
    root_table.cyhy_db_name,
    root_table.num_root_domain,
    sub_table.num_sub_domain
   FROM (( SELECT reported_orgs.organizations_uid,
            reported_orgs.cyhy_db_name,
            COALESCE(root_counts.num_root_domain, (0)::bigint) AS num_root_domain
           FROM (( SELECT organizations.organizations_uid,
                    organizations.cyhy_db_name
                   FROM public.organizations
                  WHERE (organizations.report_on = true)) reported_orgs
             LEFT JOIN ( SELECT root_table_1.organizations_uid,
                    count(DISTINCT root_table_1.root_domain) AS num_root_domain
                   FROM public.root_domains root_table_1
                  GROUP BY root_table_1.organizations_uid) root_counts ON ((reported_orgs.organizations_uid = root_counts.organizations_uid)))) root_table
     JOIN ( SELECT reported_orgs.organizations_uid,
            reported_orgs.cyhy_db_name,
            COALESCE(sub_counts.num_sub_domain, (0)::bigint) AS num_sub_domain
           FROM (( SELECT organizations.organizations_uid,
                    organizations.cyhy_db_name
                   FROM public.organizations
                  WHERE (organizations.report_on = true)) reported_orgs
             LEFT JOIN ( SELECT root_table_1.organizations_uid,
                    count(DISTINCT sub_table_1.sub_domain) AS num_sub_domain
                   FROM (public.sub_domains sub_table_1
                     JOIN public.root_domains root_table_1 ON ((sub_table_1.root_domain_uid = root_table_1.root_domain_uid)))
                  GROUP BY root_table_1.organizations_uid) sub_counts ON ((reported_orgs.organizations_uid = sub_counts.organizations_uid)))) sub_table ON ((root_table.organizations_uid = sub_table.organizations_uid)))
  ORDER BY sub_table.num_sub_domain, root_table.num_root_domain;


ALTER TABLE public.vw_orgs_total_domains OWNER TO pe;

--
-- Name: VIEW vw_orgs_total_domains; Type: COMMENT; Schema: public; Owner: pe
--

COMMENT ON VIEW public.vw_orgs_total_domains IS 'Gets the total number of root and sub domains for all orgs.';


--
-- Name: vw_orgs_total_foreign_ips; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_orgs_total_foreign_ips AS
 SELECT reported_orgs.organizations_uid,
    COALESCE(foreign_ips.num_foreign_ips, (0)::bigint) AS num_foreign_ips
   FROM (( SELECT organizations.organizations_uid
           FROM public.organizations
          WHERE (organizations.report_on = true)) reported_orgs
     LEFT JOIN ( SELECT sa.organizations_uid,
            count(
                CASE
                    WHEN ((sa.country_code <> 'US'::text) OR (sa.country_code IS NOT NULL)) THEN 1
                    ELSE NULL::integer
                END) AS num_foreign_ips
           FROM public.shodan_assets sa
          GROUP BY sa.organizations_uid) foreign_ips ON ((reported_orgs.organizations_uid = foreign_ips.organizations_uid)));


ALTER TABLE public.vw_orgs_total_foreign_ips OWNER TO pe;

--
-- Name: vw_orgs_total_ips; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_orgs_total_ips AS
 SELECT reported_orgs.organizations_uid,
    reported_orgs.cyhy_db_name,
    COALESCE(count(all_ips.ip), (0)::bigint) AS num_ips
   FROM (( SELECT organizations.organizations_uid,
            organizations.cyhy_db_name
           FROM public.organizations
          WHERE (organizations.report_on = true)) reported_orgs
     LEFT JOIN ( SELECT cidrs_table.organizations_uid,
            ips_table.ip
           FROM (public.ips ips_table
             JOIN public.cidrs cidrs_table ON ((ips_table.origin_cidr = cidrs_table.cidr_uid)))
        UNION
         SELECT rd.organizations_uid,
            i.ip
           FROM (((public.root_domains rd
             JOIN public.sub_domains sd ON ((rd.root_domain_uid = sd.root_domain_uid)))
             JOIN public.ips_subs si ON ((sd.sub_domain_uid = si.sub_domain_uid)))
             JOIN public.ips i ON ((si.ip_hash = i.ip_hash)))) all_ips ON ((reported_orgs.organizations_uid = all_ips.organizations_uid)))
  GROUP BY reported_orgs.organizations_uid, reported_orgs.cyhy_db_name
  ORDER BY COALESCE(count(all_ips.ip), (0)::bigint);


ALTER TABLE public.vw_orgs_total_ips OWNER TO pe;

--
-- Name: VIEW vw_orgs_total_ips; Type: COMMENT; Schema: public; Owner: pe
--

COMMENT ON VIEW public.vw_orgs_total_ips IS 'Gets the total number of ips associated with each organization.';


--
-- Name: vw_orgs_total_ports; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_orgs_total_ports AS
 SELECT reported_orgs.organizations_uid,
    reported_orgs.cyhy_db_name,
    COALESCE(count(all_ports.port), (0)::bigint) AS num_ports
   FROM (( SELECT organizations.organizations_uid,
            organizations.cyhy_db_name
           FROM public.organizations
          WHERE (organizations.report_on = true)) reported_orgs
     LEFT JOIN ( SELECT DISTINCT assets.organizations_uid,
            assets.ip,
            assets.port
           FROM public.shodan_assets assets
        UNION
         SELECT DISTINCT vulns.organizations_uid,
            vulns.ip,
            (vulns.port)::integer AS port
           FROM public.shodan_vulns vulns
        UNION
         SELECT DISTINCT unverif_vulns.organizations_uid,
            unverif_vulns.ip,
            unverif_vulns.port
           FROM public.shodan_insecure_protocols_unverified_vulns unverif_vulns) all_ports ON ((reported_orgs.organizations_uid = all_ports.organizations_uid)))
  GROUP BY reported_orgs.organizations_uid, reported_orgs.cyhy_db_name
  ORDER BY COALESCE(count(all_ports.port), (0)::bigint);


ALTER TABLE public.vw_orgs_total_ports OWNER TO pe;

--
-- Name: VIEW vw_orgs_total_ports; Type: COMMENT; Schema: public; Owner: pe
--

COMMENT ON VIEW public.vw_orgs_total_ports IS 'Gets the total number of unique ports for every organization P&E reports on';


--
-- Name: vw_orgs_total_ports_protocols; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_orgs_total_ports_protocols AS
 SELECT reported_orgs.organizations_uid,
    COALESCE(protocols.port_protocol, (0)::bigint) AS port_protocol
   FROM (( SELECT organizations.organizations_uid
           FROM public.organizations
          WHERE (organizations.report_on = true)) reported_orgs
     LEFT JOIN ( SELECT t.organizations_uid,
            count(*) AS port_protocol
           FROM ( SELECT DISTINCT sa.port,
                    sa.protocol,
                    sa.organizations_uid
                   FROM public.shodan_assets sa) t
          GROUP BY t.organizations_uid) protocols ON ((reported_orgs.organizations_uid = protocols.organizations_uid)));


ALTER TABLE public.vw_orgs_total_ports_protocols OWNER TO pe;

--
-- Name: vw_orgs_total_software; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_orgs_total_software AS
 SELECT reported_orgs.organizations_uid,
    COALESCE(software.num_software, (0)::bigint) AS num_software
   FROM (( SELECT organizations.organizations_uid
           FROM public.organizations
          WHERE (organizations.report_on = true)) reported_orgs
     LEFT JOIN ( SELECT t.organizations_uid,
            count(*) AS num_software
           FROM ( SELECT DISTINCT sa.product,
                    sa.organizations_uid
                   FROM public.shodan_assets sa) t
          GROUP BY t.organizations_uid) software ON ((reported_orgs.organizations_uid = software.organizations_uid)));


ALTER TABLE public.vw_orgs_total_software OWNER TO pe;

--
-- Name: vw_orgs_attacksurface; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_orgs_attacksurface AS
 SELECT domains_view.organizations_uid,
    domains_view.cyhy_db_name,
    ports_view.num_ports,
    domains_view.num_root_domain,
    domains_view.num_sub_domain,
    ips_view.num_ips,
    cidrs_view.count AS num_cidrs,
    port_prot_view.port_protocol AS num_ports_protocols,
    soft_view.num_software,
    for_ips_view.num_foreign_ips
   FROM ((((((public.vw_orgs_total_domains domains_view
     JOIN public.vw_orgs_total_ips ips_view ON ((domains_view.organizations_uid = ips_view.organizations_uid)))
     JOIN public.vw_orgs_total_ports ports_view ON ((ips_view.organizations_uid = ports_view.organizations_uid)))
     JOIN public.vw_orgs_total_cidrs cidrs_view ON ((cidrs_view.organizations_uid = ips_view.organizations_uid)))
     JOIN public.vw_orgs_total_ports_protocols port_prot_view ON ((port_prot_view.organizations_uid = ports_view.organizations_uid)))
     JOIN public.vw_orgs_total_software soft_view ON ((soft_view.organizations_uid = port_prot_view.organizations_uid)))
     JOIN public.vw_orgs_total_foreign_ips for_ips_view ON ((for_ips_view.organizations_uid = soft_view.organizations_uid)))
  ORDER BY ips_view.num_ips, domains_view.num_sub_domain, domains_view.num_root_domain, ports_view.num_ports;


ALTER TABLE public.vw_orgs_attacksurface OWNER TO pe;

--
-- Name: VIEW vw_orgs_attacksurface; Type: COMMENT; Schema: public; Owner: pe
--

COMMENT ON VIEW public.vw_orgs_attacksurface IS 'gets all attack surface related metrics for the orgs PE reports on';


--
-- Name: vw_orgs_contact_info; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_orgs_contact_info AS
 SELECT organizations.organizations_uid,
    organizations.cyhy_db_name,
    organizations.name AS agency_name,
    cyhy_contacts.contact_type,
    cyhy_contacts.name AS contact_name,
    cyhy_contacts.email,
    replace(cyhy_contacts.phone, '.'::text, '-'::text) AS phone,
    cyhy_contacts.date_pulled
   FROM (public.organizations
     JOIN public.cyhy_contacts ON ((organizations.cyhy_db_name = cyhy_contacts.org_id)))
  ORDER BY organizations.cyhy_db_name, cyhy_contacts.contact_type;


ALTER TABLE public.vw_orgs_contact_info OWNER TO pe;

--
-- Name: VIEW vw_orgs_contact_info; Type: COMMENT; Schema: public; Owner: pe
--

COMMENT ON VIEW public.vw_orgs_contact_info IS 'Gets the contact info for all PE organizations';


--
-- Name: vw_shodanvulns_suspected; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_shodanvulns_suspected AS
 SELECT svv.organizations_uid,
    svv.organization,
    svv.ip,
    svv.port,
    svv.protocol,
    svv.type,
    svv.name,
    svv.potential_vulns,
    svv.mitigation,
    svv."timestamp",
    svv.product,
    svv.server,
    svv.tags,
    svv.domains,
    svv.hostnames,
    svv.isn,
    svv.asn,
    ds.name AS data_source
   FROM (public.shodan_vulns svv
     JOIN public.data_source ds ON ((ds.data_source_uid = svv.data_source_uid)))
  WHERE (svv.is_verified = false);


ALTER TABLE public.vw_shodanvulns_suspected OWNER TO pe;

--
-- Name: vw_shodanvulns_verified; Type: VIEW; Schema: public; Owner: pe
--

CREATE VIEW public.vw_shodanvulns_verified AS
 SELECT svv.organizations_uid,
    svv.organization,
    svv.ip,
    svv.port,
    svv.protocol,
    svv."timestamp",
    svv.cve,
    svv.severity,
    svv.cvss,
    svv.summary,
    svv.product,
    svv.attack_vector,
    svv.av_description,
    svv.attack_complexity,
    svv.ac_description,
    svv.confidentiality_impact,
    svv.ci_description,
    svv.integrity_impact,
    svv.ii_description,
    svv.availability_impact,
    svv.ai_description,
    svv.tags,
    svv.domains,
    svv.hostnames,
    svv.isn,
    svv.asn,
    ds.name AS data_source
   FROM (public.shodan_vulns svv
     JOIN public.data_source ds ON ((ds.data_source_uid = svv.data_source_uid)))
  WHERE (svv.is_verified = true);


ALTER TABLE public.vw_shodanvulns_verified OWNER TO pe;

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
    last_scanned timestamp without time zone,
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
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


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
-- Name: auth_group auth_group_name_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_name_key UNIQUE (name);


--
-- Name: auth_group_permissions auth_group_permissions_group_id_permission_id_0cd325b0_uniq; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_group_id_permission_id_0cd325b0_uniq UNIQUE (group_id, permission_id);


--
-- Name: auth_group_permissions auth_group_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_pkey PRIMARY KEY (id);


--
-- Name: auth_group auth_group_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_pkey PRIMARY KEY (id);


--
-- Name: auth_permission auth_permission_content_type_id_codename_01ab375a_uniq; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_content_type_id_codename_01ab375a_uniq UNIQUE (content_type_id, codename);


--
-- Name: auth_permission auth_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_pkey PRIMARY KEY (id);


--
-- Name: auth_user_groups auth_user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_pkey PRIMARY KEY (id);


--
-- Name: auth_user_groups auth_user_groups_user_id_group_id_94350c0c_uniq; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_user_id_group_id_94350c0c_uniq UNIQUE (user_id, group_id);


--
-- Name: auth_user auth_user_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user
    ADD CONSTRAINT auth_user_pkey PRIMARY KEY (id);


--
-- Name: auth_user_user_permissions auth_user_user_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_pkey PRIMARY KEY (id);


--
-- Name: auth_user_user_permissions auth_user_user_permissions_user_id_permission_id_14a6b632_uniq; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_user_id_permission_id_14a6b632_uniq UNIQUE (user_id, permission_id);


--
-- Name: auth_user auth_user_username_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user
    ADD CONSTRAINT auth_user_username_key UNIQUE (username);


--
-- Name: cidrs cidrs_uid_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cidrs
    ADD CONSTRAINT cidrs_uid_pkey PRIMARY KEY (cidr_uid);


--
-- Name: credential_exposures credential_exposure_unique_constraint; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.credential_exposures
    ADD CONSTRAINT credential_exposure_unique_constraint UNIQUE (breach_name, email);


--
-- Name: cve_info cve_info_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cve_info
    ADD CONSTRAINT cve_info_pkey PRIMARY KEY (cve_uuid);


--
-- Name: cve_info cve_name_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cve_info
    ADD CONSTRAINT cve_name_key UNIQUE (cve_name);


--
-- Name: cyhy_contacts cyhy_contacts_org_id_contact_type_email_name_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cyhy_contacts
    ADD CONSTRAINT cyhy_contacts_org_id_contact_type_email_name_key UNIQUE (org_id, contact_type, email, name);


--
-- Name: cyhy_contacts cyhy_contacts_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cyhy_contacts
    ADD CONSTRAINT cyhy_contacts_pkey PRIMARY KEY (_id);


--
-- Name: cyhy_db_assets cyhy_db_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cyhy_db_assets
    ADD CONSTRAINT cyhy_db_assets_pkey PRIMARY KEY (_id);


--
-- Name: cyhy_db_assets cyhy_db_assets_unique_constraint; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cyhy_db_assets
    ADD CONSTRAINT cyhy_db_assets_unique_constraint UNIQUE (org_id, network);


--
-- Name: dataAPI_apiuser dataAPI_apiuser_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public."dataAPI_apiuser"
    ADD CONSTRAINT "dataAPI_apiuser_pkey" PRIMARY KEY (id);


--
-- Name: dataAPI_apiuser dataAPI_apiuser_user_id_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public."dataAPI_apiuser"
    ADD CONSTRAINT "dataAPI_apiuser_user_id_key" UNIQUE (user_id);


--
-- Name: data_source data_source_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.data_source
    ADD CONSTRAINT data_source_pkey PRIMARY KEY (data_source_uid);


--
-- Name: django_admin_log django_admin_log_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_pkey PRIMARY KEY (id);


--
-- Name: django_content_type django_content_type_app_label_model_76bd3d3b_uniq; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.django_content_type
    ADD CONSTRAINT django_content_type_app_label_model_76bd3d3b_uniq UNIQUE (app_label, model);


--
-- Name: django_content_type django_content_type_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.django_content_type
    ADD CONSTRAINT django_content_type_pkey PRIMARY KEY (id);


--
-- Name: django_migrations django_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.django_migrations
    ADD CONSTRAINT django_migrations_pkey PRIMARY KEY (id);


--
-- Name: django_session django_session_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.django_session
    ADD CONSTRAINT django_session_pkey PRIMARY KEY (session_key);


--
-- Name: dns_records dns_records_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.dns_records
    ADD CONSTRAINT dns_records_pkey PRIMARY KEY (dns_record_uid);


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
-- Name: dotgov_domains dotgov_uid_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.dotgov_domains
    ADD CONSTRAINT dotgov_uid_pkey PRIMARY KEY (dotgov_uid);


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
-- Name: ips ip_unique; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.ips
    ADD CONSTRAINT ip_unique UNIQUE (ip);


--
-- Name: ips ips_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.ips
    ADD CONSTRAINT ips_pkey PRIMARY KEY (ip_hash);


--
-- Name: ips_subs ips_subs_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.ips_subs
    ADD CONSTRAINT ips_subs_pkey PRIMARY KEY (ips_subs_uid);


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
-- Name: org_type org_type_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.org_type
    ADD CONSTRAINT org_type_pkey PRIMARY KEY (org_type_uid);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (organizations_uid);


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
-- Name: report_summary_stats report_summary_stats_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.report_summary_stats
    ADD CONSTRAINT report_summary_stats_pkey PRIMARY KEY (report_uid);


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
-- Name: shodan_vulns shodan_verified_vulns_organizations_uid_ip_port_protocol_ti_key; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_vulns
    ADD CONSTRAINT shodan_verified_vulns_organizations_uid_ip_port_protocol_ti_key UNIQUE (organizations_uid, ip, port, protocol, "timestamp");


--
-- Name: shodan_vulns shodan_verified_vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_vulns
    ADD CONSTRAINT shodan_verified_vulns_pkey PRIMARY KEY (shodan_vuln_uid);


--
-- Name: sub_domains sub_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_pkey PRIMARY KEY (sub_domain_uid);


--
-- Name: sub_domains sub_domains_un; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_un UNIQUE (sub_domain, root_domain_uid);


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
-- Name: topic_totals topic_totals_pk; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.topic_totals
    ADD CONSTRAINT topic_totals_pk PRIMARY KEY (cound_uuid);


--
-- Name: organizations unique_cyhy_db_name; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT unique_cyhy_db_name UNIQUE (cyhy_db_name);


--
-- Name: dotgov_domains unique_domain; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.dotgov_domains
    ADD CONSTRAINT unique_domain UNIQUE (domain_name);


--
-- Name: org_id_map unique_id_map_unique; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.org_id_map
    ADD CONSTRAINT unique_id_map_unique UNIQUE (cyhy_id, pe_org_id);


--
-- Name: ips_subs unique_ips_subs_unique; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.ips_subs
    ADD CONSTRAINT unique_ips_subs_unique UNIQUE (ip_hash, sub_domain_uid);


--
-- Name: cidrs unique_org_cidr; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cidrs
    ADD CONSTRAINT unique_org_cidr UNIQUE (organizations_uid, network);


--
-- Name: report_summary_stats unique_report; Type: CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.report_summary_stats
    ADD CONSTRAINT unique_report UNIQUE (organizations_uid, start_date);


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
-- Name: auth_group_name_a6ea08ec_like; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX auth_group_name_a6ea08ec_like ON public.auth_group USING btree (name varchar_pattern_ops);


--
-- Name: auth_group_permissions_group_id_b120cbf9; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX auth_group_permissions_group_id_b120cbf9 ON public.auth_group_permissions USING btree (group_id);


--
-- Name: auth_group_permissions_permission_id_84c5c92e; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX auth_group_permissions_permission_id_84c5c92e ON public.auth_group_permissions USING btree (permission_id);


--
-- Name: auth_permission_content_type_id_2f476e4b; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX auth_permission_content_type_id_2f476e4b ON public.auth_permission USING btree (content_type_id);


--
-- Name: auth_user_groups_group_id_97559544; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX auth_user_groups_group_id_97559544 ON public.auth_user_groups USING btree (group_id);


--
-- Name: auth_user_groups_user_id_6a12ed8b; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX auth_user_groups_user_id_6a12ed8b ON public.auth_user_groups USING btree (user_id);


--
-- Name: auth_user_user_permissions_permission_id_1fbb5f2c; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX auth_user_user_permissions_permission_id_1fbb5f2c ON public.auth_user_user_permissions USING btree (permission_id);


--
-- Name: auth_user_user_permissions_user_id_a95ead1b; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX auth_user_user_permissions_user_id_a95ead1b ON public.auth_user_user_permissions USING btree (user_id);


--
-- Name: auth_user_username_6821ab7c_like; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX auth_user_username_6821ab7c_like ON public.auth_user USING btree (username varchar_pattern_ops);


--
-- Name: django_admin_log_content_type_id_c4bce8eb; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX django_admin_log_content_type_id_c4bce8eb ON public.django_admin_log USING btree (content_type_id);


--
-- Name: django_admin_log_user_id_c564eba6; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX django_admin_log_user_id_c564eba6 ON public.django_admin_log USING btree (user_id);


--
-- Name: django_session_expire_date_a5c62663; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX django_session_expire_date_a5c62663 ON public.django_session USING btree (expire_date);


--
-- Name: django_session_session_key_c0390e0f_like; Type: INDEX; Schema: public; Owner: pe
--

CREATE INDEX django_session_session_key_c0390e0f_like ON public.django_session USING btree (session_key varchar_pattern_ops);


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
-- Name: auth_group_permissions auth_group_permissio_permission_id_84c5c92e_fk_auth_perm; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissio_permission_id_84c5c92e_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_group_permissions auth_group_permissions_group_id_b120cbf9_fk_auth_group_id; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_group_id_b120cbf9_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_permission auth_permission_content_type_id_2f476e4b_fk_django_co; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_content_type_id_2f476e4b_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_user_groups auth_user_groups_group_id_97559544_fk_auth_group_id; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_group_id_97559544_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_user_groups auth_user_groups_user_id_6a12ed8b_fk_auth_user_id; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_user_id_6a12ed8b_fk_auth_user_id FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_user_user_permissions auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: auth_user_user_permissions auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: cidrs cidrs_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cidrs
    ADD CONSTRAINT cidrs_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: cidrs cidrs_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.cidrs
    ADD CONSTRAINT cidrs_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


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
-- Name: dataAPI_apiuser dataAPI_apiuser_user_id_9b9cb3a6_fk_auth_user_id; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public."dataAPI_apiuser"
    ADD CONSTRAINT "dataAPI_apiuser_user_id_9b9cb3a6_fk_auth_user_id" FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: django_admin_log django_admin_log_content_type_id_c4bce8eb_fk_django_co; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_content_type_id_c4bce8eb_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: django_admin_log django_admin_log_user_id_c564eba6_fk_auth_user_id; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_user_id_c564eba6_fk_auth_user_id FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;


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
-- Name: ips ip_origin_cidr_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.ips
    ADD CONSTRAINT ip_origin_cidr_uid_fkey FOREIGN KEY (origin_cidr) REFERENCES public.cidrs(cidr_uid) NOT VALID;


--
-- Name: ips_subs ip_subs_ip_hash_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.ips_subs
    ADD CONSTRAINT ip_subs_ip_hash_fkey FOREIGN KEY (ip_hash) REFERENCES public.ips(ip_hash) ON DELETE CASCADE;


--
-- Name: ips_subs ips_subs_sub_domain_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.ips_subs
    ADD CONSTRAINT ips_subs_sub_domain_uid_fkey FOREIGN KEY (sub_domain_uid) REFERENCES public.sub_domains(sub_domain_uid) ON DELETE CASCADE;


--
-- Name: mentions mentions_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.mentions
    ADD CONSTRAINT mentions_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: organizations organizations_org_type_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_org_type_uid_fkey FOREIGN KEY (org_type_uid) REFERENCES public.org_type(org_type_uid) NOT VALID;


--
-- Name: organizations parent_child_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT parent_child_fkey FOREIGN KEY (parent_org_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


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
-- Name: report_summary_stats report_summary_stats_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.report_summary_stats
    ADD CONSTRAINT report_summary_stats_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid);


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
-- Name: shodan_vulns shodan_verified_vulns_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_vulns
    ADD CONSTRAINT shodan_verified_vulns_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: shodan_vulns shodan_verified_vulns_organizations_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.shodan_vulns
    ADD CONSTRAINT shodan_verified_vulns_organizations_uid_fkey FOREIGN KEY (organizations_uid) REFERENCES public.organizations(organizations_uid) NOT VALID;


--
-- Name: sub_domains sub_domains_data_source_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_data_source_uid_fkey FOREIGN KEY (data_source_uid) REFERENCES public.data_source(data_source_uid) NOT VALID;


--
-- Name: sub_domains sub_domains_dns_records_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_dns_records_uid_fkey FOREIGN KEY (dns_record_uid) REFERENCES public.dns_records(dns_record_uid) NOT VALID;


--
-- Name: sub_domains sub_domains_root_domain_uid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_root_domain_uid_fkey FOREIGN KEY (root_domain_uid) REFERENCES public.root_domains(root_domain_uid) NOT VALID;


--
-- Name: sub_domains sub_domains_sub_domain_root_domain_uid_key; Type: FK CONSTRAINT; Schema: public; Owner: pe
--

ALTER TABLE ONLY public.sub_domains
    ADD CONSTRAINT sub_domains_sub_domain_root_domain_uid_key FOREIGN KEY (root_domain_uid) REFERENCES public.root_domains(root_domain_uid) NOT VALID;


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
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: crossfeed
--

REVOKE ALL ON SCHEMA public FROM rdsadmin;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO crossfeed;
GRANT ALL ON SCHEMA public TO PUBLIC;

--
-- Name: was_customers public; Type: ACL; Schema: -; Owner: postgres
-- TODO: Make customer_id a foreign from was tracker once that information is available
CREATE TABLE public.was_findings (
    finding_uid UUID PRIMARY KEY,
    finding_type varchar,
    webapp_id int,
    was_org_id text,
    owasp_category varchar,
    severity varchar,
    times_detected int,
    base_score float8,
    temporal_score float8,
    fstatus varchar,
    last_detected date,
    first_detected date);
--
-- Name: was_history public; Type: ACL; Schema: -; Owner: postgres
--
CREATE TABLE public.was_history(
	was_org_id TEXT NOT NULL, 
	date_scanned date NOT NULL,
	vuln_cnt int,
	vuln_webapp_cnt int,
	web_app_cnt int,
	high_rem_time int,
	crit_rem_time int,
	PRIMARY KEY (was_org_id,date_scanned)
)
--
-- Name: was_map public; Type: ACL; Schema: -; Owner: postgres
--
CREATE TABLE public.was_map(
	was_org_id text NOT NULL,
	pe_org_id UUID,
	report_on bool,
	last_scanned date,
	primary key(was_org_id),
	CONSTRAINT pe_org_id_fk 
	FOREIGN KEY (pe_org_id) REFERENCES public.organizations(organizations_uid)
)


--
-- PostgreSQL database dump complete
--
