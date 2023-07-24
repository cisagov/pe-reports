#!/usr/bin/env python
"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import datetime
import logging
import sys
import requests
import json
import time

# Third-Party Libraries
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
from psycopg2.extensions import AsIs
from psycopg2 import sql

from .config import config, staging_config

# from pe_reports.data.cyhy_db_query import pe_db_staging_connect as connect


# from pe_reports.data.cyhy_db_query import pe_db_staging_connect as connect


# Setup logging to central file
LOGGER = logging.getLogger(__name__)

CONN_PARAMS_DIC = config()
# CONN_PARAMS_DIC_STAGING = staging_config()

# These need to filled with API key/url path in database.ini
pe_api_key = CONN_PARAMS_DIC.get("pe_api_key")
pe_api_url = CONN_PARAMS_DIC.get("pe_api_url")


def show_psycopg2_exception(err):
    """Handle errors for PostgreSQL issues."""
    err_type, err_obj, traceback = sys.exc_info()
    LOGGER.error(
        "Database connection error: %s on line number: %s", err, traceback.tb_lineno
    )


def connect():
    """Connect to PostgreSQL database."""
    conn = None
    try:
        conn = psycopg2.connect(**CONN_PARAMS_DIC)
    except OperationalError as err:

        show_psycopg2_exception(err)
        conn = None
    return conn


def close(conn):
    """Close connection to PostgreSQL."""
    conn.close()
    return


def get_scorecard_sectors():
    """Query sectors flagged to run scorecards."""
    print("running get_orgs")
    conn = connect()
    sql = """SELECT * FROM sectors
            WHERE run_scorecards = True"""
    pe_orgs = pd.read_sql(sql, conn)
    conn.close()
    return pe_orgs


def find_sub_sectors(sector):
    """Find subsectors for a given sector."""
    conn = connect()
    sql = """
            with recursive sector_queries as
            (
                select * from sectors s where s.run_scorecards = true and s.id = %(sector)s
                union all
                select e.* from sectors e
                inner join sector_queries c on e.parent_sector_uid  =  c.sector_uid
            )
            select cq.id from sector_queries cq
        """
    sub_sectors = pd.read_sql(sql, conn, params={"sector": sector})
    conn.close()
    return sub_sectors


def get_scorecard_orgs():
    """Query organizations table."""
    print("running get_orgs")
    conn = connect()
    sql = """SELECT * FROM vw_scorecard_orgs"""
    pe_orgs = pd.read_sql(sql, conn)
    conn.close()
    return pe_orgs


def refresh_views():
    """Refresh materialized views."""
    try:
        LOGGER.info("Refreshing views.")
        conn = connect()
        sql = """
            REFRESH MATERIALIZED VIEW
            public.mat_vw_fceb_total_ips
            WITH DATA
        """
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()

        sql = """
            REFRESH MATERIALIZED VIEW
            public.mat_vw_cyhy_port_counts
            WITH DATA
        """
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()

        LOGGER.info("Finished refreshing port counts.")

        sql = """
            REFRESH MATERIALIZED VIEW
            public.mat_vw_cyhy_protocol_counts
            WITH DATA
        """
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()

        LOGGER.info("Finished refreshing protocol counts.")

        sql = """
            REFRESH MATERIALIZED VIEW
            public.mat_vw_cyhy_risky_protocol_counts
            WITH DATA
        """
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()

        LOGGER.info("Finished refreshing risky protocol counts.")

        sql = """
            REFRESH MATERIALIZED VIEW
            public.mat_vw_cyhy_services_counts
            WITH DATA
        """
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()

        conn.close()

        LOGGER.info("Finished refreshing services count.")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cur.close()


# ----- IP list -------
def query_ips_counts(org_uid_list):
    """Query database for ips found from cidrs and discovered by other means."""
    conn = connect()
    print("running query_ips_counts")
    LOGGER.info("running query_ips_counts")
    # sql = """
    #     SELECT * from vw_orgs_total_ips
    #     where organizations_uid in %(org_list)s
    # """
    # total_ips_df = pd.read_sql(sql, conn, params={"org_list": tuple(org_uid_list)})

    # sql = """
    #     select o.organizations_uid,o.cyhy_db_name, coalesce(cnts.count, 0) as identified_ip_count
    #     from organizations o
    #     left join
    #     (SELECT o.organizations_uid, o.cyhy_db_name, count(i.ip) as count
    #     FROM ips i
    #     join ips_subs ip_s on ip_s.ip_hash = i.ip_hash
    #     join sub_domains sd on sd.sub_domain_uid = ip_s.sub_domain_uid
    #     join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    #     right join organizations o on rd.organizations_uid = o.organizations_uid
    #     WHERE i.origin_cidr is null
    #     GROUP BY o.organizations_uid, o.cyhy_db_name) as cnts
    #     on o.organizations_uid = cnts.organizations_uid
    #     where o.organizations_uid in %(org_list)s;
    # """
    # discovered_ips_df = pd.read_sql(sql, conn, params={"org_list": tuple(org_uid_list)})

    sql = """
         SELECT * from mat_vw_fceb_total_ips
         where organizations_uid in %(org_list)s
    """
    ips_df = pd.read_sql(sql, conn, params={"org_list": tuple(org_uid_list)})
    conn.close()
    LOGGER.info("DONE query_ips_counts")
    return ips_df


def query_domain_counts(org_uid_list):
    """Query domain counts."""
    conn = connect()
    print("running query_domain_counts")
    # cur = conn.cursor()
    # sql = """
    #     select o.organizations_uid, o.cyhy_db_name,
    #     coalesce(cnts.identified, 0) as identified,
    #     coalesce(cnts.unidentified, 0) as unidentified
    #     from organizations o
    #     left join
    #     (select rd.organizations_uid, sum(case sd.identified  when True then 1 else 0 end) identified, sum(case sd.identified when False then 1 else 0 end) unidentified
    #     from root_domains rd
    #     join sub_domains sd on sd.root_domain_uid = rd.root_domain_uid
    #     group by rd.organizations_uid) cnts
    #     on o.organizations_uid = cnts.organizations_uid
    #     where o.organizations_uid in %(org_list)s;
    # """
    sql = """
        select o.* from vw_domain_counts o
        where o.organizations_uid in %(org_list)s;
    """
    domain_counts = pd.read_sql(sql, conn, params={"org_list": tuple(org_uid_list)})
    # cur.execute(sql, {"org_list": tuple(org_uid_list)})
    # domain_counts = cur.fetchall()
    # keys = [desc[0] for desc in cur.description]
    # domain_counts = [dict(zip(keys, values)) for values in domain_counts]
    close(conn)
    return domain_counts


def query_was_sector_ttr(date_period, sector):
    """Calculate Summary results for a provided sector."""
    conn = connect()
    print("running query_was_sector_ttr")
    sql = """
        SELECT vso.sector_id, o.cyhy_db_name , wh.crit_rem_time, wh.crit_rem_cnt, wh.high_rem_time, wh.high_rem_cnt
        from was_history wh
        join was_map wm on wh.was_org_id = wm.was_org_id
        join organizations o on o.organizations_uid = wm.pe_org_id
        join vw_scorecard_orgs vso on o.organizations_uid = vso.organizations_uid
        inner join (with recursive sector_queries as
        (
            select * from sectors s where s.run_scorecards = true and s.id = %(sector)s
            union all
            select e.* from sectors e
            inner join sector_queries c on e.parent_sector_uid  =  c.sector_uid
        )
        select cq.id from sector_queries cq ) as sec on vso.sector_id = sec.id
            where wh.report_period = %(start_date)s
            and o.retired = False;
    """
    df = pd.read_sql(sql, conn, params={"sector": sector, "start_date": date_period})
    # Change critical vuln count to closed critical vuln count
    total_critical = df["crit_rem_cnt"].sum()
    df["weighted_critical"] = (df["crit_rem_cnt"] / total_critical) * df[
        "crit_rem_time"
    ]
    critical = df["weighted_critical"].sum() if total_critical > 0 else "N/A"

    # Change high vuln count to closed high vuln count
    total_high = df["high_rem_cnt"].sum()
    print(total_high)

    df["weighted_high"] = (df["high_rem_cnt"] / total_high) * df["high_rem_time"]
    high = df["weighted_high"].sum() if total_high > 0 else "N/A"
    close(conn)
    sector_dict = {"critical": critical, "high": high}
    print(sector_dict)
    # if not fceb_dict["critical"]:
    # # fceb_dict["critical"] = "N/A"

    # # if not fceb_dict["high"]:
    # # fceb_dict["high"] = "N/A"
    return sector_dict


def query_web_app_counts(date_period, org_uid_list):
    """Query web_app counts."""
    # TODO update query to pull critical and high vulns
    conn = connect()
    print("running query_web_app_counts")
    sql = """
            select o.organizations_uid, o.cyhy_db_name, cnts.date_scanned,
            coalesce(cnts.vuln_cnt, 0) as vuln_cnt,
            coalesce(cnts.vuln_webapp_cnt,0) as vuln_web_app_cnt,
            coalesce(cnts.web_app_cnt, 0) as web_app_cnt,
            coalesce(cnts.high_rem_time, Null) high_rem_time,
            coalesce(cnts.crit_rem_time, null) crit_rem_time,
            coalesce(cnts.crit_vuln_cnt, 0) crit_vuln_cnt,
            coalesce(cnts.high_vuln_cnt, 0) high_vuln_cnt,
            coalesce(cnts.crit_rem_cnt, 0) crit_rem_cnt,
            coalesce(cnts.high_rem_cnt, 0) high_rem_cnt
            from organizations o
            left join
            (SELECT o.organizations_uid, wh.*
            from was_history wh
                join was_map wm
                on wh.was_org_id = wm.was_org_id
                join organizations o
                on o.organizations_uid = wm.pe_org_id
                where wh.report_period = %(start_date)s
                ) cnts
            on o.organizations_uid = cnts.organizations_uid
            where o.organizations_uid  IN %(org_uid_list)s;

    """
    web_app_counts = pd.read_sql(
        sql,
        conn,
        params={"start_date": date_period, "org_uid_list": tuple(org_uid_list)},
    )

    close(conn)

    return web_app_counts


def query_certs(start_date, end_date):
    """Query certs counts for organizations."""
    conn = connect()
    try:
        sql = """select cd.organizations_uid , count(cc.serial)
        from cyhy_certs cc
        left join cyhy_domains cd on
        cd."domain" = cc.trimmed_subjects
        where not_before >= %(start_date)s and not_after > %(end_date)s
        group by cd.organizations_uid"""
        certs_df = pd.read_sql(
            sql, conn, params={"start_date": start_date, "end_date": end_date}
        )
        return certs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_https_scan(org_id_list):
    """Query https scan results for a given agency and month."""
    conn = connect()
    print("running query_https_scan")
    try:
        # Not sure if this should be a date filter or just latest = True
        sql = """SELECT * FROM cyhy_https_scan where cyhy_latest is True and organizations_uid IN %(org_id_list)s"""
        cur = conn.cursor()

        cur.execute(sql, {"org_id_list": tuple(org_id_list)})
        https_results = cur.fetchall()
        keys = [desc[0] for desc in cur.description]
        https_results = [dict(zip(keys, values)) for values in https_results]

        cur.close()
        return https_results
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_sslyze_scan(org_id_list, port_list):
    """Query sslyze scan results for a given agency and month."""
    # "domain", "scanned_port", "scanned_hostname", "sslv2", "sslv3", "any_3des", "any_rc4", "is_symantec_cert
    conn = connect()
    print("running query_sslyze_scan")
    try:
        # Need to verify where statement: other options scan_date, first_seen, last_seen
        sql = """
                SELECT * FROM cyhy_sslyze where cyhy_latest is True and scanned_port in %(port_list)s
                and organizations_uid in %(org_id_list)s
            """
        cur = conn.cursor()

        cur.execute(
            sql, {"port_list": tuple(port_list), "org_id_list": tuple(org_id_list)}
        )
        https_results = cur.fetchall()
        keys = [desc[0] for desc in cur.description]
        https_results = [dict(zip(keys, values)) for values in https_results]

        cur.close()
        return https_results
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_trusty_mail(org_id_list):
    """Query trusty mail scan results for a given agency and month."""
    # all_domains_cursor = self.__db.trustymail.find(
    #         {"latest": True, "agency.name": agency}, no_cursor_timeout=True
    #     )
    conn = connect()
    print("running query_trusty_mail")
    try:
        # Need to verify where statement: other options scan_date, first_seen, last_seen
        sql = """SELECT * FROM cyhy_trustymail where cyhy_latest is True and organizations_uid in %(org_uid)s"""
        cur = conn.cursor()

        cur.execute(sql, {"org_uid": tuple(org_id_list)})
        https_results = cur.fetchall()
        keys = [desc[0] for desc in cur.description]
        https_results = [dict(zip(keys, values)) for values in https_results]

        cur.close()
        return https_results
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_cyhy_snapshots(start_date, end_date):
    """Query PE database for cyhy snapshots."""
    conn = connect()
    sql = """select o.organizations_uid, o.cyhy_db_name, cs.host_count, cs.vulnerable_host_count, cs.cyhy_last_change
        from organizations o
        left join cyhy_snapshots cs on
        o.organizations_uid = cs.organizations_uid
        where (o.fceb = true or o.fceb_child = true) and o.retired = False and cs.cyhy_last_change  >= %(start_date)s and cs.cyhy_last_change < %(end_date)s"""

    snapshots = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
    )
    conn.close
    return snapshots


# **
def query_software_scans(start_date, end_date, org_id_list=[]):
    """Query the PE database for vuln data identified by the VS team scans."""
    conn = connect()
    LOGGER.info("running query_software_scans")
    if org_id_list:
        sql = """select o.organizations_uid, o.cyhy_db_name, count(cvs.plugin_name)
        from organizations o
        left join cyhy_vuln_scans cvs on
        o.organizations_uid = cvs.organizations_uid
        where o.organizations_uid in %(org_list)s
        and cvs.plugin_name = 'Unsupported Web Server Detection' and
        cvs.cyhy_time  >= %(start_date)s and cvs.cyhy_time < %(end_date)s
        group by o.organizations_uid, o.cyhy_db_name """

        software_count = pd.read_sql(
            sql,
            conn,
            params={
                "org_list": tuple(org_id_list),
                "start_date": start_date,
                "end_date": end_date,
            },
        )
    else:
        sql = """select o.organizations_uid, o.cyhy_db_name, count(cvs.plugin_name),
        from organizations o
        left join cyhy_vuln_scans cvs on
        o.organizations_uid = cvs.organizations_uid
        where (o.fceb = true or o.fceb_child = True) and o.retired = False
        and cvs.plugin_name = 'Unsupported Web Server Detection'
        and cvs.cyhy_time  >= %(start_date)s and cvs.cyhy_time < %(end_date)s
        group by o.organizations_uid, o.cyhy_db_name """

        software_count = pd.read_sql(
            sql, conn, params={"start_date": start_date, "end_date": end_date}
        )
    conn.close()

    return software_count


# **
def query_cyhy_port_scans(start_date, end_date, org_uid_list=[]):
    """Query port info identified by vulnerability scanning."""
    try:
        conn = connect()
        print("running query_cyhy_port_scans")
        if org_uid_list:
            sql = """select o.organizations_uid, o.cyhy_db_name, cps.ip, cps.port, cps.service_name, cps.state
                from organizations o
                left join cyhy_port_scans cps on
                o.organizations_uid = cps.organizations_uid
                where cps.cyhy_time  >= %(start_date)s and cps.cyhy_time < %(end_date)s
                and o.organizations_uid in %(org_list)s """

            port_data = pd.read_sql(
                sql,
                conn,
                params={
                    "start_date": start_date,
                    "end_date": end_date,
                    "org_list": tuple(org_uid_list),
                },
            )
        else:
            sql = """select o.organizations_uid, o.cyhy_db_name, cps.ip, cps.port, cps.service_name, cps.state
                from organizations o
                left join cyhy_port_scans cps on
                o.organizations_uid = cps.organizations_uid
                where (o.fceb = True or o.fceb_child = True) and o.retired = False and cps.cyhy_time  >= %(end_date)s and cps.cyhy_time < %(end_date)s
                """

            port_data = pd.read_sql(
                sql, conn, params={"start_date": start_date, "end_date": end_date}
            )

        conn.close()
        return port_data
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# **
def query_vuln_tickets(org_id_list=[]):
    """Query current open vulns counts based on tickets."""
    conn = connect()
    LOGGER.info("running query_vuln_tickets")
    if org_id_list:
        sql = """
            select
                o.organizations_uid,
                o.cyhy_db_name,
                coalesce (cnts.high, 0) as high,
                coalesce (cnts.critical, 0) as critical,
                coalesce (cnts.kev, 0) as kev
            from organizations o
            left join
                (select
                    ct.organizations_uid,
                    sum(case  when ct.cvss_base_score >= 7 and ct.cvss_base_score <9  then 1 else 0 end)as  high,
                    sum(case  when ct.cvss_base_score >= 9 and ct.cvss_base_score <=10  then 1 else 0 end)as  critical,
                    sum(case  when ct.cve in (select kev from cyhy_kevs) then 1 else 0 end)as  kev
                from cyhy_tickets ct
                join
                    organizations o on o.organizations_uid = ct.organizations_uid
                where ct.time_closed is Null and false_positive = False
                group by ct.organizations_uid) cnts
            on  o.organizations_uid =cnts.organizations_uid
            where o.organizations_uid  IN %(org_id_list)s;
        """

        vs_vuln_counts = pd.read_sql(
            sql, conn, params={"org_id_list": tuple(org_id_list)}
        )

    else:
        sql = """
            select
                o.organizations_uid,
                o.cyhy_db_name,
                coalesce (cnts.high, 0) as high,
                coalesce (cnts.critical, 0) as critical,
                coalesce (cnts.kev, 0) as kev
            from organizations o
            left join
                (select
                    ct.organizations_uid,
                    sum(case  when ct.cvss_base_score >= 7 and ct.cvss_base_score <9  then 1 else 0 end)as  high,
                    sum(case  when ct.cvss_base_score >= 9 then 1 else 0 end)as  critical,
                    sum(case  when ct.cve in (select kev from cyhy_kevs) then 1 else 0 end)as  kev
                from cyhy_tickets ct
                join
                    organizations o on o.organizations_uid = ct.organizations_uid
                where ct.time_closed is Null and false_positive = False
                group by ct.organizations_uid) cnts
            on  o.organizations_uid =cnts.organizations_uid
            where (o.fceb = True or o.fceb_child = True) and retired = False;
        """

        vs_vuln_counts = pd.read_sql(sql, conn)

    conn.close()

    return vs_vuln_counts


# **
def query_vuln_remediation(start_date, end_date, org_id_list):
    """Query vulnerability time to remediate."""
    conn = connect()
    print("running query_vuln_remediation")
    try:
        sql = """select o.cyhy_db_name, o.fceb, o.report_on, ct.cvss_base_score, ct.cve, ct.time_opened, ct.time_closed
        from organizations o
        left join cyhy_tickets ct on
        o.organizations_uid = ct.organizations_uid
        where ct.false_positive = 'False' and ct.time_closed >= %(start_date)s and ct.time_closed < %(end_date)s
        and o.organizations_uid IN %(org_id_list)s"""
        tickets_df = pd.read_sql(
            sql,
            conn,
            params={
                "start_date": start_date,
                "end_date": end_date,
                "org_id_list": tuple(org_id_list),
            },
        )
        return tickets_df

    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_open_vulns(org_id_list):
    """Query open vulnerabilities time since first seen."""
    conn = connect()
    print("running query_open_vulns")
    try:
        sql = """
        select o.cyhy_db_name, o.fceb, ct.cvss_base_score, ct.cve, ct.time_opened
        from cyhy_tickets ct
        left join organizations o on
        o.organizations_uid = ct.organizations_uid
        where ct.false_positive = 'False' and ct.time_closed is Null and (ct.cve != null or (ct.cvss_base_score != 'Nan' and ct.cvss_base_score >= 7.0))
        and o.organizations_uid IN %(org_id_list)s"""
        tickets_df = pd.read_sql(
            sql,
            conn,
            params={
                "org_id_list": tuple(org_id_list),
            },
        )
        return tickets_df

    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def execute_scorecard_summary_data(summary_dict):
    """Save summary statistics for an organization to the database."""
    try:
        if summary_dict["web_apps_kev"] in ["N/A", None]:
            summary_dict["web_apps_kev"] = 0

        if summary_dict["ext_host_kev"] in ["N/A", None]:
            summary_dict["ext_host_kev"] = 0

        if summary_dict["web_apps_vuln_critical"] in ["N/A", None]:
            summary_dict["web_apps_vuln_critical"] = 0

        if summary_dict["ext_host_vuln_critical"] in ["N/A", None]:
            summary_dict["ext_host_vuln_critical"] = 0

        if summary_dict["ext_host_vuln_high"] in ["N/A", None]:
            summary_dict["ext_host_vuln_high"] = 0

        if summary_dict["web_apps_vuln_high"] in ["N/A", None]:
            summary_dict["web_apps_vuln_high"] = 0
        conn = connect()
        cur = conn.cursor()
        sql = """
        INSERT INTO scorecard_summary_stats(
            organizations_uid,
            start_date,
            end_date,
            score,
            discovery_score,
            profiling_score,
            identification_score,
            tracking_score,
            ips_self_reported,
            ips_discovered,
            ips_monitored,
            domains_self_reported,
            domains_discovered,
            domains_monitored,
            web_apps_self_reported,
            web_apps_discovered,
            web_apps_monitored,
            certs_self_reported,
            certs_discovered,
            certs_monitored,
            total_ports,
            risky_ports,
            protocols,
            insecure_protocols,
            total_services,
            unsupported_software,
            ext_host_kev,
            ext_host_vuln_critical,
            ext_host_vuln_high,
            web_apps_kev,
            web_apps_vuln_critical,
            web_apps_vuln_high,
            total_kev,
            total_vuln_critical,
            total_vuln_high,
            org_avg_days_remediate_kev,
            org_avg_days_remediate_critical,
            org_avg_days_remediate_high,
            sect_avg_days_remediate_kev,
            sect_avg_days_remediate_critical,
            sect_avg_days_remediate_high,
            bod_22_01,
            bod_19_02_critical,
            bod_19_02_high,
            org_web_avg_days_remediate_critical,
            org_web_avg_days_remediate_high,
            sect_web_avg_days_remediate_critical,
            sect_web_avg_days_remediate_high,
            email_compliance_pct,
            https_compliance_pct,
            sector_name
        )
        VALUES(
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
            %s
        )
        ON CONFLICT(organizations_uid, start_date, sector_name)
        DO
        UPDATE SET
            score = EXCLUDED.score,
            discovery_score = EXCLUDED.discovery_score,
            profiling_score = EXCLUDED.profiling_score,
            identification_score = EXCLUDED.identification_score,
            tracking_score = EXCLUDED.tracking_score,
            ips_self_reported = EXCLUDED.ips_self_reported,
            ips_discovered = EXCLUDED.ips_discovered,
            ips_monitored = EXCLUDED.ips_monitored,
            domains_self_reported = EXCLUDED.domains_self_reported,
            domains_discovered = EXCLUDED.domains_discovered,
            domains_monitored = EXCLUDED.domains_monitored,
            web_apps_self_reported = EXCLUDED.web_apps_self_reported,
            web_apps_discovered = EXCLUDED.web_apps_discovered,
            web_apps_monitored = EXCLUDED.web_apps_monitored,
            certs_self_reported = EXCLUDED.certs_self_reported,
            certs_discovered = EXCLUDED.certs_discovered,
            certs_monitored = EXCLUDED.certs_monitored,
            total_ports = EXCLUDED.total_ports,
            risky_ports = EXCLUDED.risky_ports,
            protocols = EXCLUDED.protocols,
            insecure_protocols = EXCLUDED.insecure_protocols,
            total_services = EXCLUDED.total_services,
            unsupported_software = EXCLUDED.unsupported_software,
            ext_host_kev = EXCLUDED.ext_host_kev,
            ext_host_vuln_critical = EXCLUDED.ext_host_vuln_critical,
            ext_host_vuln_high = EXCLUDED.ext_host_vuln_high,
            web_apps_kev = EXCLUDED.web_apps_kev,
            web_apps_vuln_critical = EXCLUDED.web_apps_vuln_critical,
            web_apps_vuln_high = EXCLUDED.web_apps_vuln_high,
            total_kev = EXCLUDED.total_kev,
            total_vuln_critical = EXCLUDED.total_vuln_critical,
            total_vuln_high = EXCLUDED.total_vuln_high,
            org_avg_days_remediate_kev = EXCLUDED.org_avg_days_remediate_kev,
            org_avg_days_remediate_critical = EXCLUDED.org_avg_days_remediate_critical,
            org_avg_days_remediate_high = EXCLUDED.org_avg_days_remediate_high,
            sect_avg_days_remediate_kev = EXCLUDED.sect_avg_days_remediate_kev,
            sect_avg_days_remediate_critical = EXCLUDED.sect_avg_days_remediate_critical,
            sect_avg_days_remediate_high = EXCLUDED.sect_avg_days_remediate_high,
            bod_22_01 = EXCLUDED.bod_22_01,
            bod_19_02_critical = EXCLUDED.bod_19_02_critical,
            bod_19_02_high = EXCLUDED.bod_19_02_high,
            org_web_avg_days_remediate_critical = EXCLUDED.org_web_avg_days_remediate_critical,
            org_web_avg_days_remediate_high = EXCLUDED.org_web_avg_days_remediate_high,
            sect_web_avg_days_remediate_critical = EXCLUDED.sect_web_avg_days_remediate_critical,
            sect_web_avg_days_remediate_high = EXCLUDED.sect_web_avg_days_remediate_high,
            email_compliance_pct = EXCLUDED.email_compliance_pct,
            https_compliance_pct = EXCLUDED.https_compliance_pct;
        """
        summary_dict = {k: None if v == "N/A" else v for k, v in summary_dict.items()}
        print(summary_dict)
        print(summary_dict["sector_name"])
        cur.execute(
            sql,
            (
                summary_dict["organizations_uid"],
                summary_dict["start_date"],
                summary_dict["end_date"],
                AsIs(summary_dict["score"]),
                AsIs(summary_dict["discovery_score"]),
                AsIs(summary_dict["profiling_score"]),
                AsIs(summary_dict["identification_score"]),
                AsIs(summary_dict["tracking_score"]),
                AsIs(summary_dict["ips_self_reported"]),
                AsIs(summary_dict["ips_discovered"]),
                AsIs(summary_dict["ips_monitored"]),
                AsIs(summary_dict["domains_self_reported"]),
                AsIs(summary_dict["domains_discovered"]),
                AsIs(summary_dict["domains_monitored"]),
                AsIs(summary_dict["web_apps_self_reported"]),
                AsIs(summary_dict["web_apps_discovered"]),
                AsIs(summary_dict["web_apps_monitored"]),
                AsIs(summary_dict["certs_self_reported"]),
                AsIs(summary_dict["certs_discovered"]),
                AsIs(summary_dict["certs_monitored"]),
                AsIs(summary_dict["total_ports"]),
                AsIs(summary_dict["risky_ports"]),
                AsIs(summary_dict["protocols"]),
                AsIs(summary_dict["insecure_protocols"]),
                AsIs(summary_dict["total_services"]),
                AsIs(summary_dict["unsupported_software"]),
                AsIs(summary_dict["ext_host_kev"]),
                AsIs(summary_dict["ext_host_vuln_critical"]),
                AsIs(summary_dict["ext_host_vuln_high"]),
                AsIs(summary_dict["web_apps_kev"]),
                AsIs(summary_dict["web_apps_vuln_critical"]),
                AsIs(summary_dict["web_apps_vuln_high"]),
                AsIs(summary_dict["web_apps_kev"] + summary_dict["ext_host_kev"]),
                AsIs(
                    summary_dict["web_apps_vuln_critical"]
                    + summary_dict["ext_host_vuln_critical"]
                ),
                AsIs(
                    summary_dict["ext_host_vuln_high"]
                    + summary_dict["web_apps_vuln_high"]
                ),
                AsIs(summary_dict["org_avg_days_remediate_kev"]),
                AsIs(summary_dict["org_avg_days_remediate_critical"]),
                AsIs(summary_dict["org_avg_days_remediate_high"]),
                AsIs(summary_dict["sect_avg_days_remediate_kev"]),
                AsIs(summary_dict["sect_avg_days_remediate_critical"]),
                AsIs(summary_dict["sect_avg_days_remediate_high"]),
                summary_dict["bod_22_01-01"],
                summary_dict["bod_19_02_critical"],
                summary_dict["bod_19_02_high"],
                AsIs(summary_dict["org_web_avg_days_remediate_critical"]),
                AsIs(summary_dict["org_web_avg_days_remediate_high"]),
                AsIs(summary_dict["sect_web_avg_days_remediate_critical"]),
                AsIs(summary_dict["sect_web_avg_days_remediate_high"]),
                AsIs(summary_dict["email_compliance_pct"]),
                AsIs(summary_dict["https_compliance_pct"]),
                summary_dict["sector_name"],
            ),
        )
        conn.commit()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cur.close()


def get_scorecard_metrics_past(org_uid, date, sector):
    """Get the past Scorecard summary data for an organization."""
    conn = connect()
    sql = """select * from scorecard_summary_stats sss
                where organizations_uid = %(org_id)s
                and end_date = %(date)s
                and sector_name = %(sector)s;"""
    df = pd.read_sql(
        sql, conn, params={"org_id": org_uid, "date": date, "sector": sector}
    )
    conn.close()
    return df


def get_scorecard_metrics_current(org_uid, date, sector):
    """Get the current Scorecard summary data for an organization."""
    conn = connect()
    sql = """select * from scorecard_summary_stats sss
                where organizations_uid = %(org_id)s
                and start_date = %(date)s
                and sector_name = %(sector)s;"""
    df = pd.read_sql(
        sql, conn, params={"org_id": org_uid, "date": date, "sector": sector}
    )
    conn.close()
    return df


def query_scorecard_data(org_uid, start_date, sector):
    """Requery the data for a given org and date."""
    this_period_data = get_scorecard_metrics_current(org_uid, start_date, sector)
    scorecard_dict = this_period_data.to_dict("records")[0]
    last_period_data = get_scorecard_metrics_past(org_uid, start_date, sector)
    print("test query_scorercard_data")
    print(last_period_data)
    print("test complete")

    if last_period_data.empty:
        LOGGER.error("No Scorecard summary data for the last report period.")
        ips_monitored_trend = scorecard_dict["ips_monitored"]
        domains_monitored_trend = scorecard_dict["domains_monitored"]
        web_apps_monitored_trend = scorecard_dict["web_apps_monitored"]
        certs_monitored_trend = scorecard_dict["certs_monitored"]
        ports_total_trend = scorecard_dict["total_ports"]
        ports_risky_trend = scorecard_dict["risky_ports"]
        protocol_total_trend = scorecard_dict["protocols"]
        protocol_insecure_trend = scorecard_dict["insecure_protocols"]
        services_total_trend = scorecard_dict["total_services"]
        software_unsupported_trend = scorecard_dict["unsupported_software"]
        email_compliance_last_period = scorecard_dict["email_compliance_pct"]
        https_compliance_last_period = scorecard_dict["https_compliance_pct"]
        discovery_trend = scorecard_dict.get("discovery_score", 0)
        profiling_trend = scorecard_dict.get("profiling_score", 0)
        identification_trend = scorecard_dict.get("identification_score", 0)
        tracking_trend = scorecard_dict.get("tracking_score", 0)
    else:
        last_scorecard_dict = last_period_data.to_dict("records")[0]
        ips_monitored_trend = last_scorecard_dict["ips_monitored"]
        domains_monitored_trend = last_scorecard_dict["domains_monitored"]
        web_apps_monitored_trend = last_scorecard_dict["web_apps_monitored"]
        certs_monitored_trend = last_scorecard_dict["certs_monitored"]
        ports_total_trend = last_scorecard_dict["total_ports"]
        ports_risky_trend = last_scorecard_dict["risky_ports"]
        protocol_total_trend = last_scorecard_dict["protocols"]
        protocol_insecure_trend = last_scorecard_dict["insecure_protocols"]
        services_total_trend = last_scorecard_dict["total_services"]
        software_unsupported_trend = last_scorecard_dict["unsupported_software"]
        email_compliance_last_period = last_scorecard_dict["email_compliance_pct"]
        https_compliance_last_period = last_scorecard_dict["https_compliance_pct"]
        discovery_trend = last_scorecard_dict["discovery_score"]
        profiling_trend = last_scorecard_dict["profiling_score"]
        identification_trend = last_scorecard_dict["identification_score"]
        tracking_trend = last_scorecard_dict["tracking_score"]

    past_scorecard_metrics_dict = {
        "ips_monitored_trend": ips_monitored_trend,
        "domains_monitored_trend": domains_monitored_trend,
        "web_apps_monitored_trend": web_apps_monitored_trend,
        "certs_monitored_trend": certs_monitored_trend,
        "ports_total_trend": ports_total_trend,
        "ports_risky_trend": ports_risky_trend,
        "protocol_total_trend": protocol_total_trend,
        "protocol_insecure_trend": protocol_insecure_trend,
        "services_total_trend": services_total_trend,
        "software_unsupported_trend": software_unsupported_trend,
        "email_compliance_last_period": email_compliance_last_period,
        "https_compliance_last_period": https_compliance_last_period,
        "discovery_trend": discovery_trend,
        "profiling_trend": profiling_trend,
        "identification_trend": identification_trend,
        "tracking_trend": tracking_trend,
    }
    scorecard_dict.update(past_scorecard_metrics_dict)

    return scorecard_dict


def find_last_scan_date():
    """Find the most recent time we pulled data from cyhy."""
    conn = connect()

    sql = """
    select max(last_seen) from cyhy_sslyze cs
    """
    cur = conn.cursor()

    cur.execute(sql)
    last_scanned = cur.fetchone()
    cur.close()

    close(conn)
    return last_scanned


def find_last_data_updated(id_list):
    """Find the last time a stakeholder updated their data in cyhy."""
    conn = connect()

    sql = """
        select greatest(
            (
                select max(first_seen) as first_seen
                from cyhy_db_assets cda
                where cda.org_id in %(id_list)s
            ),
            (
                select max(last_seen) as last_seen
                from cyhy_db_assets cda
                where last_seen <> (select max(last_seen) from cyhy_db_assets cda )
                and cda.org_id in %(id_list)s
            )
        );
    """
    cur = conn.cursor()

    cur.execute(sql, {"id_list": tuple(id_list)})
    last_updated = cur.fetchone()
    cur.close()

    close(conn)
    return last_updated


def query_sector_ttr(month, year, sector):
    """Return a given sector's time to remediate data for vulns closed in a given month and year."""
    conn = connect()
    sql = """
    select ttr.organizations_uid, ttr.cyhy_db_name, ttr.sector_id,
    EXTRACT(epoch FROM ttr.kev_ttr) / 86400 as kev_ttr, kev_count,
    EXTRACT(epoch FROM ttr.critical_ttr) / 86400 as critical_ttr, critical_count,
    EXTRACT(epoch FROM ttr.high_ttr) / 86400 as high_ttr, high_count
    from vw_sector_time_to_remediate ttr
    inner join (with recursive sector_queries as
    (
        select * from sectors s where s.run_scorecards = true and s.id = %(sector)s
        union all
        select e.* from sectors e
        inner join sector_queries c on e.parent_sector_uid  =  c.sector_uid
    )
    select cq.id from sector_queries cq ) as sec on ttr.sector_id = sec.id
    where month_seen = %(month_seen)s and year_seen = %(year_seen)s
    """
    df = pd.read_sql(
        sql, conn, params={"sector": sector, "month_seen": month, "year_seen": year}
    )
    conn.close()
    df_unedited = df.copy()
    total_kevs = df["kev_count"].sum()
    df["weighted_kev"] = (df["kev_count"] / total_kevs) * df["kev_ttr"]

    total_critical = df["critical_count"].sum()
    df["weighted_critical"] = (df["critical_count"] / total_critical) * df[
        "critical_ttr"
    ]

    total_high = df["high_count"].sum()
    df["weighted_high"] = (df["high_count"] / total_high) * df["high_ttr"]
    sector_dict = {
        "name": sector,
        "ATTR KEVs": df["weighted_kev"].sum(),
        "ATTR Crits": df["weighted_critical"].sum(),
        "ATTR Highs": df["weighted_high"].sum(),
    }
    return (df_unedited, sector_dict)


def query_profiling_views(start_date, org_uid_list):
    """Query profiling datas from relevant views."""
    LOGGER.info("Query profiling views")
    org_uid_list = tuple(org_uid_list)
    profiling_dict = {}
    conn = connect()
    ports_sql = """
        SELECT *
        FROM mat_vw_cyhy_port_counts
        where report_period = %(start_date)s and organizations_uid in %(uid_list)s
    """

    ports_df = pd.read_sql(
        ports_sql, conn, params={"start_date": start_date, "uid_list": org_uid_list}
    )
    profiling_dict["ports_count"] = ports_df["ports"].sum()
    profiling_dict["risky_ports_count"] = ports_df["risky_ports"].sum()

    protocols_sql = """
        SELECT *
        FROM mat_vw_cyhy_protocol_counts
        where report_period = %(start_date)s and organizations_uid in %(uid_list)s
    """

    protocols_df = pd.read_sql(
        protocols_sql, conn, params={"start_date": start_date, "uid_list": org_uid_list}
    )
    profiling_dict["protocols_count"] = protocols_df["protocols"].sum()

    risky_protcols_sql = """
        SELECT *
        FROM mat_vw_cyhy_risky_protocol_counts
        where report_period = %(start_date)s and organizations_uid in %(uid_list)s
    """
    risky_protocols_df = pd.read_sql(
        risky_protcols_sql,
        conn,
        params={"start_date": start_date, "uid_list": org_uid_list},
    )
    profiling_dict["risky_protocols_count"] = risky_protocols_df[
        "risky_protocols"
    ].sum()

    services_sql = """
        SELECT *
        FROM mat_vw_cyhy_services_counts
        where report_period = %(start_date)s and organizations_uid in %(uid_list)s
    """
    services_df = pd.read_sql(
        services_sql, conn, params={"start_date": start_date, "uid_list": org_uid_list}
    )
    profiling_dict["services"] = services_df["services"].sum()

    conn.close()
    return profiling_dict


def get_stakeholders():
    """Get stakeholders from the materialized view."""
    conn = connect()
    try:
        sql = """
            select o.organizations_uid, o.report_on
            from organizations o
            where o.retired = False
        """
        pe_orgs_df = pd.read_sql(sql, conn)
        return pe_orgs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_was_stakeholders():
    """Query WAS stakeholders."""
    conn = connect()
    try:
        sql = """select o.organizations_uid, o.cyhy_db_name, wm.was_org_id, o.fceb, o.fceb_child, o.parent_org_uid
        from organizations o
        right join was_map wm on
        o.organizations_uid = wm.pe_org_id"""
        fceb_orgs_df = pd.read_sql(sql, conn)
        return fceb_orgs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_hosts(start_date, end_date, df_orgs=[]):
    """Get host data from cyhy snapshots table."""
    conn = connect()
    try:
        sql = """select o.organizations_uid, o.cyhy_db_name, cs.host_count, cs.vulnerable_host_count, o.parent_org_uid, max(cs.cyhy_last_change)
        from organizations o
        left join cyhy_snapshots cs on
        o.organizations_uid = cs.organizations_uid
        where cs.cyhy_last_change >= %(start_date)s AND cs.cyhy_last_change < %(end_date)s and o.organizations_uid in %(df_orgs)s
        group by o.organizations_uid, o.cyhy_db_name, cs.host_count, cs.vulnerable_host_count, o.parent_org_uid"""
        snapshots_df = pd.read_sql(
            sql,
            conn,
            params={
                "start_date": start_date,
                "end_date": end_date,
                "df_orgs": tuple(df_orgs),
            },
        )
        return snapshots_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_port_scans(start_date, end_date, df_orgs=[]):
    """Get port data from the materialized view."""
    conn = connect()
    try:
        sql = """select mvcpc.organizations_uid, mvcpc.cyhy_db_name, mvcpc.report_period, mvcpc.ports, mvcpc.risky_ports, mvcpc2.protocols, mvcrpc.risky_protocols, mvcsc2.services, o.parent_org_uid
        from mat_vw_cyhy_port_counts mvcpc
        inner join mat_vw_cyhy_protocol_counts mvcpc2 on
        mvcpc2.organizations_uid  = mvcpc.organizations_uid
        inner join mat_vw_cyhy_risky_protocol_counts mvcrpc on
        mvcrpc.organizations_uid  = mvcpc.organizations_uid
        inner join organizations o on
        o.organizations_uid = mvcpc.organizations_uid
        inner join mat_vw_cyhy_services_counts mvcsc on
        mvcsc.organizations_uid = mvcpc.organizations_uid
        inner join mat_vw_cyhy_services_counts mvcsc2 on
        mvcsc2.organizations_uid  = mvcpc.organizations_uid
        where mvcpc.report_period >= %(start_date)s and mvcpc.report_period < %(end_date)s and o.organizations_uid in %(df_orgs)s"""
        df_port_scans = pd.read_sql(
            sql,
            conn,
            params={
                "start_date": start_date,
                "end_date": end_date,
                "df_orgs": tuple(df_orgs),
            },
        )
        return df_port_scans
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_was_summary(df_orgs=[]):
    """Query the WAS summary data."""
    conn = connect()
    try:
        sql = """SELECT ws.was_org_id, wm.pe_org_id, ws.webapp_count, ws.webapp_with_vulns_count, max(ws.last_updated)
        from was_summary ws
        left join was_map wm on
        ws.was_org_id = wm.was_org_id
        where wm.pe_org_id notnull and text(wm.pe_org_id) in %(df_orgs)s
        group by ws.was_org_id, wm.pe_org_id, ws.webapp_count, ws.webapp_with_vulns_count"""
        was_data_df = pd.read_sql(sql, conn, params={"df_orgs": tuple(df_orgs)})
        return was_data_df
    except (Exception, psycopg2.DatabaseError) as error:
        print("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_software(start_date, end_date, df_orgs=[]):
    """Query software data from vuln_scans table."""
    conn = connect()
    try:
        sql = """select o.organizations_uid, o.cyhy_db_name, o.parent_org_uid, o.fceb, count(cvs.plugin_name)
        from organizations o
        left join cyhy_vuln_scans cvs on
        o.organizations_uid = cvs.organizations_uid
        where cvs.plugin_name = 'Unsupported Web Server Detection' and cvs.cyhy_time >= %(start_date)s AND cvs.cyhy_time <%(end_date)s and o.organizations_uid in %(df_orgs)s
        group by o.organizations_uid, o.cyhy_db_name, o.parent_org_uid, o.fceb"""
        vuln_scans_df = pd.read_sql(
            sql,
            conn,
            params={
                "start_date": start_date,
                "end_date": end_date,
                "df_orgs": tuple(df_orgs),
            },
        )
        return vuln_scans_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_bod_18(start_date):
    """Query BOD 18-01 data necessary to calculate compliance."""
    conn = connect()
    try:
        sql = """SELECT o.organizations_uid, o.cyhy_db_name, o.fceb, o.fceb_child, sss.email_compliance_pct, sss.https_compliance_pct
        FROM scorecard_summary_stats sss
        left join organizations o on
        sss.organizations_uid = o.organizations_uid
        where sss.email_compliance_pct notnull and sss.https_compliance_pct notnull and start_date = %(start_date)s"""
        bod_18_df = pd.read_sql(sql, conn, params={"start_date": start_date})
        return bod_18_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_ports_protocols(start_date, end_date, df_orgs=[]):
    """Query ports and protocols data."""
    conn = connect()
    try:
        sql = """select mvcpc.organizations_uid, mvcpc.cyhy_db_name, mvcpc.report_period, mvcpc.ports, mvcpc.risky_ports, mvcpc2.protocols, mvcrpc.risky_protocols, o.parent_org_uid
        from mat_vw_cyhy_port_counts mvcpc
        inner join mat_vw_cyhy_protocol_counts mvcpc2 on
        mvcpc2.organizations_uid  = mvcpc.organizations_uid
        inner join mat_vw_cyhy_risky_protocol_counts mvcrpc on
        mvcrpc.organizations_uid  = mvcpc.organizations_uid
        inner join organizations o on
        o.organizations_uid = mvcpc.organizations_uid
        where mvcpc.report_period >= %(start_date)s and mvcpc.report_period < %(end_date)s and o.organizations_uid in %(df_orgs)s"""
        df_port_scans = pd.read_sql(
            sql,
            conn,
            params={
                "start_date": start_date,
                "end_date": end_date,
                "df_orgs": tuple(df_orgs),
            },
        )
        return df_port_scans
    except (Exception, psycopg2.DatabaseError) as error:
        print("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_pe_vulns(start_date, end_date, df_orgs=[]):
    """Query P&E identified vulnerabilities."""
    conn = connect()
    try:
        sql = """select o.cyhy_db_name, o.organizations_uid, o.parent_org_uid, vsv."timestamp", vsv.cve, vsv.cvss
        from vw_shodanvulns_verified vsv
        left join organizations o on
        o.organizations_uid = vsv.organizations_uid
        where vsv."timestamp" >= %(start_date)s AND vsv."timestamp" < %(end_date)s and o.organizations_uid in %(df_orgs)s"""
        pe_vulns_df = pd.read_sql(
            sql,
            conn,
            params={
                "start_date": start_date,
                "end_date": end_date,
                "df_orgs": tuple(df_orgs),
            },
        )
        return pe_vulns_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_kevs():
    """Query all KEVs from database."""
    conn = connect()
    try:
        sql = """select KEV from cyhy_kevs"""
        kevs_df = pd.read_sql(sql, conn)
        return kevs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_vs_open_vulns(df_orgs=[]):
    """Query open vulnerabilities."""
    conn = connect()
    try:
        sql = """select o.cyhy_db_name, o.organizations_uid, o.parent_org_uid, ct.cve, ct.cvss_base_score, ct.time_opened
        from cyhy_tickets ct
        left join organizations o on
        ct.organizations_uid = o.organizations_uid
        where ct.false_positive = 'false' and ct.cvss_base_score != 'NaN' and ct.time_closed is null and o.organizations_uid in %(df_orgs)s"""
        vs_open_vulns_df = pd.read_sql(sql, conn, params={"df_orgs": tuple(df_orgs)})
        return vs_open_vulns_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_vs_closed_vulns(start_date, end_date, df_orgs=[]):
    """Query closed vulnerabilities."""
    conn = connect()
    try:
        sql = """select o.cyhy_db_name, o.organizations_uid, o.parent_org_uid, ct.cve, ct.cvss_base_score, ct.time_opened, ct.time_closed
        from cyhy_tickets ct
        left join organizations o on
        ct.organizations_uid = o.organizations_uid
        where ct.false_positive = 'false' and ct.cvss_base_score != 'NaN' and (ct.time_closed >= %(start_date)s and ct.time_closed < %(end_date)s) and o.organizations_uid in %(df_orgs)s"""
        vs_open_vulns_df = pd.read_sql(
            sql,
            conn,
            params={
                "start_date": start_date,
                "end_date": end_date,
                "df_orgs": tuple(df_orgs),
            },
        )
        return vs_open_vulns_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_was_open_vulns(start_date, end_date, df_orgs=[]):
    """Query open WAS vulnerabilities."""
    conn = connect()
    try:
        sql = """select wf.was_org_id, wm.pe_org_id, wf.base_score, wf.fstatus, wf.last_detected, wf.first_detected
        from was_findings wf
        left join was_map wm on
        wf.was_org_id = wm.was_org_id
        where (wf.last_detected >= %(start_date)s and wf.last_detected < %(end_date)s) and wf.fstatus != 'FIXED' and wm.pe_org_id notnull and text(wm.pe_org_id) in %(df_orgs)s"""
        was_open_vulns_df = pd.read_sql(
            sql,
            conn,
            params={
                "start_date": start_date,
                "end_date": end_date,
                "df_orgs": tuple(df_orgs),
            },
        )
        return was_open_vulns_df
    except (Exception, psycopg2.DatabaseError) as error:
        print("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_was_closed_vulns(start_date, end_date, df_orgs=[]):
    """Query WAS closed vulnerabilities."""
    conn = connect()
    try:
        sql = """select wf.was_org_id, wm.pe_org_id ,wf.base_score, wf.fstatus, wf.last_detected, wf.first_detected
        from was_findings wf
        left join was_map wm on
        wf.was_org_id = wm.was_org_id
        where (wf.last_detected >= %(start_date)s and wf.last_detected < %(end_date)s) and wf.fstatus = 'FIXED' and wm.pe_org_id notnull and text(wm.pe_org_id) in %(df_orgs)s"""
        was_open_vulns_df = pd.read_sql(
            sql,
            conn,
            params={
                "start_date": start_date,
                "end_date": end_date,
                "df_orgs": tuple(df_orgs),
            },
        )
        return was_open_vulns_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def insert_scores(start_date, org_uid, score, score_name, sector):
    """Insert a score into the scorecard summary stats table."""
    try:
        conn = connect()

        cursor = conn.cursor()
        query = sql.SQL(
            """
            UPDATE scorecard_summary_stats
            set {column_name} = %(score)s
            where start_date = %(start_date)s
            and organizations_uid = %(org_uid)s
            and sector_name = %(sector)s;
            """
        ).format(column_name=sql.Identifier(score_name))
        # sql = """
        #     UPDATE scorecard_summary_stats
        #     set {} = %(score)s
        #     where start_date = %(start_date)s
        #     and organizations_uid = %(org_uid)s
        #     and sector_name = %(sector)s;
        #     """

        cursor.execute(
            query,
            {
                "score_name": score_name,
                "score": score,
                "start_date": start_date,
                "org_uid": org_uid,
                "sector": sector,
            },
        )
        conn.commit()
        cursor.close()
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
        if conn is not None:
            close(conn)


# v ---------- D-Score API Queries ---------- v
def api_dscore_vs_cert(org_list):
    """
    Query API for all VS certificate data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS certificate data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_vs_cert"
    check_task_url = pe_api_url + "dscore_vs_cert/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for dscore_vs_cert endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged dscore_vs_cert status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("dscore_vs_cert query task failed, details: ", check_task_resp)


def api_dscore_vs_mail(org_list):
    """
    Query API for all VS mail data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS mail data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_vs_mail"
    check_task_url = pe_api_url + "dscore_vs_mail/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for dscore_vs_mail endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged dscore_vs_mail status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("dscore_vs_mail query task failed, details: ", check_task_resp)


def api_dscore_pe_ip(org_list):
    """
    Query API for all PE IP data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All PE IP data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_pe_ip"
    check_task_url = pe_api_url + "dscore_pe_ip/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info("Created task for dscore_pe_ip endpoint query, task_id: ", task_id)
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged dscore_pe_ip status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("dscore_pe_ip query task failed, details: ", check_task_resp)


def api_dscore_pe_domain(org_list):
    """
    Query API for all PE domain data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All PE domain data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_pe_domain"
    check_task_url = pe_api_url + "dscore_pe_domain/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for dscore_pe_domain endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged dscore_pe_domain status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception(
            "dscore_pe_domain query task failed, details: ", check_task_resp
        )


def api_dscore_was_webapp(org_list):
    """
    Query API for all WAS webapp data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All WAS webapp data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_was_webapp"
    check_task_url = pe_api_url + "dscore_was_webapp/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for dscore_was_webapp endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged dscore_was_webapp status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception(
            "dscore_was_webapp query task failed, details: ", check_task_resp
        )


def api_fceb_status(org_list):
    """
    Query API for the FCEB status of a list of organizations.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        The FCEB status of the specified list of organizations
    """
    # Endpoint info
    create_task_url = pe_api_url + "fceb_status"
    check_task_url = pe_api_url + "fceb_status/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info("Created task for fceb_status endpoint query, task_id: ", task_id)
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged fceb_status status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("fceb_status query task failed, details: ", check_task_resp)


# v ---------- I-Score API Queries ---------- v
def api_iscore_vs_vuln(org_list):
    """
    Query API for all VS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS vuln data of the specified orgs needed for the I-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "iscore_vs_vuln"
    check_task_url = pe_api_url + "iscore_vs_vuln/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_vs_vuln endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged iscore_vs_vuln status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        # If empty dataframe comes back, insert placeholder data
        if result_df.empty:
            result_df = pd.concat(
                [
                    result_df,
                    pd.DataFrame(
                        {
                            "organizations_uid": "test_org",
                            "parent_org_uid": "test_parent_org",
                            "cve_name": "test_cve",
                            "cvss_score": 1.0,
                        },
                        index=[0],
                    ),
                ],
                ignore_index=True,
            )
        return result_df
    else:
        raise Exception("iscore_vs_vuln query task failed, details: ", check_task_resp)


def api_iscore_vs_vuln_prev(org_list, start_date, end_date):
    """
    Query API for all previous VS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All previous VS vuln data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    create_task_url = pe_api_url + "iscore_vs_vuln_prev"
    check_task_url = pe_api_url + "iscore_vs_vuln_prev/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_vs_vuln_prev endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_vs_vuln_prev status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        # If empty dataframe comes back, insert placeholder data
        if result_df.empty:
            result_df = pd.concat(
                [
                    result_df,
                    pd.DataFrame(
                        {
                            "organizations_uid": "test_org",
                            "parent_org_uid": "test_parent_org",
                            "cve_name": "test_cve",
                            "cvss_score": 1.0,
                            "time_closed": datetime.date(1, 1, 1),
                        },
                        index=[0],
                    ),
                ],
                ignore_index=True,
            )
        else:
            result_df["time_closed"] = pd.to_datetime(result_df["time_closed"]).dt.date
        return result_df
    else:
        raise Exception(
            "iscore_vs_vuln_prev query task failed, details: ", check_task_resp
        )


def api_iscore_pe_vuln(org_list, start_date, end_date):
    """
    Query API for all PE vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE vuln data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    create_task_url = pe_api_url + "iscore_pe_vuln"
    check_task_url = pe_api_url + "iscore_pe_vuln/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_vuln endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged iscore_pe_vuln status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        # If empty dataframe comes back, insert placeholder data
        if result_df.empty:
            result_df = pd.concat(
                [
                    result_df,
                    pd.DataFrame(
                        {
                            "organizations_uid": "test_org",
                            "parent_org_uid": "test_parent_org",
                            "date": datetime.date(1, 1, 1),
                            "cve_name": "test_cve",
                            "cvss_score": 1.0,
                        },
                        index=[0],
                    ),
                ],
                ignore_index=True,
            )
        else:
            result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
        return result_df
    else:
        raise Exception("iscore_pe_vuln query task failed, details: ", check_task_resp)


def api_iscore_pe_cred(org_list, start_date, end_date):
    """
    Query API for all PE cred data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE cred data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    create_task_url = pe_api_url + "iscore_pe_cred"
    check_task_url = pe_api_url + "iscore_pe_cred/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_cred endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged iscore_pe_cred status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        # If empty dataframe comes back, insert placeholder data
        if result_df.empty:
            result_df = pd.concat(
                [
                    result_df,
                    pd.DataFrame(
                        {
                            "organizations_uid": "test_org",
                            "parent_org_uid": "test_parent_org",
                            "date": datetime.date(1, 1, 1),
                            "password_creds": 0,
                            "total_creds": 0,
                        },
                        index=[0],
                    ),
                ],
                ignore_index=True,
            )
        else:
            result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
        return result_df
    else:
        raise Exception("iscore_pe_cred query task failed, details: ", check_task_resp)


def api_iscore_pe_breach(org_list, start_date, end_date):
    """
    Query API for all PE breach data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE breach data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    create_task_url = pe_api_url + "iscore_pe_breach"
    check_task_url = pe_api_url + "iscore_pe_breach/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_breach endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_pe_breach status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        # If empty dataframe comes back, insert placeholder data
        if result_df.empty:
            result_df = pd.concat(
                [
                    result_df,
                    pd.DataFrame(
                        {
                            "organizations_uid": "test_org",
                            "parent_org_uid": "test_parent_org",
                            "date": datetime.date(1, 1, 1),
                            "breach_count": 0,
                        },
                        index=[0],
                    ),
                ],
                ignore_index=True,
            )
        else:
            result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
        return result_df
    else:
        raise Exception(
            "iscore_pe_breach query task failed, details: ", check_task_resp
        )


def api_iscore_pe_darkweb(org_list, start_date, end_date):
    """
    Query API for all PE darkweb data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE darkweb data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    create_task_url = pe_api_url + "iscore_pe_darkweb"
    check_task_url = pe_api_url + "iscore_pe_darkweb/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_darkweb endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_pe_darkweb status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        # If empty dataframe comes back, insert placeholder data
        if result_df.empty:
            result_df = pd.concat(
                [
                    result_df,
                    pd.DataFrame(
                        {
                            "organizations_uid": "test_org",
                            "parent_org_uid": "test_parent_org",
                            "alert_type": "TEST_TYPE",
                            "date": datetime.date(1, 1, 1),
                            "Count": 0,
                        },
                        index=[0],
                    ),
                ],
                ignore_index=True,
            )
        else:
            result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
        return result_df
    else:
        raise Exception(
            "iscore_pe_darkweb query task failed, details: ", check_task_resp
        )


def api_iscore_pe_protocol(org_list, start_date, end_date):
    """
    Query API for all PE protocol data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE protocol data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    create_task_url = pe_api_url + "iscore_pe_protocol"
    check_task_url = pe_api_url + "iscore_pe_protocol/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_protocol endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_pe_protocol status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        # If empty dataframe comes back, insert placeholder data
        if result_df.empty:
            result_df = pd.concat(
                [
                    result_df,
                    pd.DataFrame(
                        {
                            "organizations_uid": "test_org",
                            "parent_org_uid": "test_parent_org",
                            "port": "test_port",
                            "ip": "test_ip",
                            "protocol": "test_protocol",
                            "protocol_type": "test_type",
                            "date": datetime.date(1, 1, 1),
                        },
                        index=[0],
                    ),
                ],
                ignore_index=True,
            )
        else:
            result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
        return result_df
    else:
        raise Exception(
            "iscore_pe_protocol query task failed, details: ", check_task_resp
        )


def api_iscore_was_vuln(org_list, start_date, end_date):
    """
    Query API for all WAS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All WAS vuln data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    create_task_url = pe_api_url + "iscore_was_vuln"
    check_task_url = pe_api_url + "iscore_was_vuln/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_was_vuln endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_was_vuln status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        # If empty dataframe comes back, insert placeholder data
        if result_df.empty:
            result_df = pd.concat(
                [
                    result_df,
                    pd.DataFrame(
                        {
                            "organizations_uid": "test_org",
                            "parent_org_uid": "test_parent_org",
                            "date": datetime.date(1, 1, 1),
                            "cve_name": "test_cve",
                            "cvss_score": 1.0,
                            "owasp_category": "test_category",
                        },
                        index=[0],
                    ),
                ],
                ignore_index=True,
            )
        else:
            result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
        return result_df
    else:
        raise Exception("iscore_was_vuln query task failed, details: ", check_task_resp)


def api_iscore_was_vuln_prev(org_list, start_date, end_date):
    """
    Query API for all previous WAS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All previous WAS vuln data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    create_task_url = pe_api_url + "iscore_was_vuln_prev"
    check_task_url = pe_api_url + "iscore_was_vuln_prev/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_was_vuln_prev endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_was_vuln_prev status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        # If empty dataframe comes back, insert placeholder data
        if result_df.empty:
            result_df = pd.concat(
                [
                    result_df,
                    pd.DataFrame(
                        {
                            "organizations_uid": "test_org",
                            "parent_org_uid": "test_parent_org",
                            "was_total_vulns_prev": 0,
                            "date": datetime.date(1, 1, 1),
                        },
                        index=[0],
                    ),
                ],
                ignore_index=True,
            )
        else:
            result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
        return result_df
    else:
        raise Exception(
            "iscore_was_vuln_prev query task failed, details: ", check_task_resp
        )


def api_kev_list():
    """
    Query API for list of all KEVs.

    Return:
        List of all KEVs
    """
    # Endpoint info
    create_task_url = pe_api_url + "kev_list"
    check_task_url = pe_api_url + "kev_list/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info("Created task for kev_list endpoint query, task_id: ", task_id)
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged kev_list status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("kev_list query task failed, details: ", check_task_resp)


# ---------- Misc. Score Related API Queries ----------
def api_xs_stakeholders():
    """
    Query API for list of all XS stakeholders.

    Return:
        List of all XS stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "xs_stakeholders"
    check_task_url = pe_api_url + "xs_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for xs_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged xs_stakeholders status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("xs_stakeholders query task failed, details: ", check_task_resp)


def api_s_stakeholders():
    """
    Query API for list of all S stakeholders.

    Return:
        List of all S stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "s_stakeholders"
    check_task_url = pe_api_url + "s_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for s_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged s_stakeholders status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("s_stakeholders query task failed, details: ", check_task_resp)


def api_m_stakeholders():
    """
    Query API for list of all M stakeholders.

    Return:
        List of all M stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "m_stakeholders"
    check_task_url = pe_api_url + "m_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for m_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged m_stakeholders status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("m_stakeholders query task failed, details: ", check_task_resp)


def api_l_stakeholders():
    """
    Query API for list of all L stakeholders.

    Return:
        List of all L stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "l_stakeholders"
    check_task_url = pe_api_url + "l_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for l_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged l_stakeholders status endpoint, status:", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("l_stakeholders query task failed, details: ", check_task_resp)


def api_xl_stakeholders():
    """
    Query API for list of all XL stakeholders.

    Return:
        List of all XL stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "xl_stakeholders"
    check_task_url = pe_api_url + "xl_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for xl_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged xl_stakeholders status endpoint, status:", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)

    # Once task finishes, return result
    if task_status == "Completed":
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("xl_stakeholders query task failed, details: ", check_task_resp)


# v ========== OLD TSQL VERSIONS OF I/D SCORE QUERIES ========== v
# Fallback to these if something goes wrong during the first run using API endpoints.
# If the new api_...() functions are breaking things, just revert all the
# api functions called in generate_d_score.py and generate_i_score.py to the
# old query_...() TSQL functions below.

# ---------- D-Score SQL Queries ----------
# ----- VS Cert -----
def query_dscore_vs_data_cert(org_list):
    """
    Query all VS certificate data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS certificate data of the specified orgs needed for the D-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
       SELECT  cert.organizations_uid, cert.parent_org_uid, cert.num_ident_cert, cert.num_monitor_cert
        FROM  vw_dscore_vs_cert cert
        Where cert.organizations_uid in %(sector_str)s
    """
    # Make query
    dscore_vs_data_cert = pd.read_sql(
        sql,
        conn,
        params={"sector_str": tuple(org_list["organizations_uid"].tolist())},
    )
    # Close connection
    conn.close()
    return dscore_vs_data_cert


# ----- VS Mail -----
def query_dscore_vs_data_mail(org_list):
    """
    Query all VS mail data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS mail data of the specified orgs needed for the D-Score
    """
    # Open connection
    conn = connect()
    sql = """
       SELECT  mail.organizations_uid, mail.parent_org_uid, mail.num_valid_dmarc, mail.num_valid_spf, mail.num_valid_dmarc_or_spf, mail.total_mail_domains
        FROM  vw_dscore_vs_mail mail
        Where mail.organizations_uid in %(sector_str)s
    """
    # Make query
    dscore_vs_data_mail = pd.read_sql(
        sql,
        conn,
        params={"sector_str": tuple(org_list["organizations_uid"].tolist())},
    )
    # Close connection
    conn.close()
    return dscore_vs_data_mail


# ----- PE IP -----
def query_dscore_pe_data_ip(org_list):
    """
    Query all PE IP data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All PE ip data of the specified orgs needed for the D-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sector_str = (
        "UUID('" + "')), (UUID('".join(org_list["organizations_uid"].tolist()) + "')"
    )
    sql = """
    SELECT
        sector.organizations_uid, ip.parent_org_uid, ip.num_ident_ip, ip.num_monitor_ip
    FROM
        (VALUES (%(sector_str)s)) AS sector(organizations_uid)
        LEFT JOIN
        vw_dscore_pe_ip ip
        ON sector.organizations_uid = ip.organizations_uid;"""
    dscore_pe_data_ip = pd.read_sql(
        sql,
        conn,
        params={"sector_str": AsIs(sector_str)},
    )
    # Close connection
    conn.close()
    return dscore_pe_data_ip


# ----- PE Domain -----
def query_dscore_pe_data_domain(org_list):
    """
    Query all PE domain data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All PE domain data of the specified orgs needed for the D-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
       SELECT  
            domain.organizations_uid, domain.parent_org_uid, domain.num_ident_domain, domain.num_monitor_domain
       FROM  
            vw_dscore_pe_domain domain
        Where domain.organizations_uid in %(sector_str)s
    """
    # Make query
    dscore_pe_data_domain = pd.read_sql(
        sql,
        conn,
        params={"sector_str": tuple(org_list["organizations_uid"].tolist())},
    )
    # Close connection
    conn.close()
    return dscore_pe_data_domain


# ----- WAS Webapp -----
def query_dscore_was_data_webapp(org_list):
    """
    Query all WAS webapp data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All WAS webapp data of the specified orgs needed for the D-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
       SELECT  
            webapp.organizations_uid, webapp.parent_org_uid, webapp.num_ident_webapp, webapp.num_monitor_webapp
       FROM  
            vw_dscore_was_webapp webapp
        Where webapp.organizations_uid in %(sector_str)s
    """
    # Make query
    dscore_was_data_webapp = pd.read_sql(
        sql,
        conn,
        params={"sector_str": tuple(org_list["organizations_uid"].tolist())},
    )
    # Close connection
    conn.close()
    return dscore_was_data_webapp


# ---------- I-Score SQL Queries ----------
# ----- VS Vulns -----
def query_iscore_vs_data_vuln(org_list):
    """
    Query all VS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS vuln data of the specified orgs needed for the I-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
       SELECT  
            vuln.organizations_uid, vuln.parent_org_uid, vuln.cve_name, vuln.cvss_score
       FROM  
            vw_iscore_vs_vuln vuln
        Where vuln.organizations_uid in %(sector_str)s
    """
    # Make query
    iscore_vs_vuln_data = pd.read_sql(
        sql,
        conn,
        params={"sector_str": tuple(org_list["organizations_uid"].tolist())},
    )
    # Close connection
    conn.close()
    # Check if dataframe comes back empty
    if iscore_vs_vuln_data.empty:
        # If empty, insert placeholder data row
        # This data will not affect score calculations
        iscore_vs_vuln_data = pd.concat(
            [
                iscore_vs_vuln_data,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "cve_name": "test_cve",
                        "cvss_score": 1.0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_vs_vuln_data


# ----- VS Vulns Previous -----
def query_iscore_vs_data_vuln_prev(org_list, start_date, end_date):
    """
    Query all VS prev vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: Start date of specified report period
        end_date: End date of specified report period
    Return:
        All VS prev vuln data of the specified orgs needed for the I-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
        SELECT 
            prev_vuln.organizations_uid, prev_vuln.parent_org_uid, prev_vuln.cve_name, prev_vuln.cvss_score, prev_vuln.time_closed
        FROM 
            vw_iscore_vs_vuln_prev prev_vuln
        WHERE 
            prev_vuln.organizations_uid in %(sector_str)s
        AND 
            prev_vuln.time_closed BETWEEN %(start_date)s AND %(end_date)s;
    """
    # Make query
    iscore_vs_vuln_prev_data = pd.read_sql(
        sql,
        conn,
        params={
            "sector_str": tuple(org_list["organizations_uid"].tolist()),
            "start_date": start_date,
            "end_date": end_date,
        },
    )
    # Close connection
    conn.close()
    # Check if dataframe comes back empty
    if iscore_vs_vuln_prev_data.empty:
        # If empty, insert placeholder data row
        # This data will not affect score calculations
        iscore_vs_vuln_prev_data = pd.concat(
            [
                iscore_vs_vuln_prev_data,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "cve_name": "test_cve",
                        "cvss_score": 1.0,
                        "time_closed": datetime.date(1, 1, 1),
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_vs_vuln_prev_data


# ----- PE Vulns -----
def query_iscore_pe_data_vuln(org_list, start_date, end_date):
    """
    Query all PE vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: Start date of specified report period
        end_date: End date of specified report period
    Return:
        All PE vuln data of the specified orgs needed for the I-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
    SELECT
        vuln.organizations_uid, vuln.parent_org_uid, vuln.date, vuln.cve_name, vuln.cvss_score
    FROM
        vw_iscore_pe_vuln vuln
    WHERE
        vuln.organizations_uid in %(sector_str)s
    AND 
        vuln.date BETWEEN %(start_date)s AND %(end_date)s;
    """
    # Make query
    iscore_pe_vuln_data = pd.read_sql(
        sql,
        conn,
        params={
            "sector_str": tuple(org_list["organizations_uid"].tolist()),
            "start_date": start_date,
            "end_date": end_date,
        },
    )
    # Close connection
    conn.close()
    # Check if dataframe comes back empty
    if iscore_pe_vuln_data.empty:
        # If empty, insert placeholder data row
        # This data will not affect score calculations
        iscore_pe_vuln_data = pd.concat(
            [
                iscore_pe_vuln_data,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "date": datetime.date(1, 1, 1),
                        "cve_name": "test_cve",
                        "cvss_score": 1.0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_pe_vuln_data


# ----- PE Vulns Previous -----
# Uses query_iscore_pe_data_vuln, but with prev report period dates


# ----- PE Creds -----
def query_iscore_pe_data_cred(org_list, start_date, end_date):
    """
    Query all PE cred data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: Start date of specified report period
        end_date: End date of specified report period
    Return:
        All PE cred data of the specified orgs needed for the I-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
        SELECT
            cred.organizations_uid, cred.parent_org_uid, cred.date, cred.password_creds, cred.total_creds
        FROM
            vw_iscore_pe_cred cred
        WHERE 
            cred.organizations_uid in %(sector_str)s
        AND
            date BETWEEN %(start_date)s AND %(end_date)s;
    """
    # Make query
    iscore_pe_cred_data = pd.read_sql(
        sql,
        conn,
        params={
            "sector_str": tuple(org_list["organizations_uid"].tolist()),
            "start_date": start_date,
            "end_date": end_date,
        },
    )
    # Close connection
    conn.close()
    # Check if dataframe comes back empty
    if iscore_pe_cred_data.empty:
        # If empty, insert placeholder data row
        # This data will not affect score calculations
        iscore_pe_cred_data = pd.concat(
            [
                iscore_pe_cred_data,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "date": datetime.date(1, 1, 1),
                        "password_creds": 0,
                        "total_creds": 0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_pe_cred_data


# ----- PE Breaches -----
def query_iscore_pe_data_breach(org_list, start_date, end_date):
    """
    Query all PE breach data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: Start date of specified report period
        end_date: End date of specified report period
    Return:
        All PE breach data of the specified orgs needed for the I-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
        SELECT 
            breach.organizations_uid, breach.parent_org_uid, breach.date, breach.breach_count
        FROM
            vw_iscore_pe_breach breach
        WHERE 
            breach.organizations_uid in %(sector_str)s
        AND
            date BETWEEN %(start_date)s AND %(end_date)s;"""
    # Make query
    iscore_pe_breach_data = pd.read_sql(
        sql,
        conn,
        params={
            "sector_str": tuple(org_list["organizations_uid"].tolist()),
            "start_date": start_date,
            "end_date": end_date,
        },
    )
    # Close connection
    conn.close()
    # Check if dataframe comes back empty
    if iscore_pe_breach_data.empty:
        # If empty, insert placeholder data row
        # This data will not affect score calculations
        iscore_pe_breach_data = pd.concat(
            [
                iscore_pe_breach_data,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "date": datetime.date(1, 1, 1),
                        "breach_count": 0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_pe_breach_data


# ----- PE DarkWeb -----
def query_iscore_pe_data_darkweb(org_list, start_date, end_date):
    """
    Query all PE dark web data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: Start date of specified report period
        end_date: End date of specified report period
    Return:
        All PE darkweb data of the specified orgs needed for the I-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sector_str = (
        "UUID('" + "')), (UUID('".join(org_list["organizations_uid"].tolist()) + "')"
    )
    sql = """
    SELECT
        sector.organizations_uid, darkweb.parent_org_uid, darkweb.alert_type, darkweb.date, darkweb."Count"
    FROM
        (VALUES (%(sector_str)s)) AS sector(organizations_uid)
        LEFT JOIN
        vw_iscore_pe_darkweb darkweb
        ON sector.organizations_uid = darkweb.organizations_uid
    WHERE
        date BETWEEN %(start_date)s AND %(end_date)s OR date = '0001-01-01';"""

    sql = """
        SELECT 
            darkweb.organizations_uid, darkweb.parent_org_uid, darkweb.alert_type, darkweb.date, darkweb."Count"
        FROM
            vw_iscore_pe_darkweb darkweb
        WHERE 
            darkweb.organizations_uid in %(sector_str)s
        AND
        date BETWEEN %(start_date)s AND %(end_date)s OR date = '0001-01-01';"""

    # Make query
    iscore_pe_darkweb_data = pd.read_sql(
        sql,
        conn,
        params={
            "sector_str": tuple(org_list["organizations_uid"].tolist()),
            "start_date": start_date,
            "end_date": end_date,
        },
    )
    # Close connection
    conn.close()
    # Check if dataframe comes back empty
    if iscore_pe_darkweb_data.empty:
        # If empty, insert placeholder data row
        # This data will not affect score calculations
        iscore_pe_darkweb_data = pd.concat(
            [
                iscore_pe_darkweb_data,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "alert_type": "TEST_TYPE",
                        "date": datetime.date(1, 1, 1),
                        "Count": 0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_pe_darkweb_data


# ----- PE Protocol -----
def query_iscore_pe_data_protocol(org_list, start_date, end_date):
    """
    Query all PE protocol data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: Start date of specified report period
        end_date: End date of specified report period
    Return:
        All PE protocol data of the specified orgs needed for the I-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
        SELECT
            protocol.organizations_uid, protocol.parent_org_uid, protocol.port, protocol.ip, protocol.protocol, protocol.protocol_type, protocol.date
        FROM 
            vw_iscore_pe_protocol protocol
        WHERE 
            protocol.organizations_uid in %(sector_str)s
        AND
            date BETWEEN %(start_date)s AND %(end_date)s;
    """
    # Make query
    iscore_pe_protocol_data = pd.read_sql(
        sql,
        conn,
        params={
            "sector_str": tuple(org_list["organizations_uid"].tolist()),
            "start_date": start_date,
            "end_date": end_date,
        },
    )
    # Close connection
    conn.close()
    # Check if dataframe comes back empty
    if iscore_pe_protocol_data.empty:
        # If empty, insert placeholder data row
        # This data will not affect score calculations
        iscore_pe_protocol_data = pd.concat(
            [
                iscore_pe_protocol_data,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "port": "test_port",
                        "ip": "test_ip",
                        "protocol": "test_protocol",
                        "protocol_type": "test_type",
                        "date": datetime.date(1, 1, 1),
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_pe_protocol_data


# ----- WAS Vulns -----
def query_iscore_was_data_vuln(org_list, start_date, end_date):
    """
    Query all WAS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: Start date of specified report period
        end_date: End date of specified report period
    Return:
        All WAS vuln data of the specified orgs needed for the I-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
        SELECT
            vuln.organizations_uid, vuln.parent_org_uid, vuln.date, vuln.cve_name, vuln.cvss_score, vuln.owasp_category
        FROM
            vw_iscore_was_vuln vuln
        WHERE
            vuln.organizations_uid in %(sector_str)s
        AND
            date BETWEEN %(start_date)s AND %(end_date)s;
    """
    # Make query
    iscore_was_vuln_data = pd.read_sql(
        sql,
        conn,
        params={
            "sector_str": tuple(org_list["organizations_uid"].tolist()),
            "start_date": start_date,
            "end_date": end_date,
        },
    )
    # Close connection
    conn.close()
    # Check if dataframe comes back empty
    if iscore_was_vuln_data.empty:
        # If empty, insert placeholder data row
        # This data will not affect score calculations
        iscore_was_vuln_data = pd.concat(
            [
                iscore_was_vuln_data,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "date": datetime.date(1, 1, 1),
                        "cve_name": "test_cve",
                        "cvss_score": 1.0,
                        "owasp_category": "test_category",
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_was_vuln_data


# ----- WAS Vulns Previous -----
def query_iscore_was_data_vuln_prev(org_list, start_date, end_date):
    """
    Query all WAS prev vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: Start date of specified report period
        end_date: End date of specified report period
    Return:
        All WAS vuln prev data of the specified orgs needed for the I-Score
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
        SELECT 
            prev_vuln.organizations_uid, prev_vuln.parent_org_uid, prev_vuln.was_total_vulns_prev, prev_vuln.date
        FROM 
            vw_iscore_was_vuln_prev prev_vuln
        WHERE 
            prev_vuln.organizations_uid in %(sector_str)s
        AND 
            date BETWEEN %(start_date)s AND %(end_date)s;
    """
    # Make query
    iscore_was_vuln_prev_data = pd.read_sql(
        sql,
        conn,
        params={
            "sector_str": tuple(org_list["organizations_uid"].tolist()),
            "start_date": start_date,
            "end_date": end_date,
        },
    )
    # Close connection
    conn.close()
    # Check if dataframe comes back empty
    if iscore_was_vuln_prev_data.empty:
        # If empty, insert placeholder data row
        # This data will not affect score calculations
        iscore_was_vuln_prev_data = pd.concat(
            [
                iscore_was_vuln_prev_data,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "was_total_vulns_prev": 0,
                        "date": datetime.date(1, 1, 1),
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_was_vuln_prev_data


# ----- KEV List -----
def query_kev_list():
    """Query list of all CVE names that are considered KEVs."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT kev FROM cyhy_kevs;"""
    kev_list = pd.read_sql(sql, conn)
    # Close connection
    conn.close()
    return kev_list


# v ---------- Misc. Score SQL Queries ---------- v
# ----- All FCEB Parents List -----
def query_fceb_parent_list():
    """Query list of all FCEB parent stakeholders (all FCEB excluding child orgs)."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT organizations_uid, cyhy_db_name FROM organizations WHERE fceb = true AND retired = false AND election = false;"""
    fceb_parent_list = pd.read_sql(sql, conn)
    # Close connection
    conn.close()
    return fceb_parent_list


# ----- XS Stakeholder List -----
def query_xs_stakeholder_list():
    """Query list of all stakeholders that fall in the XS group/sector."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT organizations_uid, cyhy_db_name FROM vw_iscore_orgs_ip_counts WHERE ip_count >= 0 AND ip_count <= 100;"""
    xs_stakeholder_list = pd.read_sql(sql, conn)
    # Close connection
    conn.close()
    return xs_stakeholder_list


# ----- S Stakeholder List -----
def query_s_stakeholder_list():
    """Query list of all stakeholders that fall in the S group/sector."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT organizations_uid, cyhy_db_name FROM vw_iscore_orgs_ip_counts WHERE ip_count > 100 AND ip_count <= 1000;"""
    s_stakeholder_list = pd.read_sql(sql, conn)
    # Close connection
    conn.close()
    return s_stakeholder_list


# ----- M Stakeholder List -----
def query_m_stakeholder_list():
    """Query list of all stakeholders that fall in the M group/sector."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT organizations_uid, cyhy_db_name FROM vw_iscore_orgs_ip_counts WHERE (ip_count > 1000 AND ip_count <= 10000)
    OR ip_count = -1;"""
    # Any stakeholderes not reported on get put in this
    # sector by default
    m_stakeholder_list = pd.read_sql(sql, conn)
    # Close connection
    conn.close()
    return m_stakeholder_list


# ----- L Stakeholder List -----
def query_l_stakeholder_list():
    """Query list of all stakeholders that fall in the L group/sector."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT organizations_uid, cyhy_db_name FROM vw_iscore_orgs_ip_counts WHERE ip_count > 10000 AND ip_count <= 100000;"""
    l_stakeholder_list = pd.read_sql(sql, conn)
    # Close connection
    conn.close()
    return l_stakeholder_list


# ----- XL Stakeholder List -----
def query_xl_stakeholder_list():
    """Query list of all stakeholders that fall in the XL group/sector."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT organizations_uid, cyhy_db_name FROM vw_iscore_orgs_ip_counts WHERE ip_count > 100000;"""
    xl_stakeholder_list = pd.read_sql(sql, conn)
    # Close connection
    conn.close()
    return xl_stakeholder_list


# ----- PE Stakeholder List -----
def query_pe_stakeholder_list():
    """Query list of all stakeholders PE reports on."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT organizations_uid, cyhy_db_name, is_parent, parent_org_uid FROM organizations WHERE report_on = True or runs_scans = True;"""
    pe_stakeholder_list = pd.read_sql(sql, conn)
    # Close connection
    conn.close()
    return pe_stakeholder_list


# ----- FCEB Status -----
def query_fceb_status(org_list):
    """
    Check if each organization in the list is FCEB or non-FCEB.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        org list with additional boolean column of FCEB true/false
    """
    # Open connection
    conn = connect()
    # Build query
    sql = """
        SELECT 
            org.organizations_uid, COALESCE(org.fceb, false) as fceb
        FROM organizations org
        WHERE organizations_uid in %(sector_str)s;
    """
    # Make query
    orgs_fceb_status = pd.read_sql(
        sql,
        conn,
        params={"sector_str": tuple(org_list["organizations_uid"].tolist())},
    )
    # Close connection
    conn.close()
    return orgs_fceb_status
