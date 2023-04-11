#!/usr/bin/env python
"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import datetime
import logging
import sys

# Third-Party Libraries
import pandas as pd
import psycopg2

# cisagov Libraries
from pe_reports.data.cyhy_db_query import pe_db_staging_connect as connect

from .config import config, staging_config

# from psycopg2 import OperationalError


# Setup logging to central file
LOGGER = logging.getLogger(__name__)

CONN_PARAMS_DIC = config()
CONN_PARAMS_DIC_STAGING = staging_config()


def show_psycopg2_exception(err):
    """Handle errors for PostgreSQL issues."""
    err_type, err_obj, traceback = sys.exc_info()
    LOGGER.error(
        "Database connection error: %s on line number: %s", err, traceback.tb_lineno
    )


# def connect():
#     """Connect to PostgreSQL database."""
#     conn = None
#     try:
#         conn = psycopg2.connect(**CONN_PARAMS_DIC)
#     except OperationalError as err:
#         print(err)
#         show_psycopg2_exception(err)
#         conn = None
#     return conn


def close(conn):
    """Close connection to PostgreSQL."""
    conn.close()
    return


def get_orgs():
    """Query organizations table."""
    conn = connect()
    sql = """SELECT * FROM organizations where report_on or run_scans"""
    # TODO change to the below sql statement
    # sql = """SELECT * FROM organizations where fceb or fceb_child"""
    pe_orgs = pd.read_sql(sql, conn)
    conn.close()
    return pe_orgs


# ----- IP list -------
def query_ips_counts(org_uid_list):
    """Query database for ips found from cidrs and discovered by other means."""
    conn = connect()

    sql = """
        SELECT * from vw_orgs_total_ips
        where organizations_uid in %(org_list)s
    """
    total_ips_df = pd.read_sql(sql, conn, params={"org_list": tuple(org_uid_list)})

    sql = """
        select o.organizations_uid,o.cyhy_db_name, coalesce(cnts.count, 0) as identified_ip_count
        from organizations o
        left join
        (SELECT o.organizations_uid, o.cyhy_db_name, count(i.ip) as count
        FROM ips i
        join ips_subs ip_s on ip_s.ip_hash = i.ip_hash
        join sub_domains sd on sd.sub_domain_uid = ip_s.sub_domain_uid
        join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
        right join organizations o on rd.organizations_uid = o.organizations_uid
        WHERE i.origin_cidr is null
        GROUP BY o.organizations_uid, o.cyhy_db_name) as cnts
        on o.organizations_uid = cnts.organizations_uid
        where o.organizations_uid in %(org_list)s;
    """
    discovered_ips_df = pd.read_sql(sql, conn, params={"org_list": tuple(org_uid_list)})

    conn.close()
    return (total_ips_df, discovered_ips_df)


def query_domain_counts(org_uid_list):
    """Query domain counts."""
    conn = connect()

    # cur = conn.cursor()
    sql = """
        select o.organizations_uid, o.cyhy_db_name,
        coalesce(cnts.identified, 0) as identified,
        coalesce(cnts.unidentified, 0) as unidentified
        from organizations o
        left join
        (select rd.organizations_uid, sum(case sd.identified  when True then 1 else 0 end) identified, sum(case sd.identified when False then 1 else 0 end) unidentified
        from root_domains rd
        join sub_domains sd on sd.root_domain_uid = rd.root_domain_uid
        group by rd.organizations_uid) cnts
        on o.organizations_uid = cnts.organizations_uid
        where o.organizations_uid in %(org_list)s;
    """
    domain_counts = pd.read_sql(sql, conn, params={"org_list": tuple(org_uid_list)})
    # cur.execute(sql, {"org_list": tuple(org_uid_list)})
    # domain_counts = cur.fetchall()
    # keys = [desc[0] for desc in cur.description]
    # domain_counts = [dict(zip(keys, values)) for values in domain_counts]
    close(conn)
    return domain_counts


def query_was_fceb_ttr(date_period):
    """Calculate Summary results for all of FCEB."""
    conn = connect()

    sql = """
    SELECT avg(wh.crit_rem_time) as fceb_critical, avg(wh.high_rem_time) as fceb_high
    from was_history wh
    join was_map wm
    on wh.was_org_id = wm.was_org_id
    join organizations o
    on o.organizations_uid = wm.pe_org_id
    where wh.report_period = %(start_date)s
    and o.fceb
    """
    # or fceb_child
    cur = conn.cursor()

    cur.execute(sql, {"start_date": date_period})
    fceb_counts = cur.fetchone()
    cur.close()
    # fceb_counts = pd.read_sql(sql, conn, params = {"start_date": date_period})

    close(conn)

    fceb_dict = {"critical": fceb_counts[0], "high": fceb_counts[1]}
    return fceb_dict


def query_webapp_counts(date_period, org_uid_list):
    """Query webapp counts."""
    # TODO update query to pull critical and high vulns
    conn = connect()

    sql = """
            select o.organizations_uid, o.cyhy_db_name, cnts.date_scanned,
            coalesce(cnts.vuln_cnt, 0) as vuln_cnt,
            coalesce(cnts.vuln_webapp_cnt,0) as vuln_webapp_cnt,
            coalesce(cnts.web_app_cnt, 0) as web_app_cnt,
            coalesce(cnts.high_rem_time, Null) high_rem_time,
            coalesce(cnts.crit_rem_time, null) crit_rem_time,
            coalesce(cnts.crit_vuln_cnt, 0) crit_vuln_cnt,
            coalesce(cnts.high_vuln_cnt, 0) high_vuln_cnt
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
    webapp_counts = pd.read_sql(
        sql,
        conn,
        params={"start_date": date_period, "org_uid_list": tuple(org_uid_list)},
    )

    close(conn)

    return webapp_counts


def query_certs_counts():
    """Query certificate counts."""
    identified_certs = None
    monitored_certs = None
    return (identified_certs, monitored_certs)


def query_https_scan(org_id_list):
    """Query https scan results for a given agency and month."""
    conn = connect()
    try:
        # Not sure if this should be a date filter or just latest = True
        sql = """SELECT * FROM cyhy_https_scan where latest is True and organizations_uid IN %(org_id_list)s"""
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


def query_sslyze_scan(org_id_list):
    """Query sslyze scan results for a given agency and month."""
    # "domain", "scanned_port", "scanned_hostname", "sslv2", "sslv3", "any_3des", "any_rc4", "is_symantec_cert
    conn = connect()
    try:
        # Need to verify where statement: other options scan_date, first_seen, last_seen
        sql = """
                SELECT * FROM cyhy_sslyze where latest is True and scanned_port in (25, 587, 465, 443)
                and organizations_uid in %(org_id_list)s
            """
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


def query_trusty_mail(org_id_list):
    """Query trusty mail scan results for a given agency and month."""
    # all_domains_cursor = self.__db.trustymail.find(
    #         {"latest": True, "agency.name": agency}, no_cursor_timeout=True
    #     )
    conn = connect()
    try:
        # Need to verify where statement: other options scan_date, first_seen, last_seen
        sql = """SELECT * FROM cyhy_trustymail where latest is True and organizations_uid in %(org_uid)s"""
        cur = conn.cursor()

        cur.execute(sql, params={"org_uid": tuple(org_id_list)})
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


# v ---------- I-Score SQL Queries ---------- v
# ----- VS Vulns -----
def query_iscore_vs_data_vuln(start_date, end_date):
    """Query all VS vuln data needed for I-Score calculation."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT * FROM vw_iscore_vs_vuln WHERE date BETWEEN %(start_date)s AND %(end_date)s;"""
    iscore_vs_vuln_data = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
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
                        "date": datetime.date(1, 1, 1),
                        "cve_name": "test_cve",
                        "cvss_score": 1.0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return iscore_vs_vuln_data


# ----- PE Vulns -----
def query_iscore_pe_data_vuln(start_date, end_date):
    """Query all PE vuln data needed for I-Score calculation."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT * FROM vw_iscore_pe_vuln WHERE date BETWEEN %(start_date)s AND %(end_date)s;"""
    iscore_pe_vuln_data = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
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


# ----- PE Creds -----
def query_iscore_pe_data_cred(start_date, end_date):
    """Query all PE cred data needed for I-Score calculation."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT * FROM vw_iscore_pe_cred WHERE date BETWEEN %(start_date)s AND %(end_date)s;"""
    iscore_pe_cred_data = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
    )
    # Close connection
    conn.close()
    return iscore_pe_cred_data


# ----- PE Breaches -----
def query_iscore_pe_data_breach(start_date, end_date):
    """Query all PE breach data needed for I-Score calculation."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT * FROM vw_iscore_pe_breach WHERE date BETWEEN %(start_date)s AND %(end_date)s;"""
    iscore_pe_breach_data = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
    )
    # Close connection
    conn.close()
    return iscore_pe_breach_data


# ----- PE DarkWeb -----
def query_iscore_pe_data_darkweb(start_date, end_date):
    """Query all PE dark web data needed for I-Score calculation."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT * FROM vw_iscore_pe_darkweb WHERE date BETWEEN %(start_date)s AND %(end_date)s;"""
    iscore_pe_darkweb_data = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
    )
    # Close connection
    conn.close()
    return iscore_pe_darkweb_data


# ----- PE Protocol -----
def query_iscore_pe_data_protocol(start_date, end_date):
    """Query all PE protocol data needed for I-Score calculation."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT * FROM vw_iscore_pe_protocol WHERE date BETWEEN %(start_date)s AND %(end_date)s;"""
    iscore_pe_protocol_data = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
    )
    # Close connection
    conn.close()
    return iscore_pe_protocol_data


# ----- WAS Vulns -----
def query_iscore_was_data_vuln(start_date, end_date):
    """Query all WAS vuln data needed for I-Score calculation."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT * FROM vw_iscore_was_vuln WHERE date BETWEEN %(start_date)s AND %(end_date)s;"""
    iscore_was_vuln_data = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
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
                        "org_id": "test_org",
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


# ----- PE Stakeholder List -----
def query_pe_stakeholder_list():
    """Query list of all stakeholders PE reports on."""
    # Open connection
    conn = connect()
    # Make query
    sql = """SELECT organizations_uid, cyhy_db_name, is_parent, parent_org_uid FROM organizations WHERE report_on = True;"""
    pe_stakeholder_list = pd.read_sql(sql, conn)
    # Close connection
    conn.close()
    return pe_stakeholder_list


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


def query_was_summary(last_updated):
    """Query PE database for WAS summary data."""
    conn = connect()

    sql = """SELECT was_org_id, webapp_count, webapp_with_vulns_count, last_updated
        from was_summary ws
        where last_updated = %(last_updated)s"""

    was_summary_data = pd.read_sql(sql, conn, params={"last_updated": last_updated})
    conn.close
    return was_summary_data


def query_cyhy_snapshots(start_date, end_date):
    """Query PE database for cyhy snapshots."""
    conn = connect()
    sql = """select o.organizations_uid, o.cyhy_db_name, cs.host_count, cs.vulnerable_host_count, cs.cyhy_last_change
        from organizations o
        left join cyhy_snapshots cs on
        o.organizations_uid = cs.organizations_uid
        where o.report_on  = true and cs.cyhy_last_change  >= %(start_date)s and cs.cyhy_last_change < %(end_date)s"""

    snapshots = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
    )
    conn.close
    return snapshots


# **
def query_sofware_scans(start_date, end_date, org_id_list=[]):
    """Query the PE database for vuln data identified by the VS team scans."""
    conn = connect()
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
        where o.report_on  = true and cvs.plugin_name = 'Unsupported Web Server Detection' and
        cvs.cyhy_time  >= %(start_date)s and cvs.cyhy_time < %(end_date)s
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
        if org_uid_list:
            sql = """select o.organizations_uid, o.cyhy_db_name, cps.ip, cps.port, cps.service_name, cps.state
                from organizations o
                left join cyhy_port_scans cps on
                o.organizations_uid = cps.organizations_uid
                where cps.cyhy_time  >= %(end_date)s and cps.cyhy_time < %(end_date)s
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
                where o.report_on = True and cps.cyhy_time  >= %(end_date)s and cps.cyhy_time < %(end_date)s
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
                where ct.time_closed = 'None' and false_positive = False
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
                where ct.time_closed = 'None' and false_positive = False
                group by ct.organizations_uid) cnts
            on  o.organizations_uid =cnts.organizations_uid
            where o.report_on = True;
        """

        vs_vuln_counts = pd.read_sql(sql, conn)

    conn.close()

    return vs_vuln_counts


# **
def query_vuln_remediation(start_date, end_date, org_id_list):
    """Query vulnerability time to remediate."""
    conn = connect()
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
    try:
        sql = """
        select o.cyhy_db_name, o.fceb, ct.cvss_base_score, ct.cve, ct.time_opened
        from cyhy_tickets ct
        left join organizations o on
        o.organizations_uid = ct.organizations_uid
        where ct.false_positive = 'False' and ct.time_closed = 'None' and (ct.cve != null or (ct.cvss_base_score != 'Nan' and ct.cvss_base_score >= 7.0))
        and and o.organizations_uid IN %(org_id_list)s"""
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
