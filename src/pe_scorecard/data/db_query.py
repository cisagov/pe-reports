#!/usr/bin/env python
"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import datetime
import logging
import sys

# Third-Party Libraries
import pandas as pd
import psycopg2
from psycopg2 import OperationalError

from .config import config, staging_config

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


def connect():
    """Connect to PostgreSQL database."""
    conn = None
    try:
        conn = psycopg2.connect(**CONN_PARAMS_DIC)
    except OperationalError as err:
        print(err)
        show_psycopg2_exception(err)
        conn = None
    return conn


def close(conn):
    """Close connection to PostgreSQL."""
    conn.close()
    return


def get_orgs():
    """Query organizations table."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """SELECT * FROM organizations where report_on or demo or run_scans"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        keys = [desc[0] for desc in cur.description]
        pe_orgs = [dict(zip(keys, values)) for values in pe_orgs]
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# ----- IP list -------
def query_ips_counts():
    """Query database for ips found from cidrs and discovered by other means."""
    conn = connect()

    sql = """SELECT * from vw_orgs_total_ips"""
    total_ips_df = pd.read_sql(sql, conn)

    sql = """
        select o.organizations_uid,o.cyhy_db_name, coalesce(cnts.count, 0)
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
        where o.report_on =True
    """
    discovered_ips_df = pd.read_sql(sql, conn)

    conn.close()
    return (total_ips_df, discovered_ips_df)


def get_domain_counts():
    """Query domain counts."""
    conn = connect()
    try:
        cur = conn.cursor()
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
            where o.report_on or o.run_scans
        """
        cur.execute(sql)
        domain_counts = cur.fetchall()
        keys = [desc[0] for desc in cur.description]
        domain_counts = [dict(zip(keys, values)) for values in domain_counts]
        cur.close()
        return domain_counts
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_webapp_counts():
    """Query webapp counts."""
    try:
        conn = connect()
        cur = conn.cursor()
        # Need to add filters
        sql = """
            SELECT * from was_summary
        """
        cur.execute(sql)
        webapp_counts = cur.fetchall()
        keys = [desc[0] for desc in cur.description]
        webapp_counts = [dict(zip(keys, values)) for values in webapp_counts]
        cur.close()
        return webapp_counts
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_https_scan(month, agency):
    """Query https scan results for a given agency and month."""
    conn = connect()
    try:
        # Not sure if this should be a date filter or just latest = True
        sql = """SELECT * FROM cyhy_https_scan where latest is True"""
        cur = conn.cursor()

        cur.execute(sql)
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


def query_sslyze_scan(month, agency):
    """Query sslyze scan results for a given agency and month."""
    # "domain", "scanned_port", "scanned_hostname", "sslv2", "sslv3", "any_3des", "any_rc4", "is_symantec_cert
    conn = connect()
    try:
        # Need to verify where statement: other options scan_date, first_seen, last_seen
        sql = """SELECT * FROM cyhy_sslyze where latest is True and scanned_port in [25, 587, 465]"""
        cur = conn.cursor()

        cur.execute(sql)
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


def query_trusty_mail(month, agency_uid):
    """Query trusty mail scan results for a given agency and month."""
    # all_domains_cursor = self.__db.trustymail.find(
    #         {"latest": True, "agency.name": agency}, no_cursor_timeout=True
    #     )
    conn = connect()
    try:
        # Need to verify where statement: other options scan_date, first_seen, last_seen
        sql = """SELECT * FROM cyhy_trustymail where latest is True and organizations_uid = %(org_uid)s"""
        cur = conn.cursor()

        cur.execute(sql, params={"org_uid": agency_uid})
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


def query_cyhy_vuln_scans(start_date, end_date):
    """Query the PE database for vuln data identified by the VS team scans."""
    conn = connect()
    sql = """select o.organizations_uid, o.cyhy_db_name, count(cvs.plugin_name),
    from organizations o
    left join cyhy_vuln_scans cvs on
    o.organizations_uid = cvs.organizations_uid
    where o.report_on  = true and cvs.plugin_name = 'Unsupported Web Server Detection' and
    cvs.cyhy_time  >= %(start_date)s and cvs.cyhy_time < %(end_date)s
    group by o.organizations_uid, o.cyhy_db_name """

    cyhy_vulns = pd.read_sql(
        sql, conn, params={"start_date": start_date, "end_date": end_date}
    )
    conn.close()

    return cyhy_vulns


def query_cyhy_port_scans(start_date, end_date):
    """Query port info identified by vulnerability scanning."""
    try:
        conn = connect()
        sql = """select o.organizations_uid, o.cyhy_db_name, cps.ip, cps.port, cps.service_name, cps.state
            from organizations o
            left join cyhy_port_scans cps on
            o.organizations_uid = cps.organizations_uid
            where o.report_on  = true and cps.cyhy_time  >= %(end_date)s and cps.cyhy_time < %(end_date)s """

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
