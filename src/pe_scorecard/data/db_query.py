#!/usr/bin/env python
"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import logging
import sys
import datetime

# Third-Party Libraries
import psycopg2
from psycopg2 import OperationalError
import pandas as pd

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


def query_https_scan(month, agency):
    """Query https scan results for a given agency and month."""


def query_sslyze_scan(month, agency):
    """Query sslyze scan results for a given agency and month."""
    # "domain", "scanned_port", "scanned_hostname", "sslv2", "sslv3", "any_3des", "any_rc4", "is_symantec_cert


def query_subs_https_scan(base_domain):
    """Query sub_domain sslyze scan results for a given root_domain."""


#  self.__db.https_scan.find(
#                         {
#                             "latest": True,
#                             "base_domain": domain_doc["base_domain"],
#                             "is_base_domain": False,
#                         }
#                     ).sort([("domain", 1)])


def query_trusty_mail(month, agency):
    """Query trusty mail scan results for a given agency and month."""
    # all_domains_cursor = self.__db.trustymail.find(
    #         {"latest": True, "agency.name": agency}, no_cursor_timeout=True
    #     )


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
    sql = """SELECT organizations_uid, cyhy_db_name FROM organizations WHERE report_on = True;"""
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


# ^ ---------- I-Score SQL Queries ---------- ^
