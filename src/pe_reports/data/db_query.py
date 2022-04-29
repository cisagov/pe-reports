"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import logging
import sys

# Third-Party Libraries
import numpy as np
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
from psycopg2.extensions import AsIs

from .config import config

logging.basicConfig(format="%(asctime)-15s %(levelname)s %(message)s", level="INFO")

CONN_PARAMS_DIC = config()


def show_psycopg2_exception(err):
    """Handle errors for PostgreSQL issues."""
    err_type, err_obj, traceback = sys.exc_info()
    logging.error(
        "Database connection error: %s on line number: %s", err, traceback.tb_lineno
    )


def connect():
    """Connect to PostgreSQL database."""
    conn = None
    try:
        logging.info("Connecting to the PostgreSQL......")
        conn = psycopg2.connect(**CONN_PARAMS_DIC)
        logging.info("Connection successful......")
    except OperationalError as err:
        show_psycopg2_exception(err)
        conn = None
    return conn


def close(conn):
    """Close connection to PostgreSQL."""
    conn.close()
    return


def get_orgs(conn):
    """Query organizations table."""
    try:
        cur = conn.cursor()
        sql = """SELECT * FROM organizations"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_creds_view(org_uid, start_date, end_date):
    """Query credentials view ."""
    conn = connect()
    try:
        sql = """SELECT * FROM vw_breachcomp
        WHERE organizations_uid = %(org_uid)s
        AND modified_date BETWEEN %(start_date)s AND %(end_date)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={"org_uid": org_uid, "start_date": start_date, "end_date": end_date},
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_domMasq(org_uid, start_date, end_date):
    """Query domain masquerading table."""
    conn = connect()
    try:
        sql = """SELECT * FROM dnstwist_domain_masq
        WHERE organizations_uid = %(org_uid)s
        AND date_observed BETWEEN %(start_date)s AND %(end_date)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={
                "org_uid": org_uid,
                "start_date": start_date,
                "end_date": end_date,
            },
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# The 'table' parameter is used in query_shodan, query_darkweb and
# query_darkweb_cves functions to call specific tables that relate to the
# function name.  The result of this implementation reduces the code base,
# the code reduction leads to an increase in efficiency by reusing the
# function by passing only a parameter to get the required information from
# the database.


def query_shodan(org_uid, start_date, end_date, table):
    """Query Shodan table."""
    conn = connect()
    try:
        sql = """SELECT * FROM %(table)s
        WHERE organizations_uid = %(org_uid)s
        AND timestamp BETWEEN %(start_date)s AND %(end_date)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={
                "table": AsIs(table),
                "org_uid": org_uid,
                "start_date": start_date,
                "end_date": end_date,
            },
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_darkweb(org_uid, start_date, end_date, table):
    """Query Dark Web table."""
    conn = connect()
    try:
        sql = """SELECT * FROM %(table)s
        WHERE organizations_uid = %(org_uid)s
        AND date BETWEEN %(start_date)s AND %(end_date)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={
                "table": AsIs(table),
                "org_uid": org_uid,
                "start_date": start_date,
                "end_date": end_date,
            },
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_darkweb_cves(table):
    """Query Dark Web CVE table."""
    conn = connect()
    try:
        sql = """SELECT * FROM %(table)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={"table": AsIs(table)},
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_cyberSix_creds(org_uid, start_date, end_date):
    """Query cybersix_exposed_credentials table."""
    conn = connect()
    try:
        sql = """SELECT * FROM public.cybersix_exposed_credentials as creds
        WHERE organizations_uid = %(org_uid)s
        AND breach_date BETWEEN %(start)s AND %(end)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={"org_uid": org_uid, "start": start_date, "end": end_date},
        )
        df["breach_date_str"] = pd.to_datetime(df["breach_date"]).dt.strftime(
            "%m/%d/%Y"
        )
        df.loc[df["breach_name"] == "", "breach_name"] = (
            "Cyber_six_" + df["breach_date_str"]
        )
        df["description"] = (
            df["description"].str.split("Query to find the related").str[0]
        )
        df["password_included"] = np.where(df["password"] != "", True, False)
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)
