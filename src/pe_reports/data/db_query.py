"""Query the PE postgres database."""

# Standard Python Libraries
import logging
import sys

# Third-Party Libraries
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
from psycopg2.extensions import AsIs

from .config import config

logging.basicConfig(format="%(asctime)-15s %(levelname)s %(message)s", level="INFO")

CONN_PARAMS_DIC = config()


def show_psycopg2_exception(err):
    """Handle errors for postgres issues."""
    err_type, traceback = sys.exc_info()
    line_n = traceback.tb_lineno
    logging.error(f"\npsycopg2 ERROR: {err} on line number: {line_n}")
    logging.error(f"psycopg2 traceback: {traceback} -- type: {err_type}")
    logging.error(f"\nextensions.Diagnostivcs: {err}")

    logging.error(f"pgerror: {err}")

    logging.error(f"pgcode: {err}\n")


def connect():
    """Connect to postgres database."""
    conn = None
    try:
        logging.info("Connecting to the PostgreSQL......")

        conn = psycopg2.connect(**CONN_PARAMS_DIC)
        logging.info("Connection successful................\n")

    except OperationalError as err:
        show_psycopg2_exception(err)
        conn = None
    return conn


def close(conn):
    """Close connection to postgres."""
    conn.close()
    return


def get_orgs(conn):
    """Query orgs table."""
    try:
        cur = conn.cursor()
        sql = """SELECT * FROM organizations"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(f"There was a problem with your database query {error}")
    finally:
        if conn is not None:
            close(conn)


def query_hibp_view(conn, org_uid, start_date, end_date):
    """Query hibp table."""
    try:
        sql = """SELECT * FROM vw_breach_complete
        WHERE organizations_uid = %(org_uid)s
        AND modified_date BETWEEN %(start_date)s AND %(end_date)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={"org_uid": org_uid, "start_date": start_date, "end_date": end_date},
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(f"There was an problem with your database query {error}")
    finally:
        if conn is not None:
            close(conn)


def query_domMasq(conn, org_uid, start_date, end_date):
    """Query domain masquerading table."""
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
        logging.error(f"There was an problem with your database query {error}")
    finally:
        if conn is not None:
            close(conn)


def query_shodan(conn, org_uid, start_date, end_date, table):
    """Query Shodan Table."""
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
        logging.error(f"There was an problem with your database query {error}")
    finally:
        if conn is not None:
            close(conn)


def query_darkweb(conn, org_uid, start_date, end_date, table):
    """Query Dark Web Table."""
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
        logging.error(f"There was an problem with your database query {error}")
    finally:
        if conn is not None:
            close(conn)


def query_darkweb_cves(conn, table):
    """Query Dark Web CVE Table."""
    try:
        sql = """SELECT * FROM %(table)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={"table": AsIs(table)},
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(f"There was an problem with your database query {error}")
    finally:
        if conn is not None:
            close(conn)


def query_cyberSix_creds(conn, org_uid, start_date, end_date):
    """Query hibp table."""
    try:
        sql = """SELECT * FROM public.cybersix_exposed_credentials as creds
        WHERE organizations_uid = %(org_uid)s
        AND breach_date BETWEEN %(start)s AND %(end)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={"org_uid": org_uid, "start": start_date, "end": end_date},
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(f"There was an problem with your database query {error}")
    finally:
        if conn is not None:
            close(conn)
