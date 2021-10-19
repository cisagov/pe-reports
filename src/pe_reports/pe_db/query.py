"""Query the PE postgres database."""

# Standard Python Libraries
import sys

# Third-Party Libraries
import pandas as pd
from pe_db.config import config
import psycopg2
from psycopg2 import OperationalError
from psycopg2.extensions import AsIs

CONN_PARAMS_DIC = config()


def show_psycopg2_exception(err):
    """Handle errors for postgres issues."""
    err_type, traceback = sys.exc_info()
    line_n = traceback.tb_lineno
    print("\npsycopg2 ERROR:", err, "on line number:", line_n)
    print("psycopg2 traceback:", traceback, "-- type:", err_type)
    print("\nextensions.Diagnostics:", err)
    print("pgerror:", err)
    print("pgcode:", err, "\n")


def connect():
    """Connect to postgres database."""
    conn = None
    try:
        print("[Info] Connecting to the PostgreSQL...........")
        conn = psycopg2.connect(**CONN_PARAMS_DIC)
        print("[Info] Connection successfully..................")
        print("\n")
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
    cur = conn.cursor()
    sql = """SELECT * FROM organizations"""
    cur.execute(sql)
    pe_orgs = cur.fetchall()
    cur.close()
    return pe_orgs


def query_hibp_view(conn, org_uid, start_date, end_date):
    """Query hibp table."""
    sql = """SELECT * FROM vw_breach_complete
    WHERE organizations_uid = %(org_uid)s
    AND modified_date BETWEEN %(start_date)s AND %(end_date)s"""
    df = pd.read_sql(
        sql,
        conn,
        params={"org_uid": org_uid, "start_date": start_date, "end_date": end_date},
    )
    return df


# TODO: update date column in database to be a datetime and add start/end date query
def query_domMasq(conn, org_uid, start_date, end_date):
    """Query domain masquerading table."""
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


def query_shodan(conn, org_uid, start_date, end_date, table):
    """Query Shodan Table."""
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


def query_darkweb(conn, org_uid, start_date, end_date, table):
    """Query Dark Web Table."""
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


def query_darkweb_cves(conn, start_date, end_date, table):
    """Query Dark Web CVE Table."""
    sql = """SELECT * FROM %(table)s
    WHERE date BETWEEN %(start_date)s AND %(end_date)s"""
    df = pd.read_sql(
        sql,
        conn,
        params={
            "table": AsIs(table),
            "start_date": start_date,
            "end_date": end_date,
        },
    )
    return df


def query_cyberSix_creds(conn, org_uid, start_date, end_date):
    """Query hibp table."""
    sql = """SELECT * FROM public.cybersix_exposed_credentials as creds
    WHERE organizations_uid = %(org_uid)s
    AND create_time BETWEEN %(start)s AND %(end)s"""
    df = pd.read_sql(
        sql,
        conn,
        params={"org_uid": org_uid, "start": start_date, "end": end_date},
    )
    return df
