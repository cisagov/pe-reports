"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import logging
import os
import platform
import sys

# Third-Party Libraries
import numpy as np
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
from psycopg2.extensions import AsIs
import sshtunnel
from sshtunnel import SSHTunnelForwarder

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

    if platform.system() != "Darwin":
        try:
            logging.info("Connecting to the PostgreSQL......")
            conn = psycopg2.connect(**CONN_PARAMS_DIC)
            logging.info("Connection successful......")
        except OperationalError as err:
            show_psycopg2_exception(err)
            conn = None
        return conn
    else:
        theport = thesshTunnel()
        try:

            logging.info("****SSH Tunnel Established****")

            conn = psycopg2.connect(
                host="127.0.0.1",
                user=os.getenv("PE_DB_USER"),
                password=os.getenv("PE_DB_PASSWORD"),
                dbname=os.getenv("PE_DB_NAME"),
                port=theport,
            )

            return conn
        except OperationalError as err:
            show_psycopg2_exception(err)
            conn = None

            return conn


def thesshTunnel():
    """SSH Tunnel to the Crossfeed database instance."""
    server = SSHTunnelForwarder(
        ("localhost"),
        ssh_username="ubuntu",
        ssh_pkey="~/Users/duhnc/.ssh/accessor_rsa",
        remote_bind_address=(
            "crossfeed-stage-db.c4a9ojyrk2io.us-east-1.rds.amazonaws.com",
            5432,
        ),
    )
    server.start()

    return server.local_bind_port


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


def query_hibp_view(org_uid, start_date, end_date):
    """Query 'Have I Been Pwned?' table."""
    conn = connect()
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


def getorgTopicCount(today):
    """Get all organizaiton names from P&E database."""
    # global conn, cursor
    conn = connect()
    cursor = ""
    resultDict = {}

    try:
        # Print all the databases
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query = """select organizations_uid, content_count from topic_totals where count_date like  %('%' + today)s"""
        cursor.execute(query)
        result = cursor.fetchall()

        for row in result:
            # print(row)
            theorg = row[0]
            thecount = row[1]
            resultDict[theorg] = thecount

        return resultDict
    except sshtunnel.BaseSSHTunnelForwarderError:
        logging.info(
            "The ssh screen has not been started," " and will start momentairly."
        )
    finally:
        conn.close()


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
