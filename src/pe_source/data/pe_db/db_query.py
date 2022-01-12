"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import logging
import sys

# Third-Party Libraries
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
import psycopg2.extras as extras

from .config import config

logging.basicConfig(format="%(asctime)-15s %(levelname)s %(message)s", level="INFO")

CONN_PARAMS_DIC = config()


def show_psycopg2_exception(err):
    """Handle errors for PostgreSQL issues."""
    err_type, err_obj, traceback = sys.exc_info()
    line_n = traceback.tb_lineno
    logging.error(f"Database connection error: {err} on line number: {line_n}")


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


def get_orgs():
    """Query organizations table."""
    conn = connect()
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


def get_ips(org_uid):
    """Get IP data."""
    conn = connect()
    sql = """SELECT wa.asset as ip_address
            FROM web_assets wa
            WHERE wa.organizations_uid = %(org_uid)s
            and wa.report_on = True
            and wa.asset_type = 'ipv4'
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    ips = list(df["ip_address"].values)
    conn.close()
    return ips


def insert_sixgill_alerts(df):
    """Insert sixgill alert data."""
    conn = connect()
    df = df[
        [
            "alert_name",
            "content",
            "date",
            "sixgill_id",
            "read",
            "severity",
            "site",
            "threat_level",
            "threats",
            "title",
            "user_id",
            "category",
            "lang",
            "organizations_uid",
        ]
    ]
    table = "alerts"
    # Create a list of tupples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL quert to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (sixgill_id) DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info("Successfully inserted/updated alert data into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)
        conn.rollback()
        cursor.close()
    cursor.close()


def insert_sixgill_mentions(df):
    """Insert sixgill mention data."""
    conn = connect()
    try:
        df = df[
            [
                "organizations_uid",
                "category",
                "collection_date",
                "content",
                "creator",
                "date",
                "sixgill_mention_id",
                "lang",
                "post_id",
                "rep_grade",
                "site",
                "site_grade",
                "sub_category",
                "title",
                "type",
                "url",
                "comments_count",
                "tags",
            ]
        ]
    except Exception as e:
        logging.error(e)
        df = df[
            [
                "organizations_uid",
                "category",
                "collection_date",
                "content",
                "creator",
                "date",
                "sixgill_mention_id",
                "lang",
                "post_id",
                "rep_grade",
                "site",
                "site_grade",
                "sub_category",
                "title",
                "type",
                "url",
                "comments_count",
            ]
        ]
    df = df.apply(
        lambda col: col.str.replace(r"[\x00|NULL]", "", regex=True)
        if col.dtype == object
        else col
    )
    table = "mentions"
    # Create a list of tupples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL quert to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (sixgill_mention_id) DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info("Successfully inserted/updated mention data into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)
        conn.rollback()
        cursor.close()
    cursor.close()


def insert_sixgill_credentials(df):
    """Insert sixgill credential data."""
    conn = connect()
    table = "cybersix_exposed_credentials"
    # Create a list of tupples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL quert to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_id, email) DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info(
            "Successfully inserted/updated exposed credentials into PE database."
        )
    except (Exception, psycopg2.DatabaseError) as error:
        logging.info(error)
        conn.rollback()
        cursor.close()
    cursor.close()


def insert_sixgill_topCVEs(df):
    """Instert sixgill top CVEs."""
    conn = connect()
    table = "top_cves"
    # Create a list of tupples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL quert to execute
    # query = "INSERT INTO {}({}) VALUES %s ON CONFLICT (CVE_id, date) DO NOTHING;"
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (cve_id, date) DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info("Successfully inserted/updated top cve data into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        logging.info(error)
        conn.rollback()
        cursor.close()
    cursor.close()


def insert_shodan_data(dataframe, table, thread, org_name, failed):
    """Insert shodan data into db."""
    conn = connect()
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (organizations_uid, ip, port, protocol, timestamp)
    DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            sql.format(
                table,
                cols,
            ),
            tpls,
        )
        conn.commit()
        logging.info(
            f"{thread} Data inserted using execute_values() successfully - {org_name}"
        )
    except Exception as e:
        logging.error(f"{org_name} failed inserting into {table}")
        logging.error(f"{thread} {e} - {org_name}")
        failed.append(f"{org_name} failed inserting into {table}")
        conn.rollback()
        cursor.close()
    cursor.close()
    return failed
