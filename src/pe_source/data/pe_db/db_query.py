"""Query the PE PostgreSQL database."""

# Standard Python Libraries
from datetime import datetime
import logging
import sys

# Third-Party Libraries
import psycopg2
from psycopg2 import OperationalError
import psycopg2.extras as extras

# cisagov Libraries
from pe_reports.data.config import config

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
    try:
        conn = psycopg2.connect(**CONN_PARAMS_DIC)
    except OperationalError as err:
        show_psycopg2_exception(err)
        conn = None
    return conn


def close(conn):
    """Close connection to PostgreSQL."""
    conn.close()


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
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_data_source_uid(source):
    """Get data source uid."""
    conn = connect()
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name = '{}'"""
    cur.execute(sql.format(source))
    sources = cur.fetchone()[0]
    cur = conn.cursor()
    # Update last_run in data_source table
    date = datetime.today().strftime("%Y-%m-%d")
    sql = """update data_source set last_run = '{}'
            where name = '{}';"""
    cur.execute(sql.format(date, source))
    cur.close()
    close(conn)
    return sources


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
            "data_source_uid",
        ]
    ]
    table = "alerts"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (sixgill_id)
    DO UPDATE SET content = EXCLUDED.content;"""
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


def insert_sixgill_mentions(df):
    """Insert sixgill mention data."""
    conn = connect()
    try:
        df = df[
            [
                "organizations_uid",
                "data_source_uid",
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
                "data_source_uid",
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
    # Remove any "[\x00|NULL]" characters
    df = df.apply(
        lambda col: col.str.replace(r"[\x00|NULL]", "", regex=True)
        if col.dtype == object
        else col
    )
    table = "mentions"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
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


def insert_sixgill_breaches(df):
    """Insert sixgill breach data."""
    conn = connect()
    table = "credential_breaches"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name) DO UPDATE SET
    exposed_cred_count = EXCLUDED.exposed_cred_count,
    password_included = EXCLUDED.password_included;"""
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
        logging.info("Successfully inserted/updated breaches into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        logging.info(error)
        conn.rollback()
    cursor.close()


def get_breaches():
    """Get credential breaches."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """SELECT breach_name, credential_breaches_uid FROM credential_breaches"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def insert_sixgill_credentials(df):
    """Insert sixgill credential data."""
    conn = connect()
    table = "credential_exposures"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name, email, name) DO UPDATE SET
    modified_date = EXCLUDED.modified_date;"""
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


def insert_sixgill_topCVEs(df):
    """Insert sixgill top CVEs."""
    conn = connect()
    table = "top_cves"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
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


def execute_dnsmonitor_data(dataframe, table):
    """Insert dnsmonitor data."""
    conn = connect("")
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    print(cols)
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (domain_permutation)
    DO UPDATE SET ipv4 = EXCLUDED.ipv4,
        ipv6 = EXCLUDED.ipv6,
        date_observed = EXCLUDED.date_observed,
        mail_server = EXCLUDED.mail_server,
        name_server = EXCLUDED.name_server,
        sub_domain_uid = EXCLUDED.sub_domain_uid,
        data_source_uid = EXCLUDED.data_source_uid;"""
    cursor = conn.cursor()
    extras.execute_values(
        cursor,
        sql.format(
            table,
            cols,
        ),
        tpls,
    )
    conn.commit()
    print("DNSMonitor Data inserted using execute_values() successfully..")


def execute_dnsmonitor_alert_data(dataframe, table):
    """Insert dnsmonitor alert data."""
    conn = connect("")
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    print(cols)
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (alert_type, sub_domain_uid, date, new_value)
    DO NOTHING;"""
    cursor = conn.cursor()
    extras.execute_values(
        cursor,
        sql.format(
            table,
            cols,
        ),
        tpls,
    )
    conn.commit()
    print("DNSMonitor Alert Data inserted using execute_values() successfully..")
