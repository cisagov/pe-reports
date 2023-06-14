#!/usr/bin/env python
"""Query the PE PostgreSQL database."""

# Standard Python Libraries
from datetime import datetime
import logging
import socket
import sys
import os

# Third-Party Libraries
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
import psycopg2.extras as extras

LOGGER = logging.getLogger(__name__)


def show_psycopg2_exception(err):
    """Handle errors for PostgreSQL issues."""
    err_type, err_obj, traceback = sys.exc_info()
    logging.error(
        "Database connection error: %s on line number: %s", err, traceback.tb_lineno
    )


def connect():
    """Connect to PostgreSQL database."""
    try:
        print(os.environ.get("PE_DB_NAME"))
        db_name = os.environ.get("PE_DB_NAME")
        if not db_name:
            LOGGER.info("Database credentials have not been set in the environment.")
            return None
        conn = psycopg2.connect(
            host=os.environ.get("DB_HOST"),
            user=os.environ.get("PE_DB_USERNAME"),
            password=os.environ.get("PE_DB_PASSWORD"),
            dbname=os.environ.get("PE_DB_NAME"),
            port=5432,
        )
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
        sql = """SELECT * FROM organizations where report_on or demo"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        keys = ("org_uid", "org_name", "cyhy_db_name")
        pe_orgs = [dict(zip(keys, values)) for values in pe_orgs]
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_ips(org_uid):
    """Get IP data."""
    conn = connect()
    sql1 = """SELECT i.ip_hash, i.ip, ct.network FROM ips i
    JOIN cidrs ct on ct.cidr_uid = i.origin_cidr
    JOIN organizations o on o.organizations_uid = ct.organizations_uid
    where o.organizations_uid = %(org_uid)s
    and i.origin_cidr is not null
    and i.shodan_results is True;"""
    df1 = pd.read_sql(sql1, conn, params={"org_uid": org_uid})
    ips1 = list(df1["ip"].values)

    sql2 = """select i.ip_hash, i.ip
    from ips i
    join ips_subs is2 ON i.ip_hash = is2.ip_hash
    join sub_domains sd on sd.sub_domain_uid = is2.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    JOIN organizations o on o.organizations_uid = rd.organizations_uid
    where o.organizations_uid = %(org_uid)s
    and i.shodan_results is True;"""
    df2 = pd.read_sql(sql2, conn, params={"org_uid": org_uid})
    ips2 = list(df2["ip"].values)

    in_first = set(ips1)
    in_second = set(ips2)

    in_second_but_not_in_first = in_second - in_first

    ips = ips1 + list(in_second_but_not_in_first)
    conn.close()

    return ips


def get_data_source_uid(source):
    """Get data source uid."""
    conn = connect()
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name = '{}'"""
    cur.execute(sql.format(source))
    source = cur.fetchone()[0]
    cur.close()
    cur = conn.cursor()
    # Update last_run in data_source table
    date = datetime.today().strftime("%Y-%m-%d")
    sql = """update data_source set last_run = '{}'
            where name = '{}';"""
    cur.execute(sql.format(date, source))
    cur.close()
    close(conn)
    return source


def insert_sixgill_alerts(df):
    """Insert sixgill alert data."""
    conn = connect()
    columns_to_subset = [
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
        "content_snip",
        "asset_mentioned",
        "asset_type",
    ]
    try:
        df = df.loc[:, df.columns.isin(columns_to_subset)]
    except Exception as e:
        logging.error(e)
    table = "alerts"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (sixgill_id) DO UPDATE SET
    content = EXCLUDED.content,
    content_snip = EXCLUDED.content_snip,
    asset_mentioned = EXCLUDED.asset_mentioned,
    asset_type = EXCLUDED.asset_type;"""
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
    columns_to_subset = [
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
    try:
        df = df.loc[:, df.columns.isin(columns_to_subset)]
    except Exception as e:
        logging.error(e)

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
    ON CONFLICT (breach_name, email) DO UPDATE SET
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


def insert_shodan_data(dataframe, table, thread, org_name, failed):
    """Insert Shodan data into database."""
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
            "{} Data inserted using execute_values() successfully - {}".format(
                thread, org_name
            )
        )
    except Exception as e:
        logging.error("{} failed inserting into {}".format(org_name, table))
        logging.error("{} {} - {}".format(thread, e, org_name))
        failed.append("{} failed inserting into {}".format(org_name, table))
        conn.rollback()
    cursor.close()
    return failed


def execute_dnsmonitor_data(dataframe, table):
    """Insert DNSMonitor data."""
    conn = connect()
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (domain_permutation, organizations_uid)
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
        sql.format(table, cols),
        tpls,
    )
    conn.commit()


def execute_dnsmonitor_alert_data(dataframe, table):
    """Insert DNSMonitor alerts."""
    conn = connect()
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (alert_type, sub_domain_uid, date, new_value)
    DO NOTHING;"""
    cursor = conn.cursor()
    extras.execute_values(
        cursor,
        sql.format(table, cols),
        tpls,
    )
    conn.commit()


def getSubdomain(domain):
    """Get subdomain."""
    conn = connect()
    cur = conn.cursor()
    print(domain)
    sql = """SELECT * FROM sub_domains sd
        WHERE sd.sub_domain = %s"""
    print(sql)
    cur.execute(sql, [domain])
    sub = cur.fetchone()
    cur.close()
    print(sub)
    return sub


def getRootdomain(domain):
    """Get root domain."""
    conn = connect()
    cur = conn.cursor()
    sql = """SELECT * FROM root_domains rd
        WHERE rd.root_domain = '{}'"""
    cur.execute(sql.format(domain))
    root = cur.fetchone()
    cur.close()
    return root


def addRootdomain(root_domain, pe_org_uid, source_uid, org_name):
    """Add root domain."""
    conn = connect()
    ip_address = str(socket.gethostbyname(root_domain))
    sql = """insert into root_domains(root_domain, organizations_uid, organization_name, data_source_uid, ip_address)
            values ('{}', '{}', '{}', '{}', '{}');"""
    cur = conn.cursor()
    cur.execute(sql.format(root_domain, pe_org_uid, org_name, source_uid, ip_address))
    conn.commit()
    cur.close()


def addSubdomain(conn, domain, pe_org_uid, root):
    """Add a subdomain into the database."""
    closeConn = False
    if conn is None:
        conn = connect()
        closeConn = True
    if root:
        root_domain = domain
    else:
        root_domain = domain.split(".")[-2:]
        root_domain = ".".join(root_domain)

    print(domain)
    cur = conn.cursor()
    date = datetime.today().strftime("%Y-%m-%d")
    cur.callproc(
        "insert_sub_domain",
        (False, date, domain, pe_org_uid, "findomain", root_domain, None),
    )
    sub_uid = cur.fetchall()
    print(sub_uid)
    # Fetch all notice messages
    notices = conn.notices

    # Print the notice messages
    print("NOTICES")
    for notice in notices:
        print(notice)
    LOGGER.info("Success adding domain %s to subdomains table.", domain)
    if closeConn:
        close(conn)

    conn = connect()
    cur = conn.cursor()
    print(domain)
    sql = """SELECT * FROM sub_domains"""
    print(sql)
    cur.execute(sql)
    sub = cur.fetchone()
    cur.close()
    print(sub)

    conn = connect()
    cur = conn.cursor()
    print(domain)
    sql = """SELECT * FROM root_domains"""
    print(sql)
    cur.execute(sql)
    sub = cur.fetchone()
    cur.close()
    print(sub)
    return sub_uid


def org_root_domains(conn, org_uid):
    """Get root domains from database given the org_uid."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """select * from root_domains rd
                where rd.organizations_uid = %s;"""
        cur.execute(sql, [org_uid])
        roots = cur.fetchall()
        print(roots)
        keys = (
            "root_uid",
            "org_uid",
            "root_domain",
            "ip_address",
            "data_source_uid",
            "enumerate_subs",
        )
        roots = [dict(zip(keys, values)) for values in pe_orgs]
        print(roots)
        cur.close()
        return roots
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_orgs_rev():
    """Query orgs in reverse."""
    conn = connect()
    sql = "SELECT * FROM organizations WHERE report_on is True ORDER BY organizations_uid DESC;"
    df = pd.read_sql_query(sql, conn)
    return df


def insert_intelx_breaches(df):
    """Insert intelx breach data."""
    conn = connect()
    table = "credential_breaches"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name) DO UPDATE SET
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


def get_intelx_breaches(source_uid):
    """Get IntelX credential breaches."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """SELECT breach_name, credential_breaches_uid FROM credential_breaches where data_source_uid = %s"""
        cur.execute(sql, [source_uid])
        all_breaches = cur.fetchall()
        cur.close()
        return all_breaches
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def insert_intelx_credentials(df):
    """Insert sixgill credential data."""
    conn = connect()
    table = "credential_exposures"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name, email) DO UPDATE SET
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
