#!/usr/bin/python3
"""CyHy database and sync queries."""

# Standard Python Libraries
import logging
import time
import sys

# Third-Party Libraries
import pandas as pd
from pymongo import MongoClient
import psycopg2
from psycopg2 import OperationalError
from psycopg2.extensions import AsIs
import psycopg2.extras as extras
from sshtunnel import SSHTunnelForwarder

# cisagov Libraries
from .config import db_config, db_password_key
from .checkAccessor import checkVMrunning

LOGGER = logging.getLogger(__name__)


def show_psycopg2_exception(err):
    """Handle errors for PostgreSQL issues."""
    err_type, err_obj, traceback = sys.exc_info()
    LOGGER.error(
        "Database connection error: %s on line number: %s", err, traceback.tb_lineno
    )


def pe_db_connect():
    """Connect to PostgreSQL database."""
    conn = None
    conn_dict = db_config(section="postgres")
    try:
        LOGGER.info("Connecting to the local PostgreSQL")
        conn = psycopg2.connect(**conn_dict)
        LOGGER.info("Connection successful")
    except OperationalError as err:
        show_psycopg2_exception(err)
        conn = None
    return conn


def pe_db_staging_connect():
    """Establish an SSH tunnel to the staging environement."""
    checkVMrunning()
    time.sleep(3)
    conn_staging_dict = db_config(section="staging")
    ssh_port = sshTunnel(conn_staging_dict)
    try:
        LOGGER.info("****SSH Tunnel Established****")
        conn = psycopg2.connect(
            host="localhost",
            user=conn_staging_dict["user"],
            password=conn_staging_dict["password"],
            dbname=conn_staging_dict["database"],
            port=ssh_port,
        )
        return conn
    except OperationalError as err:
        show_psycopg2_exception(err)
        conn = None
        return conn


def sshTunnel(conn_staging_dict):
    """SSH Tunnel to the Crossfeed database instance."""
    server = SSHTunnelForwarder(
        ("localhost"),
        ssh_username="ubuntu",
        remote_bind_address=(
            conn_staging_dict["host"],
            int(conn_staging_dict["port"]),
        ),
    )
    server.start()
    return server.local_bind_port


def mongo_connect():
    """Connect to CyHy Mongo database."""
    try:
        db_info = db_config(section="cyhy_mongo")
        host = db_info["host"]
        user = db_info["user"]
        password = db_info["password"]
        port = db_info["port"]
        dbname = db_info["database"]

        CONNECTION_STRING = f"mongodb://{user}:{password}@{host}:{port}/{dbname}"
        mongo_client = MongoClient(CONNECTION_STRING)
        return mongo_client["cyhy"]
    except Exception as e:
        LOGGER.error(e)
        LOGGER.error(
            "Failed connecting to the CyHy database. Make sure you have the ssh connection running"
        )


def get_pe_org_map(pe_db_conn):
    pe_org_map = pd.read_sql_query(
        "SELECT * FROM org_id_map WHERE merge_orgs is true;", pe_db_conn
    )
    return pe_org_map


def insert_assets(conn, assets_df, table):
    """Insert CyHy assets into the P&E databse."""
    on_conflict = """
        ON CONFLICT (org_id, network)
        DO UPDATE SET 
            contact = EXCLUDED.contact, 
            org_name = EXCLUDED.org_name, 
            type = EXCLUDED.type,
            last_seen = EXCLUDED.last_seen;
    """
    tpls = [tuple(x) for x in assets_df.to_numpy()]
    cols = ",".join(list(assets_df.columns))
    sql = "INSERT INTO %s(%s) VALUES %%s" % (table, cols)
    sql = sql + on_conflict
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql, tpls)
        conn.commit()
        LOGGER.info("Asset data inserted using execute_values() successfully")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cursor.close()


def insert_contacts(conn, contacts_df, table):
    """Insert CyHy contacts into the P&E databse."""
    on_conflict = """
        ON CONFLICT (org_id, contact_type, email, name)
        DO UPDATE SET
            org_name = EXCLUDED.org_name, 
            phone = EXCLUDED.phone, 
            date_pulled = EXCLUDED.date_pulled;
    """
    tpls = [tuple(x) for x in contacts_df.to_numpy()]
    cols = ",".join(list(contacts_df.columns))
    sql = "INSERT INTO %s(%s) VALUES %%s" % (table, cols)
    sql = sql + on_conflict
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql, tpls)
        conn.commit()
        LOGGER.info("Contact data inserted using execute_values() successfully")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cursor.close()


def insert_cyhy_agencies(conn, cyhy_agency_df):
    """Insert CyHy agencies into the P&E database."""
    password = db_password_key()
    for i, row in cyhy_agency_df.iterrows():
        try:
            cur = conn.cursor()
            sql = """
            INSERT INTO organizations(name, cyhy_db_name, agency_type, password) VALUES (%s, %s, %s, PGP_SYM_ENCRYPT(%s, %s))
            ON CONFLICT (cyhy_db_name)
            DO UPDATE SET 
                password = EXCLUDED.password, 
                agency_type = EXCLUDED.agency_type
            """
            cur.execute(
                sql,
                (
                    row["name"],
                    row["cyhy_db_name"],
                    row["agency_type"],
                    row["password"],
                    password,
                ),
            )
            conn.commit()
        except (Exception, psycopg2.DatabaseError) as err:
            show_psycopg2_exception(err)
            cur.close()
            continue
    LOGGER.info("Agencies inserted using execute_values() successfully..")


def query_pe_orgs(conn):
    sql = """
    SELECT organizations_uid, cyhy_db_name, name, agency_type
    FROM organizations o
    """
    df = pd.read_sql(sql, conn)
    return df


def update_child_parent_orgs(conn, parent_uid, child_name):
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE organizations
        set parent_org_uid = %s
        where cyhy_db_name = %s
        """,
        (parent_uid, child_name),
    )

    conn.commit()
    cursor.close()


def insert_dot_gov_domains(conn, dotgov_df, table):
    conflict = """
        ON CONFLICT (domain_name)
        DO UPDATE SET  domain_type = EXCLUDED.domain_type, agency = EXCLUDED.agency, organization = EXCLUDED.organization, city = EXCLUDED.city, state = EXCLUDED.state, security_contact_email = EXCLUDED.security_contact_email;
    """
    tpls = [tuple(x) for x in dotgov_df.to_numpy()]
    cols = ",".join(list(dotgov_df.columns))
    sql = "INSERT INTO %s(%s) VALUES %%s" % (table, cols)
    sql = sql + conflict
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql, tpls)
        conn.commit()
        LOGGER.info("Dot gov data inserted using execute_values() successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cursor.close()


def identify_org_asset_changes(conn):
    cursor = conn.cursor()
    LOGGER.info("Marking CIDRs that are in the db.")
    cursor.execute(
        """
        UPDATE cyhy_db_assets
        set currently_in_cyhy = True
        where last_seen = CURRENT_DATE
        """
    )
    conn.commit()

    LOGGER.info("Marking CIDRs that are no longer seen.")
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE cyhy_db_assets
        set currently_in_cyhy = False
        where last_seen <> CURRENT_DATE
        """
    )
    conn.commit()


def identify_cidr_changes(conn):
    cursor = conn.cursor()
    LOGGER.info("Marking CIDRs that are in the db.")
    cursor.execute(
        """
        UPDATE cidrs
        set current = True
        where last_seen = CURRENT_DATE
        """
    )
    conn.commit()

    LOGGER.info("Marking CIDRs that are no longer seen.")
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE cidrs
        set current = False
        where last_seen <> CURRENT_DATE
        """
    )
    conn.commit()
