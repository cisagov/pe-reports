#!/usr/bin/python3
"""CyHy database and sync queries."""

# Standard Python Libraries
import datetime
import logging
import sys
import time

# Third-Party Libraries
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
import psycopg2.extras as extras
from pymongo import MongoClient
from sshtunnel import SSHTunnelForwarder

from .checkAccessor import checkCyhyRunning, checkVMrunning
from .config import db_config, db_password_key

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
        checkCyhyRunning()
        time.sleep(3)
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


def mongo_scan_connect():
    """Connect to CyHy Mongo database."""
    try:
        checkCyhyRunning()
        time.sleep(3)
        db_info = db_config(section="cyhy_mongo")
        host = db_info["host"]
        user = db_info["user"]
        password = db_info["password"]
        port = db_info["port"]
        dbname = db_info["database"]

        CONNECTION_STRING = f"mongodb://{user}:{password}@{host}:{port}/{dbname}"
        mongo_client = MongoClient(CONNECTION_STRING)
        return mongo_client["scan"]
    except Exception as e:
        LOGGER.error(e)
        LOGGER.error(
            "Failed connecting to the CyHy database. Make sure you have the ssh connection running"
        )


def get_pe_org_map(pe_db_conn):
    """Get the P&E/CyHy organization mapping table."""
    pe_org_map = pd.read_sql_query(
        "SELECT * FROM org_id_map WHERE merge_orgs is true;", pe_db_conn
    )
    return pe_org_map


def insert_assets(conn, assets_df, table):
    """Insert CyHy assets into the P&E databse."""
    on_conflict = """ ON CONFLICT (org_id, network)
    DO UPDATE SET
    contact = EXCLUDED.contact,
    org_name = EXCLUDED.org_name,
    type = EXCLUDED.type,
    last_seen = EXCLUDED.last_seen; """
    tpls = [tuple(x) for x in assets_df.to_numpy()]
    cols = ",".join(list(assets_df.columns))
    sql = "INSERT INTO {}({}) VALUES %s"
    sql = sql + on_conflict
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql.format(table, cols), tpls)
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
    sql = "INSERT INTO {}({}) VALUES %s"
    sql = sql + on_conflict
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql.format(table, cols), tpls)
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
            INSERT INTO organizations(name, cyhy_db_name, agency_type, retired,
            receives_cyhy_report, receives_bod_report, receives_cybex_report,
            is_parent, fceb, cyhy_period_start, scorecard, password) VALUES (%s, %s, %s, %s,
             %s, %s, %s,
             %s, %s, %s, %s, PGP_SYM_ENCRYPT(%s, %s))
            ON CONFLICT (cyhy_db_name)
            DO UPDATE SET
                name = EXCLUDED.name,
                password = EXCLUDED.password,
                agency_type = EXCLUDED.agency_type,
                retired = EXCLUDED.retired,
                receives_cyhy_report = EXCLUDED.receives_cyhy_report,
                receives_bod_report= EXCLUDED.receives_bod_report,
                receives_cybex_report = EXCLUDED.receives_cybex_report,
                is_parent = EXCLUDED.is_parent,
                fceb = EXCLUDED.fceb,
                cyhy_period_start = EXCLUDED.cyhy_period_start,
                scorecard = EXCLUDED.scorecard
            """
            cur.execute(
                sql,
                (
                    row["name"],
                    row["cyhy_db_name"],
                    row["agency_type"],
                    row["retired"],
                    row["receives_cyhy_report"],
                    row["receives_bod_report"],
                    row["receives_cybex_report"],
                    row["is_parent"],
                    row["fceb"],
                    row["cyhy_period_start"],
                    row["scorecard"],
                    row["password"],
                    password,
                ),
            )
            conn.commit()
            cur.close()
        except (Exception, psycopg2.DatabaseError) as err:
            show_psycopg2_exception(err)
            cur.close()
            continue
    LOGGER.info("Agencies inserted using execute_values() successfully..")


def insert_sectors(conn, sectors_list):
    """Insert sectors into database."""
    password = db_password_key()
    for sector in sectors_list:
        try:
            cur = conn.cursor()
            sql = """
            INSERT INTO sectors(id, acronym, name, email, contact_name, retired, first_seen, last_seen, password) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, PGP_SYM_ENCRYPT(%s, %s))
            ON CONFLICT (id)
            DO UPDATE SET
                acronym = EXCLUDED.acronym,
                name = EXCLUDED.name,
                email = EXCLUDED.email,
                contact_name = EXCLUDED.contact_name,
                retired = EXCLUDED.retired,
                last_seen = EXCLUDED.last_seen,
                password = EXCLUDED.password
            """
            cur.execute(
                sql,
                (
                    sector["id"],
                    sector["acronym"],
                    sector["name"],
                    sector["email"],
                    sector["contact_name"],
                    sector["retired"],
                    datetime.datetime.today().date(),
                    datetime.datetime.today().date(),
                    sector["password"],
                    password,
                ),
            )
            conn.commit()
            cur.close()

        except (Exception, psycopg2.DatabaseError) as err:
            show_psycopg2_exception(err)
            cur.close()
            continue


def insert_sector_org_relationship(conn, sector_org_list):
    """Insert sector org relationship into many to many table."""
    # MAYBE TODO delete relationships first to make sure we are up to date

    for element in sector_org_list:
        try:
            cur = conn.cursor()
            sql = """
                INSERT INTO sectors_orgs(sector_uid, organizations_uid, first_seen, last_seen)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (sector_uid, organizations_uid)
                DO UPDATE SET
                last_seen = EXCLUDED.last_seen
            """
            cur.execute(sql, (element[0], element[1], element[2], element[3]))
            conn.commit()
            cur.close()

            # conflict = """ON CONFLICT (sector_uid, organizations_uid)
            #     DO UPDATE SET
            #     last_seen = EXCLUDED.last_seen"""
            # cols = "sector_uid, organizations_uid, first_seen, last_seen"
            # sql = "INSERT INTO sectors_orgs({}) VALUES %s".format(cols)
            # sql = sql + conflict
            # cursor = conn.cursor()

            # extras.execute_values(cursor, sql, sector_org_list)
            # conn.commit()
        except (Exception, psycopg2.DatabaseError) as err:
            show_psycopg2_exception(err)
            cur.close()
            continue


def query_pe_orgs(conn):
    """Query P&E organizations."""
    sql = """
    SELECT organizations_uid, cyhy_db_name, name, agency_type, report_on, fceb, scorecard
    FROM organizations o
    """
    df = pd.read_sql(sql, conn)
    return df


def query_pe_sectors(conn):
    """Query P&E sectors."""
    sql = """
    SELECT sector_uid, id, acronym, run_scorecards
    FROM sectors
    """
    df = pd.read_sql(sql, conn)
    return df


def query_pe_report_on_orgs(conn):
    """Query P&E organizations."""
    sql = """
    SELECT organizations_uid, cyhy_db_name, name, agency_type
    FROM organizations o
    WHERE report_on or run_scans or fceb or fceb_child
    """
    df = pd.read_sql(sql, conn)
    return df


def update_child_parent_orgs(conn, parent_uid, child_name):
    """Update child parent relationships between organizations."""
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


def add_sector_hierachy(conn, child_uid, parent_uid):
    """Update parent_sector_uid field."""
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE sectors
        set parent_sector_uid = %s
        where sector_uid = %s
        """,
        (parent_uid, child_uid),
    )

    conn.commit()
    cursor.close()


def update_scan_status(conn, child_name):
    """Update child parent relationships between organizations."""
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE organizations
        set run_scans = True
        where cyhy_db_name = %s
        """,
        (child_name),
    )

    conn.commit()
    cursor.close()


def update_fceb_child_status(conn, child_name):
    """Update child parent relationships between organizations."""
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE organizations
        set fceb_child = True
        where cyhy_db_name = %s
        """,
        (child_name),
    )

    conn.commit()
    cursor.close()


def updated_scorecard_child_status(conn, child_name):
    """Update organizations that are children of scorecard orgs."""
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE organizations
        set scorecard_child = True
        where cyhy_db_name = %s
        """,
        (child_name),
    )

    conn.commit()
    cursor.close()


def insert_dot_gov_domains(conn, dotgov_df, table):
    """Insert dot gov domains."""
    conflict = """
        ON CONFLICT (domain_name)
        DO UPDATE SET  domain_type = EXCLUDED.domain_type, agency = EXCLUDED.agency, organization = EXCLUDED.organization, city = EXCLUDED.city, state = EXCLUDED.state, security_contact_email = EXCLUDED.security_contact_email;
    """
    tpls = [tuple(x) for x in dotgov_df.to_numpy()]
    cols = ",".join(list(dotgov_df.columns))
    sql = "INSERT INTO {}({}) VALUES %s"
    sql = sql + conflict
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql.format(table, cols), tpls)
        conn.commit()
        LOGGER.info("Dot gov data inserted using execute_values() successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cursor.close()


def query_cidrs(conn):
    """Query all cidrs ordered by length."""
    sql = """SELECT tc.cidr_uid, tc.network, tc.organizations_uid, tc.insert_alert
            FROM cidrs tc
            WHERE current
            ORDER BY masklen(tc.network)
            """
    df = pd.read_sql(sql, conn)
    return df


def execute_ips(conn, df):
    """Insert the ips into the ips table in the database and link them to the associated cidr."""
    try:
        # Execute insert query
        tpls = [tuple(x) for x in df.to_numpy()]
        cols = ",".join(list(df.columns))
        table = "ips"
        sql = """
        INSERT INTO {}({}) VALUES %s
        ON CONFLICT (ip)
        DO UPDATE SET
            origin_cidr = UUID(EXCLUDED.origin_cidr),
            last_seen = EXCLUDED.last_seen,
            organizations_uid = EXCLUDE.organizations_uid;
        """
        cursor = conn.cursor()
        extras.execute_values(cursor, sql.format(table, cols), tpls, page_size=100000)
        conn.commit()
        LOGGER.info("%s new IPs successfully upserted into ip table...", len(df))
    except (Exception, psycopg2.DatabaseError) as err:
        # Show error and close connection if failed
        LOGGER.error("There was a problem with your database query %s", err)
        cursor.close()


def query_roots(conn):
    """Query all root_domains."""
    sql = """SELECT r.root_domain_uid, r.root_domain FROM root_domains r
            where r.enumerate_subs = True
            """
    df = pd.read_sql(sql, conn)
    return df


def insert_sub_domains(conn, df):
    """Save subdomains dataframe to the P&E DB."""
    try:
        # Execute insert query
        df = df.drop_duplicates()
        tpls = [tuple(x) for x in df.to_numpy()]
        cols = ",".join(list(df.columns))
        table = "sub_domains"
        sql = """
            INSERT INTO {}({}) VALUES %s
            ON CONFLICT (sub_domain, root_domain_uid)
            DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                identified = EXCLUDED.identified;
            """
        cursor = conn.cursor()
        extras.execute_values(cursor, sql.format(table, cols), tpls)
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as err:
        # Show error and close connection if failed
        LOGGER.error("There was a problem with your database query %s", err)
        # cursor.close()


def query_ips(org_uid, conn):
    """Query all ips that link to a cidr related to a specific org."""
    sql = """SELECT i.ip_hash, i.ip, ct.network FROM ips i
            JOIN cidrs ct on ct.cidr_uid = i.origin_cidr
            where ct.organizations_uid = %(org_uid)s
            and i.origin_cidr is not null
            and (i.last_reverse_lookup < current_date - interval '7 days' or i.last_reverse_lookup is null)
            and i."current"
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    return df


def query_subs(org_uid, conn):
    """Query all subs for an organization."""
    sql = """SELECT sd.* FROM sub_domains sd
            JOIN root_domains rd on rd.root_domain_uid = sd.root_domain_uid
            where rd.organizations_uid = %(org_uid)s
            and sd.current
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    return df


def query_cidrs_by_org(conn, org_id):
    """Get CIDRs by org."""
    sql = """
    SELECT network, cidr_uid
    FROM cidrs ct
    join organizations o on o.organizations_uid = ct.organizations_uid
    WHERE o.organizations_uid = %(org_id)s
    and current;
    """
    df = pd.read_sql(sql, conn, params={"org_id": org_id})
    return df


def update_shodan_ips(conn, df):
    """Update if an IP is a shodan IP."""
    tpls = [tuple(x) for x in df.to_numpy()]
    cols = ",".join(list(df.columns))
    table = "ips"
    sql = """
        INSERT INTO {}({})
        VALUES %s
        ON CONFLICT (ip)
            DO UPDATE SET shodan_results = EXCLUDED.shodan_results,
            current = EXCLUDED.current"""
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql.format(table, cols), tpls)
        conn.commit()
        print("Data inserted using execute_values() successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cursor.close()


def query_floating_ips(conn, org_id):
    """Query floating IPs (IPs found from current sub-domains)."""
    sql = """
    SELECT i.ip
    FROM ips i
    join ips_subs ip_s on ip_s.ip_hash = i.ip_hash
    join sub_domains sd on sd.sub_domain_uid = ip_s.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    WHERE rd.organizations_uid = %(org_id)s
    AND i.origin_cidr is null
    and sd.current;
    """
    df = pd.read_sql(sql, conn, params={"org_id": org_id})
    ips = set(df["ip"])
    return ips


def identify_org_asset_changes(conn):
    """Identify Org Asset changes."""
    cursor = conn.cursor()
    LOGGER.info("Marking CIDRs that are in the db.")
    cursor.execute(
        """
        UPDATE cyhy_db_assets
        set currently_in_cyhy = True
        where last_seen > (CURRENT_DATE - INTERVAL '3 days')
        """
    )
    conn.commit()

    LOGGER.info("Marking CIDRs that are no longer seen.")
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE cyhy_db_assets
        set currently_in_cyhy = False
        where last_seen < (CURRENT_DATE - INTERVAL '3 days')
        """
    )
    conn.commit()


def identify_cidr_changes(conn):
    """Identify CIDR changes."""
    cursor = conn.cursor()
    LOGGER.info("Marking CIDRs that are in the db.")
    cursor.execute(
        """
        UPDATE cidrs
        set current = True
        where last_seen > (CURRENT_DATE - INTERVAL '3 days')
        """
    )
    conn.commit()

    LOGGER.info("Marking CIDRs that are no longer seen.")
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE cidrs
        set current = False
        where last_seen < (CURRENT_DATE - INTERVAL '3 days')
        """
    )
    conn.commit()


def identify_ip_changes(conn):
    """Identify IP changes."""
    cursor = conn.cursor()
    LOGGER.info("Marking IPs that are in the db.")
    cursor.execute(
        """
        UPDATE ips
        set current = True
        where last_seen > (CURRENT_DATE - INTERVAL '15 days')
        """
    )
    conn.commit()

    LOGGER.info("Marking IPs that are no longer seen.")
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE ips
        set current = False
        where last_seen < (CURRENT_DATE - INTERVAL '15 days') or last_seen isnull;
        """
    )
    conn.commit()


def identify_sub_changes(conn):
    """Identify IP changes."""
    cursor = conn.cursor()
    LOGGER.info("Marking Subs that are in the db.")
    cursor.execute(
        """
        UPDATE sub_domains
        set current = True
        where last_seen > (CURRENT_DATE - INTERVAL '15 days')
        """
    )
    conn.commit()

    LOGGER.info("Marking IPs that are no longer seen.")
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE sub_domains
        set current = False
        where last_seen < (CURRENT_DATE - INTERVAL '15 days') or last_seen isnull;
        """
    )
    conn.commit()


def identify_ip_sub_changes(conn):
    """Identify IP/Subs changes."""
    cursor = conn.cursor()
    LOGGER.info("Marking Subs that are in the db.")
    cursor.execute(
        """
        UPDATE ips_subs
        set current = True
        where last_seen > (CURRENT_DATE - INTERVAL '15 days')
        """
    )
    conn.commit()

    LOGGER.info("Marking IPs that are no longer seen.")
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE ips_subs
        set current = False
        where last_seen < (CURRENT_DATE - INTERVAL '15 days') or last_seen isnull;
        """
    )
    conn.commit()


def insert_cyhy_scorecard_data(conn, df, table_name, on_conflict):
    """Save cyhy scorecard dataframe to the P&E DB."""
    try:
        # Execute insert query
        df = df.drop_duplicates()
        tpls = [tuple(x) for x in df.to_numpy()]
        cols = ",".join(list(df.columns))
        table = table_name
        sql = """
            INSERT INTO {}({}) VALUES %s
            """
        sql = sql + on_conflict
        cursor = conn.cursor()
        extras.execute_values(cursor, sql.format(table, cols), tpls)
        conn.commit()
        LOGGER.info("Success inserting data.")
    except (Exception, psycopg2.DatabaseError) as err:
        # Show error and close connection if failed
        LOGGER.error("There was a problem with your database query %s", err)
        cursor.close()


def identified_sub_domains(conn):
    """Set sub-domains to identified."""
    # If the sub's root-domain has enumerate=False, then "identified" is True
    cursor = conn.cursor()
    LOGGER.info("Marking identified sub-domains.")
    cursor.execute(
        """
        UPDATE sub_domains sd
        set identified = true
        from root_domains rd
        where rd.root_domain_uid = sd.root_domain_uid and rd.enumerate_subs = false;
        """
    )
    conn.commit()
    cursor.close()


def get_fceb_orgs(conn):
    """Query fceb orgs."""
    sql = """select * from organizations o
            where o.fceb or o.fceb_child;
            """
    df = pd.read_sql(sql, conn)
    fceb_list = list(df["cyhy_db_name"])
    return fceb_list
