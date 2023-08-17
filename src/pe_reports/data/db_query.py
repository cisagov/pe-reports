#!/usr/bin/env python
"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import datetime
from ipaddress import ip_address, ip_network
import logging
import socket
import sys
import time
import requests
import json

# Third-Party Libraries
import numpy as np
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
from psycopg2.extensions import AsIs
import psycopg2.extras as extras
from sshtunnel import SSHTunnelForwarder

from .config import config, staging_config

# Setup logging to central file
LOGGER = logging.getLogger(__name__)

CONN_PARAMS_DIC = config()
CONN_PARAMS_DIC_STAGING = staging_config()

# These need to filled with API key/url path in database.ini
pe_api_key = CONN_PARAMS_DIC_STAGING.get("pe_api_key")
pe_api_url = CONN_PARAMS_DIC_STAGING.get("pe_api_url")


def task_api_call(task_url, check_url, data={}, retry_time=3):
    """
    Query tasked endpoint given task_url and check_url

    Return:
        Endpoint result
    """
    # Endpoint info
    create_task_url = pe_api_url + task_url
    check_task_url = pe_api_url + check_url
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    task_status = "Pending"
    check_task_resp = ""
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info("Created task for", task_url, "query, task_id: ", task_id)
        check_task_url += task_id
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged", check_url, "status endpoint, status:", task_status)
            time.sleep(retry_time)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)
    # Once task finishes, return result
    if task_status == "Completed":
        return check_task_resp.get("result")
    else:
        raise Exception("API calls failed ", check_task_resp)


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


def connect_to_staging():
    """Establish an SSH tunnel to the staging environement."""
    theport = thesshTunnel()
    try:
        LOGGER.info("****SSH Tunnel Established****")
        conn = psycopg2.connect(
            host="localhost",
            user=CONN_PARAMS_DIC_STAGING["user"],
            password=CONN_PARAMS_DIC_STAGING["password"],
            dbname=CONN_PARAMS_DIC_STAGING["database"],
            port=theport,
        )
        return conn
        LOGGER.info("Success connecting to the staging db.")
    except OperationalError as err:
        show_psycopg2_exception(err)
        conn = None
        return conn


def thesshTunnel():
    """SSH Tunnel to the Crossfeed database instance."""
    server = SSHTunnelForwarder(
        ("localhost"),
        ssh_username="ubuntu",
        remote_bind_address=(
            CONN_PARAMS_DIC_STAGING["host"],
            int(CONN_PARAMS_DIC_STAGING["port"]),
        ),
    )
    server.start()
    return server.local_bind_port


def execute_values(conn, dataframe, table, except_condition=";"):
    """INSERT into table, generic."""
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = "INSERT INTO {}({}) VALUES %s"
    sql = sql + except_condition
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql.format(table, cols), tpls)
        conn.commit()
        print("Data inserted using execute_values() successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cursor.close()


def get_orgs(conn):
    """Query organizations table for orgs we report on."""
    try:
        cur = conn.cursor()
        sql = """SELECT * FROM organizations
        WHERE report_on is True"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_orgs_pass(conn, password):
    """Get all org passwords."""
    try:
        cur = conn.cursor()
        sql = """SELECT cyhy_db_name, PGP_SYM_DECRYPT(password::bytea, %s)
        FROM organizations o
        WHERE report_on;"""
        cur.execute(sql, [password])
        pe_orgs = cur.fetchall()
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_orgs_contacts(conn):
    """Get all org contacts."""
    try:
        cur = conn.cursor()
        sql = """select email, contact_type, org_id
        from cyhy_contacts cc
        join organizations o on cc.org_id = o.cyhy_db_name
        where o.report_on;"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_org_assets_count_past(org_uid, date):
    """Get asset counts for an organization."""
    conn = connect()
    sql = """select * from report_summary_stats rss 
                where organizations_uid = %(org_id)s
                and end_date = %(date)s;"""
    df = pd.read_sql(sql, conn, params={"org_id": org_uid, "date": date})
    conn.close()
    return df


def get_org_assets_count(uid):
    """Get asset counts for an organization."""
    conn = connect()
    cur = conn.cursor()
    sql = """select sur.cyhy_db_name, sur.num_root_domain, sur.num_sub_domain, sur.num_ips, sur.num_ports, sur.num_cidrs, sur.num_ports_protocols , sur.num_software, sur.num_foreign_ips
            from mat_vw_orgs_attacksurface sur
            where sur.organizations_uid = %s"""
    cur.execute(sql, [uid])
    try:
        source = cur.fetchone()
        cur.close()
        conn.close()
        assets_dict = {
            "org_uid": uid,
            "cyhy_db_name": source[0],
            "num_root_domain": source[1],
            "num_sub_domain": source[2],
            "num_ips": source[3],
            "num_ports": source[4],
            "num_cidrs": source[5],
            "num_ports_protocols": source[6],
            "num_software": source[7]
            - 1,  # Subtract 1 to remove the automatic null entry
            "num_foreign_ips": source[8],
        }
    except:
        assets_dict = {
            "org_uid": uid,
            "cyhy_db_name": "N/A",
            "num_root_domain": 0,
            "num_sub_domain": 0,
            "num_ips": 0,
            "num_ports": 0,
            "num_cidrs": 0,
            "num_ports_protocols": 0,
            "num_software": 0,
            "num_foreign_ips": 0,
        }
    return assets_dict


def get_orgs_df(staging=False):
    """Query organizations table for new orgs."""
    if staging:
        conn = connect_to_staging()
    else:
        conn = connect()
    try:
        sql = """
        SELECT * FROM organizations 
        WHERE report_on is True
        """
        pe_orgs_df = pd.read_sql(sql, conn)
        return pe_orgs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_new_orgs():
    """Query organizations table for new orgs."""
    conn = connect()
    try:
        sql = """SELECT * FROM organizations WHERE report_on='False'"""
        pe_orgs_df = pd.read_sql(sql, conn)
        return pe_orgs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def set_org_to_report_on(cyhy_db_id, premium: bool = False):
    """Set organization to report_on."""
    sql = """
    SELECT *
    FROM organizations o
    where o.cyhy_db_name = %(org_id)s
    """
    params = config()
    conn = psycopg2.connect(**params)
    df = pd.read_sql_query(sql, conn, params={"org_id": cyhy_db_id})

    if len(df) < 1:
        LOGGER.error("No org found for that cyhy id")
        return 0

    for i, row in df.iterrows():
        if row["report_on"] == True:
            if row["premium_report"] == premium:
                continue

        cursor = conn.cursor()
        sql = """UPDATE organizations
                SET report_on = True, premium_report = %s, demo = False
                WHERE organizations_uid = %s"""
        uid = row["organizations_uid"]
        cursor.execute(sql, (premium, uid))
        conn.commit()
        cursor.close()
    conn.close()
    return df


def set_org_to_demo(cyhy_db_id, premium):
    """Set organization to demo."""
    sql = """
    SELECT *
    FROM organizations o
    where o.cyhy_db_name = %(org_id)s
    """
    params = config()
    conn = psycopg2.connect(**params)
    df = pd.read_sql_query(sql, conn, params={"org_id": cyhy_db_id})

    if len(df) < 1:
        LOGGER.error("No org found for that cyhy id")
        return 0

    for i, row in df.iterrows():
        if row["demo"] == True:
            if row["premium_report"] == premium:
                continue

        cursor = conn.cursor()
        sql = """UPDATE organizations
                SET report_on = False, premium_report = %s, demo = True
                WHERE organizations_uid = %s"""
        uid = row["organizations_uid"]
        cursor.execute(sql, (premium, uid))
        conn.commit()
        cursor.close()
    conn.close()
    return df


# --- Issue 608 ---
def query_cyhy_assets(org_cyhy_name):
    """
    Query API to retrieve all cyhy assets for an organization.

    Args:
        org_cyhy_name: CyHy database name of the specified organization (not uid)

    Return:
        All the cyhy assets belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "cyhy_assets_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_cyhy_name": org_cyhy_name})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
                "field_id": "_id",
            },
            inplace=True,
        )
        result_df["first_seen"] = pd.to_datetime(result_df["first_seen"]).dt.date
        result_df["last_seen"] = pd.to_datetime(result_df["last_seen"]).dt.date
        return result_df
    except requests.exceptions.HTTPError as errh:
        LOGGER.info(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.info(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.info(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.info(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.info(err)


def get_data_source_uid(source):
    """Get data source uid."""
    params = config()
    conn = psycopg2.connect(**params)
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name = '{}'"""
    cur.execute(sql.format(source))
    source = cur.fetchone()[0]
    cur.close()
    cur = conn.cursor()
    # Update last_run in data_source table
    date = datetime.datetime.today().strftime("%Y-%m-%d")
    sql = """update data_source set last_run = '{}'
            where name = '{}';"""
    cur.execute(sql.format(date, source))
    cur.close()
    conn.close()
    return source


def api_get_data_source_uid(source):
    """Query organizations table."""
    urlOrgs = pe_api_url
    headers = {
        "Content-Type": "application/json",
        "access_token": f'{api_config("API_KEY")}',
    }
    try:

        response = requests.post(
            urlOrgs + "data_source/" + source, headers=headers
        ).json()
        # Change last viewed
        uid = response[0]["data_source_uid"]
        r = requests.put(urlOrgs + "update_last_viewed/" + uid, headers=headers)
        LOGGER.info("Updated last viewed for %s", source)
        return response
    except requests.exceptions.HTTPError as errh:
        print(errh)
    except requests.exceptions.ConnectionError as errc:
        print(errc)
    except requests.exceptions.Timeout as errt:
        print(errt)
    except requests.exceptions.RequestException as err:
        print(err)
    except json.decoder.JSONDecodeError as err:
        print(err)


def verifyIPv4(custIP):
    """Verify if parameter is a valid IPv4 IP address."""
    try:
        if ip_address(custIP):
            return True

        else:
            return False

    except ValueError as err:
        LOGGER.error("The address is incorrect, %s", err)
        return False


def validateIP(custIP):
    """
    Verify IPv4 and CIDR.

    Collect address information into a list that is ready for DB insertion.
    """
    verifiedIP = []
    for the_ip in custIP:
        if verifyCIDR(the_ip) or verifyIPv4(the_ip):
            verifiedIP.append(the_ip)
    return verifiedIP


def verifyCIDR(custIP):
    """Verify if parameter is a valid CIDR block IP address."""
    try:
        if ip_network(custIP):
            return True

        else:
            return False

    except ValueError as err:
        LOGGER.error("The CIDR is incorrect, %s", err)
        return False


# --- Issue 610 ---
def get_cidrs_and_ips(org_uid):
    """
    Query API to retrieve all CIDRs and IPs for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the CIDRs and IPs belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "cidrs_ips_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        result_list = [d["ip"] for d in result]
        # validate IPs
        validateIP(result_list)
        LOGGER.info(result_list)
        # Process data and return
        return result_list
    except requests.exceptions.HTTPError as errh:
        LOGGER.info(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.info(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.info(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.info(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.info(err)


def query_cidrs():
    """Query all cidrs ordered by length."""
    conn = connect()
    sql = """SELECT tc.cidr_uid, tc.network, tc.organizations_uid, tc.insert_alert
            FROM cidrs tc
            ORDER BY masklen(tc.network)
            """
    df = pd.read_sql(sql, conn)
    conn.close()
    return df


# --- Issue 611 ---
def query_ips(org_uid):
    """
    Query API to retrieve all IPs for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the IPs belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "ips_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        cidr_ip_list = [d["ip"] for d in result["cidr_ip_data"]]
        sub_root_ip_list = [d["ip"] for d in result["sub_root_ip_data"]]
        cidr_ip_set = set(cidr_ip_list)
        sub_root_ip_set = set(sub_root_ip_list)
        diff_set = sub_root_ip_set - cidr_ip_set
        final_ip_list = cidr_ip_list + list(diff_set)
        return final_ip_list
    except requests.exceptions.HTTPError as errh:
        LOGGER.info(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.info(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.info(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.info(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.info(err)


# --- Issue 612 ---
def query_extra_ips(org_uid):
    """
    Query API to retrieve all extra IPs for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the extra IPs belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "extra_ips_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_list = list(set([d["ip"] for d in result]))
        return result_list
    except requests.exceptions.HTTPError as errh:
        LOGGER.info(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.info(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.info(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.info(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.info(err)


# --- Issue 616 ---
def set_from_cidr():
    """
    Query API to set from_cidr to True for any IPs that have an origin_cidr.
    """
    # Endpoint info
    task_url = "ips_update_from_cidr"
    status_url = "ips_update_from_cidr/task/"
    data = None
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    LOGGER.info(result)


def refresh_asset_counts_vw():
    conn = connect()
    sql = """
        REFRESH MATERIALIZED VIEW
        public.mat_vw_orgs_attacksurface
        WITH DATA
    """
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()

    LOGGER.info("Refreshing breach comp")
    conn = connect()
    sql = """
        REFRESH MATERIALIZED VIEW
        public.mat_vw_breachcomp
        WITH DATA
    """
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()

    LOGGER.info("Refreshing breach details")
    conn = connect()
    sql = """
        REFRESH MATERIALIZED VIEW
        public.mat_vw_breachcomp_breachdetails
        WITH DATA
    """
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()

    LOGGER.info("Refreshing breach creds by date")
    conn = connect()
    sql = """
        REFRESH MATERIALIZED VIEW
        public.mat_vw_breachcomp_credsbydate
        WITH DATA
    """
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()


# --- Issue 618 ---
def query_cidrs_by_org(org_uid):
    """
    Query API to retrieve all CIDRs for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the CIDRs belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "cidrs_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
                "organizations_uid_id": "organizations_uid",
                "data_source_uid_id": "data_source_uid",
            },
            inplace=True,
        )
        result_df["first_seen"] = pd.to_datetime(result_df["first_seen"]).dt.date
        result_df["last_seen"] = pd.to_datetime(result_df["last_seen"]).dt.date
        return result_df
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 619 ---
def query_ports_protocols(org_uid):
    """
    Query API to retrieve all distinct ports/protocols for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the distinct ports/protocols belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "ports_protocols_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        return result_df
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 620 ---
def query_software(org_uid):
    """
    Query API to retrieve all distinct software products for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the distinct software belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "software_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        return result_df
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 621 ---
def query_foreign_IPs(org_uid):
    """
    Query API to retrieve all foreign ips for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the foreign ips belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "foreign_ips_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
                "organizations_uid_id": "organizations_uid",
                "data_source_uid_id": "data_source_uid",
            },
            inplace=True,
        )
        return result_df
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


def insert_roots(org, domain_list):
    """Insert root domains into the database."""
    source_uid = get_data_source_uid("P&E")
    roots_list = []
    for domain in domain_list:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = np.nan
        root = {
            "organizations_uid": org["organizations_uid"].iloc[0],
            "root_domain": domain,
            "ip_address": ip,
            "data_source_uid": source_uid,
            "enumerate_subs": True,
        }
        roots_list.append(root)

    roots = pd.DataFrame(roots_list)
    except_clause = """ ON CONFLICT (root_domain, organizations_uid)
    DO NOTHING;"""
    params = config()
    conn = psycopg2.connect(**params)
    execute_values(conn, roots, "public.root_domains", except_clause)


# --- Issue 622 ---
def query_roots(org_uid):
    """
    Query API to retrieve all root domains for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the root domains belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "root_domains_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        return result_df
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


def query_creds_view(org_uid, start_date, end_date):
    """Query credentials view ."""
    conn = connect()
    try:
        sql = """SELECT * FROM mat_vw_breachcomp
        WHERE organizations_uid = %(org_uid)s
        AND modified_date BETWEEN %(start_date)s AND %(end_date)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={"org_uid": org_uid, "start_date": start_date, "end_date": end_date},
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_credsbyday_view(org_uid, start_date, end_date):
    """Query credentials by date view ."""
    conn = connect()
    try:
        sql = """SELECT mod_date, no_password, password_included FROM mat_vw_breachcomp_credsbydate
        WHERE organizations_uid = %(org_uid)s
        AND mod_date BETWEEN %(start_date)s AND %(end_date)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={"org_uid": org_uid, "start_date": start_date, "end_date": end_date},
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_breachdetails_view(org_uid, start_date, end_date):
    """Query credentials by date view ."""
    conn = connect()
    try:
        sql = """SELECT breach_name, mod_date modified_date, breach_date, password_included, number_of_creds
        FROM mat_vw_breachcomp_breachdetails
        WHERE organizations_uid = %(org_uid)s
        AND mod_date BETWEEN %(start_date)s AND %(end_date)s"""
        df = pd.read_sql(
            sql,
            conn,
            params={"org_uid": org_uid, "start_date": start_date, "end_date": end_date},
        )
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_domMasq(org_uid, start_date, end_date):
    """Query domain masquerading table."""
    conn = connect()
    try:
        sql = """SELECT * FROM domain_permutations
        WHERE organizations_uid = %(org_uid)s
        AND date_active BETWEEN %(start_date)s AND %(end_date)s"""
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
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def query_domMasq_alerts(org_uid, start_date, end_date):
    """Query domain alerts table."""
    conn = connect()
    try:
        sql = """SELECT * FROM domain_alerts
        WHERE organizations_uid = %(org_uid)s
        AND date BETWEEN %(start_date)s AND %(end_date)s"""
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
        LOGGER.error("There was a problem with your database query %s", error)
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
        df = pd.DataFrame()
        df_list = []
        chunk_size = 1000
        sql = """SELECT * FROM %(table)s
        WHERE organizations_uid = %(org_uid)s
        AND timestamp BETWEEN %(start_date)s AND %(end_date)s"""
        count = 0
        # Batch SQL call to reduce memory (https://pythonspeed.com/articles/pandas-sql-chunking/)
        for chunk_df in pd.read_sql(
            sql,
            conn,
            params={
                "table": AsIs(table),
                "org_uid": org_uid,
                "start_date": start_date,
                "end_date": end_date,
            },
            chunksize=chunk_size,
        ):
            count += 1
            df_list.append(chunk_df)

        if len(df_list) == 0:
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
        else:
            df = pd.concat(df_list, ignore_index=True)
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# --- Issue 629 ---
# This funciton either references the "mentions" table or the "alerts" table
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
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# -- Issue 630 ---
# This Function references the "top_cves" table
# this one will use
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
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# --- Issue 560 ---
def query_all_subs():
    """
    Query API for the entire sub_domains table.

    Return:
        The sub_domains table as a dataframe
    """
    start_time = time.time()
    total_num_pages = 1
    page_num = 1
    total_data = []
    # Retrieve data for each page
    while page_num <= total_num_pages:
        # Endpoint info
        create_task_url = pe_api_url + "sub_domains_table"
        check_task_url = pe_api_url + "sub_domains_table/task/"
        headers = {
            "Content-Type": "application/json",
            "access_token": pe_api_key,
        }
        data = json.dumps({"page": page_num, "per_page": 250000})
        try:
            # Create task for query
            create_task_result = requests.post(
                create_task_url, headers=headers, data=data
            ).json()
            task_id = create_task_result.get("task_id")
            LOGGER.info(
                "Created task for sub_domains_table endpoint query, task_id: ", task_id
            )
            # Once task has been started, keep pinging task status until finished
            check_task_url += task_id
            task_status = "Pending"
            ping_ctr = 1
            while task_status != "Completed" and task_status != "Failed":
                # Ping task status endpoint and get status
                check_task_resp = requests.get(check_task_url, headers=headers).json()
                task_status = check_task_resp.get("status")
                LOGGER.info(
                    "\t",
                    ping_ctr,
                    "Pinged sub_domains_table status endpoint, status:",
                    task_status,
                )
                ping_ctr += 1
                time.sleep(3)
        except requests.exceptions.HTTPError as errh:
            LOGGER.error(errh)
        except requests.exceptions.ConnectionError as errc:
            LOGGER.error(errc)
        except requests.exceptions.Timeout as errt:
            LOGGER.error(errt)
        except requests.exceptions.RequestException as err:
            LOGGER.error(err)
        except json.decoder.JSONDecodeError as err:
            LOGGER.error(err)
        # Once task finishes, return result
        if task_status == "Completed":
            # Append retrieved data to total list
            result = check_task_resp.get("result")
            total_data += result.get("data")
            total_num_pages = result.get("total_pages")
            LOGGER.info("Retrieved page:", page_num, "of", total_num_pages)
            page_num += 1
        else:
            raise Exception(
                "sub_domains_table query task failed, details: ", check_task_resp
            )
    # Once all data has been retrieved, return overall dataframe
    total_data = pd.DataFrame.from_dict(total_data)
    LOGGER.info(
        "Total time to retrieve entire sub_domains table:", (time.time() - start_time)
    )
    total_data.rename(
        columns={
            "root_domain_uid_id": "root_domain_uid",
            "data_source_uid_id": "data_source_uid",
            "dns_record_uid_id": "dns_record_uid",
        },
        inplace=True,
    )
    return total_data


# --- Issue 633 ---
def query_subs(org_uid):
    """
    Query API to retrieve all subdomains for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the subdomains belonging to the specified org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "sub_domains_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
                "root_domain_uid_id": "root_domain_uid",
                "data_source_uid_id": "data_source_uid",
                "dns_record_uid_id": "dns_record_uid",
            },
            inplace=True,
        )
        result_df["first_seen"] = pd.to_datetime(result_df["first_seen"]).dt.date
        result_df["last_seen"] = pd.to_datetime(result_df["last_seen"]).dt.date
        return result_df
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 559 ---
def execute_ips(new_ips):
    """
    Query API to insert new IP record into ips table.
    On ip conflict, update the old record with the new data

    Args:
        new_ips: Dataframe containing the new IPs and their ip_hash/ip/origin_cidr data
    """
    # Convert dataframe to list of dictionaries
    new_ips = new_ips[["ip_hash", "ip", "origin_cidr"]]
    new_ips = new_ips.to_dict("records")
    # Endpoint info
    task_url = "ips_insert"
    status_url = "ips_insert/task/"
    data = json.dumps({"new_ips": new_ips})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    LOGGER.info("Successfully inserted new IPs into ips table using execute_ips()")


# --- Issue 632 ---
def execute_scorecard(summary_dict):
    """
    Insert a record for an organization into the report_summary_stats table.
    On org_uid/star_date conflict, update the old record with the new data

    Args:
        summary_dict: Dictionary of column names and values to be inserted
    """
    # Endpoint info
    endpoint_url = pe_api_url + "rss_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(summary_dict)
    try:
        # Call endpoint
        rss_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()
        LOGGER.info("Successfully inserted new record in report_summary_stats table")
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 634 ---
def query_previous_period(org_uid, prev_end_date):
    """
    Query API for previous period report_summary_stats data for a specific org.

    Args:
        org_uid: The organizations_uid of the specified organization
        prev_end_date: The end_date of the previous report period

    Return:
        Report_summary_stats data from the previous report period for a specific org as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "rss_prev_period"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {
            "org_uid": org_uid,
            "prev_end_date": prev_end_date,
        }
    )
    try:
        # Call endpoint
        rss_prev_period_result = requests.get(
            endpoint_url, headers=headers, data=data
        ).json()
    except requests.exceptions.HTTPError as errh:
        LOGGER.info(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.info(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.info(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.info(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.info(err)

    # Once task finishes, return result
    if rss_prev_period_result:
        # Return results if valid
        assets_dict = {
            "last_ip_count": rss_prev_period_result["ip_count"],
            "last_root_domain_count": rss_prev_period_result["root_count"],
            "last_sub_domain_count": rss_prev_period_result["sub_count"],
            "last_cred_password_count": rss_prev_period_result["cred_password_count"],
            "last_sus_vuln_addrs_count": rss_prev_period_result[
                "suspected_vuln_addrs_count"
            ],
            "last_suspected_vuln_count": rss_prev_period_result["suspected_vuln_count"],
            "last_insecure_port_count": rss_prev_period_result["insecure_port_count"],
            "last_actor_activity_count": rss_prev_period_result["threat_actor_count"],
        }
    else:
        # If no results, return all 0 dict
        assets_dict = {
            "last_ip_count": 0,
            "last_root_domain_count": 0,
            "last_sub_domain_count": 0,
            "last_cred_password_count": 0,
            "last_sus_vuln_addrs_count": 0,
            "last_suspected_vuln_count": 0,
            "last_insecure_port_count": 0,
            "last_actor_activity_count": 0,
        }
    return assets_dict


# --- Issue 635 ---
def pescore_hist_domain_alert(start_date, end_date):
    """
    Get all historical domain alert data for the PE score.

    Args:
        start_date: start date of query time range
        end_date: end date of query time range

    Return:
        Dataframe of historical domain alert data for the PE score
    """
    # Endpoint info
    task_url = "pescore_hist_domain_alert"
    status_url = "pescore_hist_domain_alert/task/"
    data = json.dumps({"start_date": start_date, "end_date": end_date})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    reported_orgs = pd.DataFrame.from_dict(result["reported_orgs"])
    pescore_hist_domain_alert_data = pd.DataFrame.from_dict(
        result["hist_domain_alert_data"]
    )
    # Combine data and return
    result_df = pd.merge(
        reported_orgs,
        pescore_hist_domain_alert_data,
        on="organizations_uid",
        how="left",
    )
    result_df.rename(columns={"date": "mod_date"}, inplace=True)
    result_df["mod_date"] = pd.to_datetime(result_df["mod_date"]).dt.date
    return result_df


# --- Issue 635 ---
def pescore_hist_darkweb_alert(start_date, end_date):
    """
    Get all historical darkweb alert data for the PE score.

    Args:
        start_date: start date of query time range
        end_date: end date of query time range

    Return:
        Dataframe of historical darkweb alert data for the PE score
    """
    # Endpoint info
    task_url = "pescore_hist_darkweb_alert"
    status_url = "pescore_hist_darkweb_alert/task/"
    data = json.dumps({"start_date": start_date, "end_date": end_date})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    reported_orgs = pd.DataFrame.from_dict(result["reported_orgs"])
    pescore_hist_darkweb_alert_data = pd.DataFrame.from_dict(
        result["hist_darkweb_alert_data"]
    )
    # Combine data and return
    result_df = pd.merge(
        reported_orgs,
        pescore_hist_darkweb_alert_data,
        on="organizations_uid",
        how="left",
    )
    result_df.rename(columns={"date": "mod_date"}, inplace=True)
    result_df["mod_date"] = pd.to_datetime(result_df["mod_date"]).dt.date
    return result_df


# --- Issue 635 ---
def pescore_hist_darkweb_ment(start_date, end_date):
    """
    Get all historical darkweb mention data for the PE score.

    Args:
        start_date: start date of query time range
        end_date: end date of query time range

    Return:
        Dataframe of historical darkweb mention data for the PE score
    """
    # Endpoint info
    task_url = "pescore_hist_darkweb_ment"
    status_url = "pescore_hist_darkweb_ment/task/"
    data = json.dumps({"start_date": start_date, "end_date": end_date})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    reported_orgs = pd.DataFrame.from_dict(result["reported_orgs"])
    pescore_hist_darkweb_ment_data = pd.DataFrame.from_dict(
        result["hist_darkweb_ment_data"]
    )
    # Combine data and return
    result_df = pd.merge(
        reported_orgs,
        pescore_hist_darkweb_ment_data,
        on="organizations_uid",
        how="left",
    )
    result_df["count"].fillna(0, inplace=True)
    result_df.rename(columns={"count": "num_mentions"}, inplace=True)
    result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


# --- Issue 635 ---
def pescore_hist_cred(start_date, end_date):
    """
    Get all historical credential data for the PE score.

    Args:
        start_date: start date of query time range
        end_date: end date of query time range

    Return:
        Dataframe of historical credential data for the PE score
    """
    # Endpoint info
    task_url = "pescore_hist_cred"
    status_url = "pescore_hist_cred/task/"
    data = json.dumps({"start_date": start_date, "end_date": end_date})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    reported_orgs = pd.DataFrame.from_dict(result["reported_orgs"])
    pescore_hist_cred_data = pd.DataFrame.from_dict(result["hist_cred_data"])
    # Combine data and return
    result_df = pd.merge(
        reported_orgs,
        pescore_hist_cred_data,
        on="organizations_uid",
        how="left",
    )
    result_df["no_password"].fillna(0, inplace=True)
    result_df["password_included"].fillna(0, inplace=True)
    result_df["total_creds"] = result_df["no_password"] + result_df["password_included"]
    result_df["mod_date"] = pd.to_datetime(result_df["mod_date"]).dt.date
    return result_df


# --- Issue 635 ---
def pescore_base_metrics(start_date, end_date):
    """
    Get all base metrics for the PE score.

    Args:
        start_date: start date of query time range
        end_date: end date of query time range

    Return:
        Dataframe of base metrics for the PE score.
    """
    # Retrieve PE score base metrics:
    task_url = "pescore_base_metrics"
    status_url = "pescore_base_metrics/task/"
    data = json.dumps({"start_date": start_date, "end_date": end_date})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process reported_orgs list
    reported_orgs = pd.DataFrame.from_dict(result["reported_orgs"])
    # Process cred metrics
    cred_data = pd.DataFrame.from_dict(result["cred_data"]).rename(
        columns={"password_included": "num_pass_creds"}
    )
    cred_data["num_total_creds"] = (
        cred_data["no_password"] + cred_data["num_pass_creds"]
    )
    cred_data.drop(columns="no_password", inplace=True)
    breach_data = pd.DataFrame.from_dict(result["breach_data"])
    # Combine all cred metrics
    cred_df = pd.merge(
        pd.merge(reported_orgs, cred_data, on="organizations_uid", how="left"),
        breach_data,
        on="organizations_uid",
        how="left",
    ).fillna(0)
    # Process domain metrics
    domain_sus_data = pd.DataFrame.from_dict(result["domain_sus_data"])
    domain_alert_data = pd.DataFrame.from_dict(result["domain_alert_data"])
    # Combine all domain metrics
    domain_df = pd.merge(
        pd.merge(reported_orgs, domain_sus_data, on="organizations_uid", how="left"),
        domain_alert_data,
        on="organizations_uid",
        how="left",
    ).fillna(0)
    # Process vuln metrics
    vuln_verif_data = pd.DataFrame.from_dict(result["vuln_verif_data"])
    vuln_unverif_data = pd.DataFrame.from_dict(result["vuln_unverif_data"])
    vuln_port_data = pd.DataFrame.from_dict(result["vuln_port_data"])
    vuln_port_data.rename(
        columns={"num_risky_ports": "num_insecure_ports"}, inplace=True
    )
    # Combine all vuln metrics
    vuln_df = pd.merge(
        pd.merge(
            pd.merge(
                reported_orgs, vuln_verif_data, on="organizations_uid", how="left"
            ),
            vuln_unverif_data,
            on="organizations_uid",
            how="left",
        ),
        vuln_port_data,
        on="organizations_uid",
        how="left",
    ).fillna(0)
    # Process darkweb metrics
    darkweb_alert_data = pd.DataFrame.from_dict(result["darkweb_alert_data"])
    darkweb_ment_data = pd.DataFrame.from_dict(result["darkweb_ment_data"])
    darkweb_threat_data = pd.DataFrame.from_dict(result["darkweb_threat_data"])
    darkweb_inv_data = pd.DataFrame.from_dict(result["darkweb_inv_data"])
    # Combine all darkweb metrics
    darkweb_df = pd.merge(
        pd.merge(
            pd.merge(
                pd.merge(
                    reported_orgs,
                    darkweb_alert_data,
                    on="organizations_uid",
                    how="left",
                ),
                darkweb_ment_data,
                on="organizations_uid",
                how="left",
            ),
            darkweb_threat_data,
            on="organizations_uid",
            how="left",
        ),
        darkweb_inv_data,
        on="organizations_uid",
        how="left",
    ).fillna(0)
    # Process attacksurface metrics
    attacksurface_df = pd.DataFrame.from_dict(result["attacksurface_data"])
    # Combine all data and return
    result_df = pd.merge(
        pd.merge(
            pd.merge(
                pd.merge(
                    cred_df,
                    domain_df,
                    on="organizations_uid",
                    how="inner",
                ),
                vuln_df,
                on="organizations_uid",
                how="inner",
            ),
            darkweb_df,
            on="organizations_uid",
            how="inner",
        ),
        attacksurface_df,
        on="organizations_uid",
        how="inner",
    )
    # Reorganize columns
    result_df = result_df[
        [
            "organizations_uid",
            "cyhy_db_name",
            "num_breaches",
            "num_total_creds",
            "num_pass_creds",
            "num_alert_domain",
            "num_sus_domain",
            "num_insecure_ports",
            "num_verif_vulns",
            "num_assets_unverif_vulns",
            "num_dw_alerts",
            "num_dw_mentions",
            "num_dw_invites",
            "num_ports",
            "num_root_domain",
            "num_sub_domain",
            "num_ips",
        ]
    ]
    result_df.sort_values(by="cyhy_db_name", inplace=True)
    result_df.reset_index(drop=True, inplace=True)
    return result_df


# --- Issue 636 ---
def get_new_cves_list():
    """
    Get any detected CVEs that aren't in the cve_info table yet.

    Return:
        Dataframe of detected CVE names that aren't in the cve_info table yet
    """
    # Endpoint info
    endpoint_url = pe_api_url + "pescore_check_new_cve"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Call endpoint
        pescore_check_new_cve_result = requests.get(
            endpoint_url, headers=headers
        ).json()
        return pd.DataFrame.from_dict(pescore_check_new_cve_result)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 637 ---
def upsert_new_cves(new_cves):
    """
    Query API to upsert new CVE records into cve_info.
    On cve_name conflict, update the old record with the new data

    Args:
        new_cves: Dataframe containing the new CVEs and their CVSS2.0/3.1/DVE data
    """
    # Convert dataframe to list of dictionaries
    new_cves = new_cves.to_dict("records")
    # Endpoint info
    task_url = "cve_info_insert"
    status_url = "cve_info_insert/task/"
    data = json.dumps({"new_cves": new_cves})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    LOGGER.info(
        "Successfully inserted new CVEs into cve_info table using upsert_new_cves()"
    )


# v ---------- D-Score API Queries, Issue 571 ---------- v
def api_dscore_vs_cert(org_list):
    """
    Query API for all VS certificate data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS certificate data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    task_url = "dscore_vs_cert"
    status_url = "dscore_vs_cert/task/"
    data = json.dumps({"specified_orgs": org_list})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


def api_dscore_vs_mail(org_list):
    """
    Query API for all VS mail data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS mail data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    task_url = "dscore_vs_mail"
    status_url = "dscore_vs_mail/task/"
    data = json.dumps({"specified_orgs": org_list})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


def api_dscore_pe_ip(org_list):
    """
    Query API for all PE IP data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All PE IP data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    task_url = "dscore_pe_ip"
    status_url = "dscore_pe_ip/task/"
    data = json.dumps({"specified_orgs": org_list})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


def api_dscore_pe_domain(org_list):
    """
    Query API for all PE domain data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All PE domain data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    task_url = "dscore_pe_domain"
    status_url = "dscore_pe_domain/task/"
    data = json.dumps({"specified_orgs": org_list})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


def api_dscore_was_webapp(org_list):
    """
    Query API for all WAS webapp data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All WAS webapp data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    task_url = "dscore_was_webapp"
    status_url = "dscore_was_webapp/task/"
    data = json.dumps({"specified_orgs": org_list})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


def api_fceb_status(org_list):
    """
    Query API for the FCEB status of a list of organizations.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        The FCEB status of the specified list of organizations
    """
    # Endpoint info
    task_url = "fceb_status"
    status_url = "fceb_status/task/"
    data = json.dumps({"specified_orgs": org_list})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


# v ---------- I-Score API Queries, Issue 570 ---------- v
def api_iscore_vs_vuln(org_list):
    """
    Query API for all VS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS vuln data of the specified orgs needed for the I-Score
    """
    # Endpoint info
    task_url = "iscore_vs_vuln"
    status_url = "iscore_vs_vuln/task/"
    data = json.dumps({"specified_orgs": org_list})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    # If empty dataframe comes back, insert placeholder data
    if result_df.empty:
        result_df = pd.concat(
            [
                result_df,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "cve_name": "test_cve",
                        "cvss_score": 1.0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    return result_df


def api_iscore_vs_vuln_prev(org_list, start_date, end_date):
    """
    Query API for all previous VS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All previous VS vuln data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    task_url = "iscore_vs_vuln_prev"
    status_url = "iscore_vs_vuln_prev/task/"
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    # If empty dataframe comes back, insert placeholder data
    if result_df.empty:
        result_df = pd.concat(
            [
                result_df,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "cve_name": "test_cve",
                        "cvss_score": 1.0,
                        "time_closed": datetime.date(1, 1, 1),
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    else:
        result_df["time_closed"] = pd.to_datetime(result_df["time_closed"]).dt.date
    return result_df


def api_iscore_pe_vuln(org_list, start_date, end_date):
    """
    Query API for all PE vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE vuln data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    task_url = "iscore_pe_vuln"
    status_url = "iscore_pe_vuln/task/"
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    # If empty dataframe comes back, insert placeholder data
    if result_df.empty:
        result_df = pd.concat(
            [
                result_df,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "date": datetime.date(1, 1, 1),
                        "cve_name": "test_cve",
                        "cvss_score": 1.0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    else:
        result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


def api_iscore_pe_cred(org_list, start_date, end_date):
    """
    Query API for all PE cred data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE cred data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    task_url = "iscore_pe_cred"
    status_url = "iscore_pe_cred/task/"
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    # If empty dataframe comes back, insert placeholder data
    if result_df.empty:
        result_df = pd.concat(
            [
                result_df,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "date": datetime.date(1, 1, 1),
                        "password_creds": 0,
                        "total_creds": 0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    else:
        result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


def api_iscore_pe_breach(org_list, start_date, end_date):
    """
    Query API for all PE breach data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE breach data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    task_url = "iscore_pe_breach"
    status_url = "iscore_pe_breach/task/"
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    # If empty dataframe comes back, insert placeholder data
    if result_df.empty:
        result_df = pd.concat(
            [
                result_df,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "date": datetime.date(1, 1, 1),
                        "breach_count": 0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    else:
        result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


def api_iscore_pe_darkweb(org_list, start_date, end_date):
    """
    Query API for all PE darkweb data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE darkweb data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    task_url = "iscore_pe_darkweb"
    status_url = "iscore_pe_darkweb/task/"
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    # If empty dataframe comes back, insert placeholder data
    if result_df.empty:
        result_df = pd.concat(
            [
                result_df,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "alert_type": "TEST_TYPE",
                        "date": datetime.date(1, 1, 1),
                        "Count": 0,
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    else:
        result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


def api_iscore_pe_protocol(org_list, start_date, end_date):
    """
    Query API for all PE protocol data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All PE protocol data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    task_url = "iscore_pe_protocol"
    status_url = "iscore_pe_protocol/task/"
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    # If empty dataframe comes back, insert placeholder data
    if result_df.empty:
        result_df = pd.concat(
            [
                result_df,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "port": "test_port",
                        "ip": "test_ip",
                        "protocol": "test_protocol",
                        "protocol_type": "test_type",
                        "date": datetime.date(1, 1, 1),
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    else:
        result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


def api_iscore_was_vuln(org_list, start_date, end_date):
    """
    Query API for all WAS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All WAS vuln data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    task_url = "iscore_was_vuln"
    status_url = "iscore_was_vuln/task/"
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    # If empty dataframe comes back, insert placeholder data
    if result_df.empty:
        result_df = pd.concat(
            [
                result_df,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
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
    else:
        result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


def api_iscore_was_vuln_prev(org_list, start_date, end_date):
    """
    Query API for all previous WAS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
        start_date: the start date (datetime.date object) of the report period
        end_date: the end date (datetime.date object) of the report period
    Return:
        All previous WAS vuln data of the specified orgs needed for the I-Score
    """
    # Convert datetime.date objects to string
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    task_url = "iscore_was_vuln_prev"
    status_url = "iscore_was_vuln_prev/task/"
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    # If empty dataframe comes back, insert placeholder data
    if result_df.empty:
        result_df = pd.concat(
            [
                result_df,
                pd.DataFrame(
                    {
                        "organizations_uid": "test_org",
                        "parent_org_uid": "test_parent_org",
                        "was_total_vulns_prev": 0,
                        "date": datetime.date(1, 1, 1),
                    },
                    index=[0],
                ),
            ],
            ignore_index=True,
        )
    else:
        result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


def api_kev_list():
    """
    Query API for list of all KEVs.

    Return:
        List of all KEVs
    """
    # Endpoint info
    task_url = "kev_list"
    status_url = "kev_list/task/"
    data = None
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


# ---------- Misc. Score Related API Queries ----------
def api_xs_stakeholders():
    """
    Query API for list of all XS stakeholders.

    Return:
        List of all XS stakeholders
    """
    # Endpoint info
    task_url = "xs_stakeholders"
    status_url = "xs_stakeholders/task/"
    data = None
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


def api_s_stakeholders():
    """
    Query API for list of all S stakeholders.

    Return:
        List of all S stakeholders
    """
    # Endpoint info
    task_url = "s_stakeholders"
    status_url = "s_stakeholders/task/"
    data = None
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


def api_m_stakeholders():
    """
    Query API for list of all M stakeholders.

    Return:
        List of all M stakeholders
    """
    # Endpoint info
    task_url = "m_stakeholders"
    status_url = "m_stakeholders/task/"
    data = None
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


def api_l_stakeholders():
    """
    Query API for list of all L stakeholders.

    Return:
        List of all L stakeholders
    """
    # Endpoint info
    task_url = "l_stakeholders"
    status_url = "l_stakeholders/task/"
    data = None
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df


def api_xl_stakeholders():
    """
    Query API for list of all XL stakeholders.

    Return:
        List of all XL stakeholders
    """
    # Endpoint info
    task_url = "xl_stakeholders"
    status_url = "xl_stakeholders/task/"
    data = None
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    return result_df
