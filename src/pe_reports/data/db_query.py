#!/usr/bin/env python
"""Query the PE PostgreSQL database."""

# Standard Python Libraries
import datetime
from ipaddress import ip_address, ip_network
import json
import logging
import socket
import sys
import time

# Third-Party Libraries
import numpy as np
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
from psycopg2.extensions import AsIs
import psycopg2.extras as extras
import requests
from sshtunnel import SSHTunnelForwarder

from .config import config, staging_config

# Setup logging to central file
LOGGER = logging.getLogger(__name__)

CONN_PARAMS_DIC = config()
CONN_PARAMS_DIC_STAGING = staging_config()

API_DIC = staging_config(section="pe_api")
pe_api_url = API_DIC.get("pe_api_url")
pe_api_key = API_DIC.get("pe_api_key")


def task_api_call(task_url, check_url, data={}, retry_time=3):
    """
    Query tasked endpoint given task_url and check_url.

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
        LOGGER.info("Created task for " + task_url + " query, task_id: " + task_id)
        check_task_url += task_id
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            # check_task_resp = requests.get(check_task_url, headers=headers).json()
            check_task_resp = requests.get(check_task_url, headers=headers)
            #print(check_task_resp)
            check_task_resp = check_task_resp.json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged " + check_url + " status endpoint, status: " + task_status
            )
            time.sleep(retry_time)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
        print(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
        print(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
        print(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
        print(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)
        print(err)
    except Exception as err:
        print(err)
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


def get_demo_orgs(conn):
    """Query organizations table for orgs we report on."""
    try:
        cur = conn.cursor()
        sql = """SELECT * FROM organizations
        WHERE demo is True"""
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


def check_org_exists(org_code):
    """Check if org code is listed in the P&E database."""
    exists = False
    conn = connect()
    sql = """
    select * from organizations o
    where o.cyhy_db_name = %(org_code)s
    """

    df = pd.read_sql_query(sql, conn, params={"org_code": org_code})

    if not df.empty:
        exists = True

    return exists


def query_org_cidrs(org_uid):
    """Query all cidrs ordered by length."""
    conn = connect()
    sql = """SELECT tc.cidr_uid, tc.network, tc.organizations_uid, tc.insert_alert
            FROM cidrs tc
            WHERE current
            and organizations_uid = %(org_id)s
            """
    df = pd.read_sql(sql, conn, params={"org_id": org_uid})
    return df


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


def refresh_asset_counts_vw():
    """Refresh asset count materialized views."""
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


# The 'table' parameter is used in query_shodan, query_darkweb and
# query_darkweb_cves functions to call specific tables that relate to the
# function name.  The result of this implementation reduces the code base,
# the code reduction leads to an increase in efficiency by reusing the
# function by passing only a parameter to get the required information from
# the database.


# --- Issue 628 ---
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


def query_score_data(start, end, sql):
    """Query data necessary to generate organization scores."""
    conn = connect()
    try:
        df = pd.read_sql(sql, conn, params={"start": start, "end": end})
        conn.close()
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


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
    task_api_call(task_url, status_url, data, 3)
    # Process data and return
    LOGGER.info("Successfully inserted new IPs into ips table using execute_ips()")


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
        create_task_url = "sub_domains_table"
        check_task_url = "sub_domains_table/task/"

        data = json.dumps({"org_uid": "n/a", "page": page_num, "per_page": 50000})
        # Make API call
        result = task_api_call(create_task_url, check_task_url, data, 3)
        # Once task finishes, append result to total list
        total_data += result.get("data")
        total_num_pages = result.get("total_pages")
        LOGGER.info("Retrieved page: " + str(page_num) + " of " + str(total_num_pages))
        page_num += 1
    # Once all data has been retrieved, return overall tuple list
    # total_data = pd.DataFrame.from_dict(total_data)
    total_data = [tuple(dic.values()) for dic in total_data]
    LOGGER.info(
        "Total time to retrieve entire sub_domains table:", (time.time() - start_time)
    )
    # total_data["first_seen"] = pd.to_datetime(total_data["first_seen"]).dt.date
    # total_data["last_seen"] = pd.to_datetime(total_data["last_seen"]).dt.date
    return total_data


# --- Issue 561 ---
# Not used anywhere, however an API endpoint
# was created for this issue. It's currently
# in the api-extended branch.


# --- Issue 562, 627? ---
def query_domMasq_alerts(org_uid, start_date, end_date):
    """
    Query API to retrieve all domain_alerts data for the specified org_uid and date range.

    Args:
        org_uid: The uid of the organization to retrieve data for
        start_date: The start date of the query's date range
        end_date: The end date of the query's date range

    Return:
        All domain_alerts data for the specified org_uid and date range as a dataframe
    """
    if isinstance(start_date, datetime.datetime) or isinstance(
        start_date, datetime.date
    ):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.datetime) or isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    endpoint_url = pe_api_url + "domain_alerts_by_org_date"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"org_uid": org_uid, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
                "sub_domain_uid_id": "sub_domain_uid",
                "data_source_uid_id": "data_source_uid",
            },
            inplace=True,
        )
        result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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


# --- Issue 563, 626? ---
def query_domMasq(org_uid, start_date, end_date):
    """
    Query API to retrieve all domain_permutations data for the specified org_uid and date range.

    Args:
        org_uid: The uid of the organization to retrieve data for
        start_date: The start date of the query's date range
        end_date: The end date of the query's date range

    Return:
        All domain_permutations data for the specified org_uid and date range as a dataframe
    """
    if isinstance(start_date, datetime.datetime) or isinstance(
        start_date, datetime.date
    ):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.datetime) or isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    endpoint_url = pe_api_url + "domain_permu_by_org_date"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"org_uid": org_uid, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
                "organizations_uid_id": "organizations_uid",
                "data_source_uid_id": "data_source_uid",
                "sub_domain_uid_id": "sub_domain_uid",
            },
            inplace=True,
        )
        result_df["date_observed"] = pd.to_datetime(result_df["date_observed"]).dt.date
        result_df["date_active"] = pd.to_datetime(result_df["date_active"]).dt.date
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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


# --- Issue 564 ---
def insert_roots(org, domain_list):
    """
    Query API to insert list of new domains for the specified org.

    Args:
        org: Dataframe of the organization to associate the new domains with
        domain_list: The list of new domains to insert into the root_domains table
    """
    # Convert org dataframe input into dict
    org.drop(columns=["password"], inplace=True)
    org_dict = org.to_dict("records")[0]
    # Endpoint info
    endpoint_url = pe_api_url + "root_domains_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_dict": org_dict, "domain_list": domain_list})
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info(result)
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


# --- Issue 601 ---
def get_orgs_contacts():
    """
    Query API to retrieve all contact data for orgs where report_on is true.

    Return:
        All contact data for orgs where report_on is true as a list of tuples
    """
    # Endpoint info
    endpoint_url = pe_api_url + "orgs_report_on_contacts"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers).json()
        # Process data and return, convert to tuple list
        return [tuple(dic.values()) for dic in result]
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


# --- Issue 603 ---
def get_org_assets_count_past(org_uid, date):
    """
    Query API to retrieve all report_summary_stats data for the specified org_uid and date.

    Args:
        org_uid: The organizations_uid of the specified org
        date: The end date of the specified report period

    Return:
        All report_summary_stats data for the specified org_uid and date as a dataframe
    """
    if isinstance(date, datetime.datetime):
        date = date.strftime("%Y-%m-%d")
    # Endpoint info
    endpoint_url = pe_api_url + "past_asset_counts_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid, "date": date})
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
                "organizations_uid_id": "organizations_uid",
            },
            inplace=True,
        )
        result_df["start_date"] = pd.to_datetime(result_df["start_date"]).dt.date
        result_df["end_date"] = pd.to_datetime(result_df["end_date"]).dt.date
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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


# --- Issue 604 ---
def get_org_assets_count(org_uid):
    """
    Query API to retrieve attacksurface data for the specified org_uid.

    Args:
        org_uid: The organizations_uid of the specified org

    Return:
        attacksurface data for the specified org_uid as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "asset_counts_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        if result:
            # If there are results, return those
            result_df = pd.DataFrame(result[0], index=[0])
            result_df.rename(
                columns={
                    "organizations_uid": "org_uid",
                },
                inplace=True,
            )
            assets_dict = result_df.to_dict("records")[0]
            return assets_dict
        else:
            # If no results, return dummy asset dict
            return {
                "org_uid": org_uid,
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


# --- Issue 605 ---
def get_new_orgs():
    """
    Query API to retrieve all data for organizations where report_on is false.

    Return:
        All data for organizations where report_on is false as a dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "orgs_report_on_false"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = None
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
                "org_type_uid_id": "org_type_uid",
                "parent_org_uid_id": "parent_org_uid",
            },
            inplace=True,
        )
        result_df["date_first_reported"] = pd.to_datetime(
            result_df["date_first_reported"]
        ).dt.date
        # to_datetime conversion only supports +/- 584 years
        result_df.loc[
            result_df["cyhy_period_start"] == "9999-01-01", "cyhy_period_start"
        ] = "1950-01-01"
        result_df["cyhy_period_start"] = pd.to_datetime(
            result_df["cyhy_period_start"]
        ).dt.date
        result_df.loc[
            result_df["cyhy_period_start"] == datetime.date(1950, 1, 1),
            "cyhy_period_start",
        ] = datetime.date(9999, 1, 1)
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


# --- Issue 606 ---
def set_org_to_report_on(cyhy_db_id, premium: bool = False):
    """
    Query API to set the specified org's report_on and premium_report fields.

    Args:
        cyhy_db_id: The cyhy db name of the specified org
        premium: The boolean value you want to set the premium_report field to

    Return:
        The data of the org's whose report_on and premium_report fields were set.
    """
    # Endpoint info
    endpoint_url = pe_api_url + "orgs_set_report_on"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"cyhy_db_name": cyhy_db_id, "premium": premium})
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        if result[0].get("organizations_uid") == "NOT FOUND":
            return 0
        else:
            result_df = pd.DataFrame.from_dict(result)
            result_df.rename(
                columns={
                    "org_type_uid_id": "org_type_uid",
                    "parent_org_uid_id": "parent_org_uid",
                },
                inplace=True,
            )
            result_df["date_first_reported"] = pd.to_datetime(
                result_df["date_first_reported"]
            ).dt.date
            result_df["cyhy_period_start"] = pd.to_datetime(
                result_df["cyhy_period_start"]
            ).dt.date
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


# --- Issue 607 ---
def set_org_to_demo(cyhy_db_id, premium):
    """
    Query API to set the specified org's demo and premium_report fields.

    Args:
        cyhy_db_id: The cyhy db name of the specified org
        premium: The boolean value you want to set the premium_report field to

    Return:
        The data of the org's whose demo and premium_report fields were set.
    """
    # Endpoint info
    endpoint_url = pe_api_url + "orgs_set_demo"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"cyhy_db_name": cyhy_db_id, "premium": premium})
    try:
        # Call endpoint
        LOGGER.info("Sending demo org request")
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        if result[0].get("organizations_uid") == "NOT FOUND":
            return 0
        else:
            result_df = pd.DataFrame.from_dict(result)
            result_df.rename(
                columns={
                    "org_type_uid_id": "org_type_uid",
                    "parent_org_uid_id": "parent_org_uid",
                },
                inplace=True,
            )
            result_df["date_first_reported"] = pd.to_datetime(
                result_df["date_first_reported"]
            ).dt.date
            result_df["cyhy_period_start"] = pd.to_datetime(
                result_df["cyhy_period_start"]
            ).dt.date
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
        result = requests.post(endpoint_url, headers=headers, data=data).json()
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
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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
        result = requests.post(endpoint_url, headers=headers, data=data).json()
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
        result = requests.post(endpoint_url, headers=headers, data=data).json()
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
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_list = list({d["ip"] for d in result})
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
    """Query API to set from_cidr to True for any IPs that have an origin_cidr."""
    # Endpoint info
    task_url = "ips_update_from_cidr"
    status_url = "ips_update_from_cidr/task/"
    data = None
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    LOGGER.info(result)


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
        result = requests.post(endpoint_url, headers=headers, data=data).json()
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
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={
                "organizations_uid_id": "organizations_uid",
                "data_source_uid_id": "data_source_uid",
            },
            inplace=True,
        )
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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


# --- Issue 623 ---
def query_creds_view(org_uid, start_date, end_date):
    """
    Query API to retrieve vw_breachcomp data for an org and date range.

    Args:
        org_uid: uid of the specified organization
        start_date: start date of report period
        end_date: end date of report period

    Return:
        vw_breachcomp data for the specified org  and date range as a dataframe
    """
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    endpoint_url = pe_api_url + "breachcomp_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {
            "org_uid": org_uid,
            "start_date": start_date,
            "end_date": end_date,
        }
    )
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df["breach_date"] = pd.to_datetime(result_df["breach_date"]).dt.date
        # result_df["added_date"] = pd.to_datetime(result_df["added_date"]).dt.date
        # result_df["modified_date"] = pd.to_datetime(result_df["modified_date"]).dt.date
        result_df["added_date"] = pd.to_datetime(result_df["added_date"])
        result_df["modified_date"] = pd.to_datetime(result_df["modified_date"])
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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


# --- Issue 624 ---
def query_credsbyday_view(org_uid, start_date, end_date):
    """
    Query API to retrieve vw_breachcomp_credsbydate data for an org and date range.

    Args:
        org_uid: uid of the specified organization
        start_date: start date of report period
        end_date: end date of report period

    Return:
        vw_breachcomp_credsbydate data for the specified org  and date range as a dataframe
    """
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    endpoint_url = pe_api_url + "credsbydate_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {
            "org_uid": org_uid,
            "start_date": start_date,
            "end_date": end_date,
        }
    )
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df["mod_date"] = pd.to_datetime(result_df["mod_date"]).dt.date
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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


# --- Issue 625 ---
def query_breachdetails_view(org_uid, start_date, end_date):
    """
    Query API to retrieve vw_breachcomp_breachdetails data for an org and date range.

    Args:
        org_uid: uid of the specified organization
        start_date: start date of report period
        end_date: end date of report period

    Return:
        vw_breachcomp_breachdetails data for the specified org  and date range as a dataframe
    """
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    endpoint_url = pe_api_url + "breachdetails_by_org"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {
            "org_uid": org_uid,
            "start_date": start_date,
            "end_date": end_date,
        }
    )
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df["mod_date"] = pd.to_datetime(result_df["mod_date"]).dt.date
        result_df["breach_date"] = pd.to_datetime(result_df["breach_date"]).dt.date
        result_df.rename(
            columns={"mod_date": "modified_date"},
            inplace=True,
        )
        # Return truly empty dataframe if no results
        if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
            result_df.drop(result_df.index, inplace=True)
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


# --- Issue 629 ---
def query_darkweb(org_uid, start_date, end_date, table):
    """
    Query API to retrieve darkweb data for an organization.

    Args:
        org_uid: uid of the specified organization
        start_date: start date of the report period
        end_date: end date of the report period
        table: darkweb related table to query

    Return:
        Darkweb data belonging to the specified org as a dataframe
    """
    if isinstance(start_date, datetime.date):
        start_date = start_date.strftime("%Y-%m-%d")
    if isinstance(end_date, datetime.date):
        end_date = end_date.strftime("%Y-%m-%d")
    # Endpoint info
    endpoint_url = pe_api_url + "darkweb_data"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Check table name is valid
    if table in [
        "mentions",
        "alerts",
        "vw_darkweb_mentionsbydate",
        "vw_darkweb_inviteonlymarkets",
        "vw_darkweb_socmedia_mostactposts",
        "vw_darkweb_mostactposts",
        "vw_darkweb_execalerts",
        "vw_darkweb_assetalerts",
        "vw_darkweb_threatactors",
        "vw_darkweb_potentialthreats",
        "vw_darkweb_sites",
    ]:
        data = json.dumps(
            {
                "org_uid": org_uid,
                "start_date": start_date,
                "end_date": end_date,
                "table": table,
            }
        )
        try:
            # Call endpoint
            result = requests.post(endpoint_url, headers=headers, data=data).json()
            # Process data and return
            result_df = pd.DataFrame.from_dict(result)
            result_df.rename(
                columns={
                    "organizations_uid_id": "organizations_uid",
                    "data_source_uid_id": "data_source_uid",
                    "count": "Count",
                    "creator": "Creator",
                    "grade": "Grade",
                    "events": "Events",
                    "title": "Title",
                    "comments_count": "Comments Count",
                    "site": "Site",
                    "threats": "Threats",
                },
                inplace=True,
            )
            if "date" in result_df.columns:
                result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
            # Return truly empty dataframe if no results
            if result_df[result_df.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
                result_df.drop(result_df.index, inplace=True)
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
    else:
        LOGGER.error("query_darkweb() error, invalid table")


# --- Issue 630 ---
def query_darkweb_cves(table):
    """
    Query API to retrieve the entire top_cves table.

    Return:
        top_cve table as a dataframe
    """
    # Endpoint info
    task_url = "darkweb_cves"
    status_url = "darkweb_cves/task/"
    # Make API call
    result = task_api_call(task_url, status_url)
    # Process data and return
    result_df = pd.DataFrame.from_dict(result)
    result_df.rename(
        columns={
            "data_source_uid_id": "data_source_uid",
        },
        inplace=True,
    )
    result_df["date"] = pd.to_datetime(result_df["date"]).dt.date
    return result_df


# --- Issue 632 ---
def execute_scorecard(summary_dict):
    """
    Insert a record for an organization into the report_summary_stats table.

    On org_uid/star_date conflict, update the old record with the new data

    Args:
        summary_dict: Dictionary of column names and values to be inserted
    """
    input_dict = summary_dict.copy()
    input_dict["start_date"] = input_dict["start_date"].strftime("%Y-%m-%d")
    input_dict["end_date"] = input_dict["end_date"].strftime("%Y-%m-%d")
    input_dict["insecure_port_count"] = int(input_dict["insecure_port_count"])
    input_dict["verified_vuln_count"] = int(input_dict["verified_vuln_count"])
    if "dns" in input_dict:
        input_dict.pop("dns")
    if "circles_df" in input_dict:
        input_dict.pop("circles_df")
    if "org_name" in input_dict:
        input_dict.pop("org_name")
    # Fill in any empty fields in dictionary
    for key in input_dict.keys():
        if ("count" in key or key == "num_ports") and input_dict.get(key) is None:
            input_dict.update({key: 0})
    # Endpoint info
    endpoint_url = pe_api_url + "rss_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(input_dict)
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


# --- Issue 633 (paginated) ---
def query_subs(org_uid):
    """
    Query API to retrieve all subdomains for an organization.

    Args:
        org_uid: uid of the specified organization

    Return:
        All the subdomains belonging to the specified org as a dataframe
    """
    start_time = time.time()
    total_num_pages = 1
    page_num = 1
    total_data = []
    # Retrieve data for each page
    while page_num <= total_num_pages:
        # Endpoint info
        create_task_url = "sub_domains_by_org"
        check_task_url = "sub_domains_by_org/task/"

        data = json.dumps({"org_uid": org_uid, "page": page_num, "per_page": 50000})
        # Make API call
        result = task_api_call(create_task_url, check_task_url, data, 3)
        # Once task finishes, append result to total list
        total_data += result.get("data")
        total_num_pages = result.get("total_pages")
        LOGGER.info("Retrieved page: " + str(page_num) + " of " + str(total_num_pages))
        page_num += 1
    # Once all data has been retrieved, return overall dataframe
    total_data = pd.DataFrame.from_dict(total_data)
    LOGGER.info(
        "Total time to retrieve all subdomains for this org: "
        + str(time.time() - start_time)
    )
    # Process data and return
    total_data.rename(
        columns={
            "root_domain_uid_id": "root_domain_uid",
            "data_source_uid_id": "data_source_uid",
            "dns_record_uid_id": "dns_record_uid",
        },
        inplace=True,
    )
    total_data["first_seen"] = pd.to_datetime(total_data["first_seen"]).dt.date
    total_data["last_seen"] = pd.to_datetime(total_data["last_seen"]).dt.date
    # Return truly empty dataframe if no results
    if total_data[total_data.columns].isnull().apply(lambda x: all(x), axis=1)[0]:
        total_data.drop(total_data.index, inplace=True)
    return total_data


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
    prev_end_date = prev_end_date.strftime("%Y-%m-%d")
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
        rss_prev_period_result = requests.post(
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
        rss_prev_period_result = rss_prev_period_result[0]
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
    # LOGGER.info("pescore_hist_domain_alert api endpoint was used!")
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
    # LOGGER.info("pescore_hist_darkweb_alert api endpoint was used!")
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
    # LOGGER.info("pescore_hist_darkweb_ment api endpoint was used!")
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
    # LOGGER.info("pescore_hist_cred api endpoint was used!")
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
    # LOGGER.info("pescore_base_metrics api endpoint was used!")
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
    # LOGGER.info("get_new_cves_list api endpoint was used!")
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
    return result


# v ===== OLD TSQL VERSIONS OF FUNCTIONS ===== v
# --- 559 OLD TSQL ---
def execute_ips_tsql(conn, dataframe):
    """Insert the ips into the ips table in the database and link them to the associated cidr."""
    for i, row in dataframe.iterrows():
        try:
            cur = conn.cursor()
            sql = """
            INSERT INTO ips(ip_hash, ip, origin_cidr) VALUES (%s, %s, %s)
            ON CONFLICT (ip)
                    DO
                    UPDATE SET origin_cidr = UUID(EXCLUDED.origin_cidr); """
            cur.execute(sql, (row["ip_hash"], row["ip"], row["origin_cidr"]))
            conn.commit()
        except (Exception, psycopg2.DatabaseError) as err:
            show_psycopg2_exception(err)
            cur.close()
            continue
    print("IPs inserted using execute_values() successfully..")


# --- 560 OLD TSQL ---
def query_all_subs_tsql(conn):
    """Query sub domains table."""
    try:
        cur = conn.cursor()
        sql = """SELECT * FROM sub_domains"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# --- 561 OLD TSQL ---
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
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# --- 562 OLD TSQL ---
def query_domMasq_alerts_tsql(org_uid, start_date, end_date):
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


# --- 563 OLD TSQL ---
def query_domMasq_tsql(org_uid, start_date, end_date):
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


# --- 564 OLD TSQL ---
def insert_roots_tsql(org, domain_list):
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


# --- 601 OLD TSQL ---
def get_orgs_contacts_tsql(conn):
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


# --- 603 OLD TSQL ---
def get_org_assets_count_past_tsql(org_uid, date):
    """Get asset counts for an organization."""
    conn = connect()
    sql = """select * from report_summary_stats rss
                where organizations_uid = %(org_id)s
                and end_date = %(date)s;"""
    df = pd.read_sql(sql, conn, params={"org_id": org_uid, "date": date})
    conn.close()
    return df


# --- 604 OLD TSQL ---
def get_org_assets_count_tsql(uid):
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
    except Exception:
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


# --- 605 OLD TSQL ---
def get_new_orgs_tsql():
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


# --- 606 OLD TSQL ---
def set_org_to_report_on_tsql(cyhy_db_id, premium: bool = False):
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


# --- 607 OLD TSQL ---
def set_org_to_demo_tsql(cyhy_db_id, premium):
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


# --- 608 OLD TSQL ---
def query_cyhy_assets_tsql(cyhy_db_id, conn):
    """Query cyhy assets."""
    sql = """
    SELECT *
    FROM cyhy_db_assets ca
    where ca.org_id = %(org_id)s
    and currently_in_cyhy;
    """

    df = pd.read_sql_query(sql, conn, params={"org_id": cyhy_db_id})

    return df


# --- 610 OLD TSQL ---
def get_cidrs_and_ips_tsql(org_uid):
    """Query all cidrs and ips for an organization."""
    params = config()
    conn = psycopg2.connect(**params)
    cur = conn.cursor()
    sql = """SELECT network from cidrs where
        organizations_uid = %s
        and current;"""
    cur.execute(sql, [org_uid])
    cidrs = cur.fetchall()
    sql = """
    SELECT i.ip
    FROM ips i
    join ips_subs ip_s on ip_s.ip_hash = i.ip_hash
    join sub_domains sd on sd.sub_domain_uid = ip_s.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    WHERE rd.organizations_uid = %s
    AND i.origin_cidr is null
    and i.current
    and sd.current;
    """
    cur.execute(sql, [org_uid])
    ips = cur.fetchall()
    conn.close()
    cidrs_ips = cidrs + ips
    cidrs_ips = [x[0] for x in cidrs_ips]
    cidrs_ips = validateIP(cidrs_ips)
    LOGGER.info(cidrs_ips)
    return cidrs_ips


# --- 611 OLD TSQL ---
# No old TSQL function?


# --- 612 OLD TSQL ---
def query_extra_ips_tsql(org_uid):
    """Get IP data."""
    conn = connect()

    sql2 = """select i.ip_hash, i.ip
    from ips i
    join ips_subs is2 ON i.ip_hash = is2.ip_hash
    join sub_domains sd on sd.sub_domain_uid = is2.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    JOIN organizations o on o.organizations_uid = rd.organizations_uid
    where o.organizations_uid = %(org_uid)s and i.origin_cidr is null
    and i.current and sd.current;"""
    df = pd.read_sql(sql2, conn, params={"org_uid": org_uid})
    ips = list(set(list(df["ip"].values)))

    conn.close()

    return ips


# --- 616 OLD TSQL ---
def set_from_cidr_tsql():
    """Set the from_cidr flag in the IPs table."""
    conn = connect()
    sql = """
        update ips
        set from_cidr = True
        where origin_cidr is not null;
    """
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()


# --- 618 OLD TSQL ---
def query_cidrs_by_org_tsql(org_uid):
    """Query all CIDRs for a specific org."""
    conn = connect()
    sql = """select *
            from cidrs c
            where c.organizations_uid  = %(org_uid)s and c.current;
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


# --- 619 OLD TSQL ---
def query_ports_protocols_tsql(org_uid):
    """Query distinct ports and protocols by org."""
    conn = connect()
    sql = """select distinct sa.port,sa.protocol
            from shodan_assets sa
            where sa.organizations_uid  = %(org_uid)s;
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


# --- 620 OLD TSQL ---
def query_software_tsql(org_uid):
    """Query distinct software by org."""
    conn = connect()
    sql = """select distinct sa.product
            from shodan_assets sa
            where sa.organizations_uid  = %(org_uid)s
            and sa.product notnull;
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


# --- 621 OLD TSQL ---
def query_foreign_IPs_tsql(org_uid):
    """Query distinct software by org."""
    conn = connect()
    sql = """select * from
            shodan_assets sa
            where (sa.country_code != 'US' and sa.country_code notnull)
            and sa.organizations_uid  = %(org_uid)s;
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


# --- 622 OLD TSQL ---
def query_roots_tsql(org_uid):
    """Query all ips that link to a cidr related to a specific org."""
    conn = connect()
    sql = """SELECT r.root_domain_uid, r.root_domain FROM root_domains r
            where r.organizations_uid = %(org_uid)s
            and r.enumerate_subs = True
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


# --- 623 OLD TSQL ---
def query_creds_view_tsql(org_uid, start_date, end_date):
    """Query credentials view ."""
    conn = connect()
    try:
        # used to pull data from mat_vw_breachcomp,
        # but that's broken now -> use vw_breachcomp
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
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# --- 624 OLD TSQL ---
def query_credsbyday_view_tsql(org_uid, start_date, end_date):
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


# --- 625 OLD TSQL ---
def query_breachdetails_view_tsql(org_uid, start_date, end_date):
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


# --- 629 OLD TSQL ---
def query_darkweb_tsql(org_uid, start_date, end_date, table):
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


# --- 630 OLD TSQL ---
def query_darkweb_cves_tsql(table):
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


# --- 632 OLD TSQL ---
def execute_scorecard_tsql(summary_dict):
    """Save summary statistics for an organization to the database."""
    try:
        conn = connect()
        cur = conn.cursor()
        sql = """
        INSERT INTO report_summary_stats(
            organizations_uid, start_date, end_date, ip_count, root_count, sub_count, ports_count,
            creds_count, breach_count, cred_password_count, domain_alert_count,
            suspected_domain_count, insecure_port_count, verified_vuln_count,
            suspected_vuln_count, suspected_vuln_addrs_count, threat_actor_count, dark_web_alerts_count,
            dark_web_mentions_count, dark_web_executive_alerts_count, dark_web_asset_alerts_count,
            pe_number_score, pe_letter_grade, cidr_count, port_protocol_count, software_count, foreign_ips_count
        )
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(organizations_uid, start_date)
        DO
        UPDATE SET
            ip_count = EXCLUDED.ip_count,
            root_count = EXCLUDED.root_count,
            sub_count = EXCLUDED.sub_count,
            ports_count = EXCLUDED.ports_count,
            creds_count = EXCLUDED.creds_count,
            breach_count = EXCLUDED.breach_count,
            cred_password_count = EXCLUDED.cred_password_count,
            domain_alert_count = EXCLUDED.domain_alert_count,
            suspected_domain_count = EXCLUDED.suspected_domain_count,
            insecure_port_count = EXCLUDED.insecure_port_count,
            verified_vuln_count = EXCLUDED.verified_vuln_count,
            suspected_vuln_count = EXCLUDED.suspected_vuln_count,
            suspected_vuln_addrs_count = EXCLUDED.suspected_vuln_addrs_count,
            threat_actor_count = EXCLUDED.threat_actor_count,
            dark_web_alerts_count = EXCLUDED.dark_web_alerts_count,
            dark_web_mentions_count = EXCLUDED.dark_web_mentions_count,
            dark_web_executive_alerts_count = EXCLUDED.dark_web_executive_alerts_count,
            dark_web_asset_alerts_count = EXCLUDED.dark_web_asset_alerts_count,
            pe_number_score = EXCLUDED.pe_number_score,
            pe_letter_grade = EXCLUDED.pe_letter_grade,
            cidr_count = EXCLUDED.cidr_count,
            port_protocol_count = EXCLUDED.port_protocol_count,
            software_count = EXCLUDED.software_count,
            foreign_ips_count = EXCLUDED.foreign_ips_count;
        """
        cur.execute(
            sql,
            (
                summary_dict["organizations_uid"],
                summary_dict["start_date"],
                summary_dict["end_date"],
                AsIs(summary_dict["ip_count"]),
                AsIs(summary_dict["root_count"]),
                AsIs(summary_dict["sub_count"]),
                AsIs(summary_dict["num_ports"]),
                AsIs(summary_dict["creds_count"]),
                AsIs(summary_dict["breach_count"]),
                AsIs(summary_dict["cred_password_count"]),
                AsIs(summary_dict["domain_alert_count"]),
                AsIs(summary_dict["suspected_domain_count"]),
                AsIs(summary_dict["insecure_port_count"]),
                AsIs(summary_dict["verified_vuln_count"]),
                AsIs(summary_dict["suspected_vuln_count"]),
                AsIs(summary_dict["suspected_vuln_addrs_count"]),
                AsIs(summary_dict["threat_actor_count"]),
                AsIs(summary_dict["dark_web_alerts_count"]),
                AsIs(summary_dict["dark_web_mentions_count"]),
                AsIs(summary_dict["dark_web_executive_alerts_count"]),
                AsIs(summary_dict["dark_web_asset_alerts_count"]),
                summary_dict["pe_number_score"],
                summary_dict["pe_letter_grade"],
                AsIs(summary_dict["cidr_count"]),
                AsIs(summary_dict["port_protocol_count"]),
                AsIs(summary_dict["software_count"]),
                AsIs(summary_dict["foreign_ips_count"]),
            ),
        )
        conn.commit()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cur.close()


# --- 633 OLD TSQL ---
def query_subs_tsql(org_uid):
    """Query all subs for an organization."""
    print("query_subs() tsql used!")
    conn = connect()
    sql = """SELECT sd.* FROM sub_domains sd
            JOIN root_domains rd on rd.root_domain_uid = sd.root_domain_uid
            where rd.organizations_uid = %(org_uid)s
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


# --- 634 OLD TSQL ---
def query_previous_period_tsql(org_uid, previous_end_date):
    """Get summary statistics for the previous period."""
    conn = connect()
    cur = conn.cursor()
    sql = """select
                sum.ip_count, sum.root_count, sum.sub_count, cred_password_count,
                sum.suspected_vuln_addrs_count, sum.suspected_vuln_count, sum.insecure_port_count,
                sum.threat_actor_count

            from report_summary_stats sum
            where sum.organizations_uid = %s and sum.end_date = %s"""
    cur.execute(sql, [org_uid, previous_end_date])
    source = cur.fetchone()
    cur.close()
    conn.close()
    if source:
        assets_dict = {
            "last_ip_count": source[0],
            "last_root_domain_count": source[1],
            "last_sub_domain_count": source[2],
            "last_cred_password_count": source[3],
            "last_sus_vuln_addrs_count": source[4],
            "last_suspected_vuln_count": source[5],
            "last_insecure_port_count": source[6],
            "last_actor_activity_count": source[7],
        }
    else:
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


# --- 636 OLD TSQL ---
def get_new_cves_list_tsql(start, end):
    """
    Get the list of all new CVEs for this report period that are not in the database yet.

    Args:
        start: The start date of the specified report period
        end: The end date of the specified report period

    Returns:
        Dataframe containing all the new CVE names that aren't in the PE database yet
    """
    conn = connect()
    sql = "SELECT * FROM pes_check_new_cve(%(start)s, %(end)s);"
    try:
        df = pd.read_sql(sql, conn, params={"start": start, "end": end})
        conn.close()
        return df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# --- 637 OLD TSQL ---
def upsert_new_cves_tsql(new_cves):
    """
    Upsert dataframe of new CVE data into the cve_info table in the database.

    Required dataframe columns:
        cve_name, cvss_2_0, cvss_2_0_severity, cvss_2_0_vector,
        cvss_3_0, cvss_3_0_severity, cvss_3_0_vector, dve_score

    Args:
        new_cves: Dataframe containing the new CVEs and their CVSS2.0/3.1/DVE data
    """
    try:
        # Drop duplicates in dataframe
        new_cves = new_cves.drop_duplicates()

        # Execute insert query
        conn = connect()
        tpls = [tuple(x) for x in new_cves.to_numpy()]
        cols = ",".join(list(new_cves.columns))
        table = "cve_info"
        sql = """INSERT INTO {}({}) VALUES %s
        ON CONFLICT (cve_name)
        DO UPDATE SET
            cve_name=EXCLUDED.cve_name,
            cvss_2_0=EXCLUDED.cvss_2_0,
            cvss_2_0_severity=EXCLUDED.cvss_2_0_severity,
            cvss_2_0_vector=EXCLUDED.cvss_2_0_vector,
            cvss_3_0=EXCLUDED.cvss_3_0,
            cvss_3_0_severity=EXCLUDED.cvss_3_0_severity,
            cvss_3_0_vector=EXCLUDED.cvss_3_0_vector,
            dve_score=EXCLUDED.dve_score;
        """
        cursor = conn.cursor()
        extras.execute_values(
            cursor,
            sql.format(table, cols),
            tpls,
        )
        conn.commit()
        LOGGER.info(
            "%s new CVEs successfully upserted into cve_info table...", len(new_cves)
        )
    except (Exception, psycopg2.DatabaseError) as err:
        # Show error and close connection if failed
        LOGGER.error("There was a problem with your database query %s", err)
        cursor.close()
    finally:
        if conn is not None:
            close(conn)
