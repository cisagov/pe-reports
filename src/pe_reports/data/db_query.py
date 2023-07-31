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

def task_api_call(task_url, check_url, data={},retry_time=3):
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
        create_task_result = requests.post(create_task_url, headers=headers , data=data).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for query, task_id: ", task_id
        )
        check_task_url += task_id
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged xl_stakeholders status endpoint, status:", task_status
            )
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


def query_cyhy_assets(cyhy_db_id, conn):
    """Query cyhy assets."""
    sql = """
    SELECT *
    FROM cyhy_db_assets ca
    where ca.org_id = %(org_id)s
    and currently_in_cyhy;
    """

    df = pd.read_sql_query(sql, conn, params={"org_id": cyhy_db_id})

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


def get_cidrs_and_ips(org_uid):
    """Query all cidrs and ips for an organization."""
    params = config()
    conn = psycopg2.connect(**params)
    cur = conn.cursor()
    sql = """SELECT network from cidrs where
        organizations_uid = %s;"""
    cur.execute(sql, [org_uid])
    cidrs = cur.fetchall()
    sql = """
    SELECT i.ip
    FROM ips i
    join ips_subs ip_s on ip_s.ip_hash = i.ip_hash
    join sub_domains sd on sd.sub_domain_uid = ip_s.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    WHERE rd.organizations_uid = %s
    AND i.origin_cidr is null;
    """
    cur.execute(sql, [org_uid])
    ips = cur.fetchall()
    conn.close()
    cidrs_ips = cidrs + ips
    cidrs_ips = [x[0] for x in cidrs_ips]
    cidrs_ips = validateIP(cidrs_ips)
    LOGGER.info(cidrs_ips)
    return cidrs_ips


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


def query_ips(org_uid):
    """Get IP data."""
    conn = connect()
    sql1 = """SELECT i.ip_hash, i.ip, ct.network FROM ips i
    JOIN cidrs ct on ct.cidr_uid = i.origin_cidr
    JOIN organizations o on o.organizations_uid = ct.organizations_uid
    where o.organizations_uid = %(org_uid)s
    and i.origin_cidr is not null;"""
    df1 = pd.read_sql(sql1, conn, params={"org_uid": org_uid})
    ips1 = list(df1["ip"].values)

    sql2 = """select i.ip_hash, i.ip
    from ips i
    join ips_subs is2 ON i.ip_hash = is2.ip_hash
    join sub_domains sd on sd.sub_domain_uid = is2.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    JOIN organizations o on o.organizations_uid = rd.organizations_uid
    where o.organizations_uid = %(org_uid)s;"""
    df2 = pd.read_sql(sql2, conn, params={"org_uid": org_uid})
    ips2 = list(df2["ip"].values)

    in_first = set(ips1)
    in_second = set(ips2)

    in_second_but_not_in_first = in_second - in_first

    ips = ips1 + list(in_second_but_not_in_first)
    conn.close()

    return ips


def query_extra_ips(org_uid):
    """Get IP data."""
    conn = connect()

    sql2 = """select i.ip_hash, i.ip
    from ips i
    join ips_subs is2 ON i.ip_hash = is2.ip_hash
    join sub_domains sd on sd.sub_domain_uid = is2.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    JOIN organizations o on o.organizations_uid = rd.organizations_uid
    where o.organizations_uid = %(org_uid)s and i.origin_cidr is null;"""
    df = pd.read_sql(sql2, conn, params={"org_uid": org_uid})
    ips = list(set(list(df["ip"].values)))

    conn.close()

    return ips


def set_from_cidr():
    conn = connect()
    sql = """
        update ips
        set from_cidr = True 
        where origin_cidr is not null;
    """
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()


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


def query_cidrs_by_org(org_uid):
    """Query all CIDRs for a specific org."""
    conn = connect()
    sql = """select *
            from cidrs c
            where c.organizations_uid  = %(org_uid)s and c.current;
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


def query_ports_protocols(org_uid):
    """Query distinct ports and protocols by org."""
    conn = connect()
    sql = """select distinct sa.port,sa.protocol 
            from shodan_assets sa 
            where sa.organizations_uid  = %(org_uid)s;
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


def query_software(org_uid):
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


def query_foreign_IPs(org_uid):
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


def query_roots(org_uid):
    """Query all ips that link to a cidr related to a specific org."""
    conn = connect()
    sql = """SELECT r.root_domain_uid, r.root_domain FROM root_domains r
            where r.organizations_uid = %(org_uid)s
            and r.enumerate_subs = True
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


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

#--- Issue 629 ---
#This funciton either references the "mentions" table or the "alerts" table
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

#-- Issue 630 ---
#This Function references the "top_cves" table
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


def query_subs(org_uid):
    """Query all subs for an organization."""
    conn = connect()
    sql = """SELECT sd.* FROM sub_domains sd
            JOIN root_domains rd on rd.root_domain_uid = sd.root_domain_uid
            where rd.organizations_uid = %(org_uid)s
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    conn.close()
    return df


# --- Issue 559 ---
def execute_ips(new_ips):
    """
    Query API to insert new IP record into ips table.
    On ip conflict, update the old record with the new data

    Args:
        new_ips: Dataframe containing the new IPs and their ip_hash/ip/origin_cidr data
    """
    # Endpoint info
    create_task_url = pe_api_url + "ips_insert"
    check_task_url = pe_api_url + "ips_insert/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Convert dataframe to list of dictionaries
    new_ips = new_ips[["ip_hash", "ip", "origin_cidr"]]
    new_ips = new_ips.to_dict("records")
    data = json.dumps({"new_ips": new_ips})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info("Created task for ips_insert endpoint query, task_id: ", task_id)
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged ips_insert status endpoint, status:", task_status)
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
        LOGGER.info("Successfully inserted new IPs into ips table using execute_ips()")
    else:
        raise Exception("ips_insert query task failed, details: ", check_task_resp)


# --- Issue 632 ---
def execute_scorecard(summary_dict):
    """
    Insert a record for an organization into the report_summary_stats table.
    On org_uid/star_date conflict, update the old record with the new data

    Args:
        summary_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
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


def get_new_cves_list(start, end):
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


# --- Issue 637 ---
def upsert_new_cves(new_cves):
    """
    Query API to upsert new CVE records into cve_info.
    On cve_name conflict, update the old record with the new data

    Args:
        new_cves: Dataframe containing the new CVEs and their CVSS2.0/3.1/DVE data

    Return:
        Status on if the records were inserted successfully
    """
    # Endpoint info
    create_task_url = pe_api_url + "cve_info_insert"
    check_task_url = pe_api_url + "cve_info_insert/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Convert dataframe to list of dictionaries
    new_cves = new_cves.to_dict("records")
    data = json.dumps({"new_cves": new_cves})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for cve_info_insert endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged cve_info_insert status endpoint, status:", task_status
            )
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
        LOGGER.info(
            "Successfully inserted new CVEs into cve_info table using upsert_new_cves()"
        )
    else:
        raise Exception("cve_info_insert query task failed, details: ", check_task_resp)


# v ---------- D-Score API Queries ---------- v
def api_dscore_vs_cert(org_list):
    """
    Query API for all VS certificate data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS certificate data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_vs_cert"
    check_task_url = pe_api_url + "dscore_vs_cert/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for dscore_vs_cert endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged dscore_vs_cert status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("dscore_vs_cert query task failed, details: ", check_task_resp)


def api_dscore_vs_mail(org_list):
    """
    Query API for all VS mail data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS mail data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_vs_mail"
    check_task_url = pe_api_url + "dscore_vs_mail/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for dscore_vs_mail endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged dscore_vs_mail status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("dscore_vs_mail query task failed, details: ", check_task_resp)


def api_dscore_pe_ip(org_list):
    """
    Query API for all PE IP data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All PE IP data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_pe_ip"
    check_task_url = pe_api_url + "dscore_pe_ip/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info("Created task for dscore_pe_ip endpoint query, task_id: ", task_id)
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged dscore_pe_ip status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("dscore_pe_ip query task failed, details: ", check_task_resp)


def api_dscore_pe_domain(org_list):
    """
    Query API for all PE domain data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All PE domain data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_pe_domain"
    check_task_url = pe_api_url + "dscore_pe_domain/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for dscore_pe_domain endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged dscore_pe_domain status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception(
            "dscore_pe_domain query task failed, details: ", check_task_resp
        )


def api_dscore_was_webapp(org_list):
    """
    Query API for all WAS webapp data needed for D-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All WAS webapp data of the specified orgs needed for the D-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "dscore_was_webapp"
    check_task_url = pe_api_url + "dscore_was_webapp/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for dscore_was_webapp endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged dscore_was_webapp status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception(
            "dscore_was_webapp query task failed, details: ", check_task_resp
        )


def api_fceb_status(org_list):
    """
    Query API for the FCEB status of a list of organizations.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        The FCEB status of the specified list of organizations
    """
    # Endpoint info
    create_task_url = pe_api_url + "fceb_status"
    check_task_url = pe_api_url + "fceb_status/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info("Created task for fceb_status endpoint query, task_id: ", task_id)
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged fceb_status status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("fceb_status query task failed, details: ", check_task_resp)


# v ---------- I-Score API Queries ---------- v
def api_iscore_vs_vuln(org_list):
    """
    Query API for all VS vuln data needed for I-Score calculation.

    Args:
        org_list: The specified list of organizations to retrieve data for
    Return:
        All VS vuln data of the specified orgs needed for the I-Score
    """
    # Endpoint info
    create_task_url = pe_api_url + "iscore_vs_vuln"
    check_task_url = pe_api_url + "iscore_vs_vuln/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"specified_orgs": org_list})
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_vs_vuln endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged iscore_vs_vuln status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
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
    else:
        raise Exception("iscore_vs_vuln query task failed, details: ", check_task_resp)


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
    create_task_url = pe_api_url + "iscore_vs_vuln_prev"
    check_task_url = pe_api_url + "iscore_vs_vuln_prev/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_vs_vuln_prev endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_vs_vuln_prev status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
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
    else:
        raise Exception(
            "iscore_vs_vuln_prev query task failed, details: ", check_task_resp
        )


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
    create_task_url = pe_api_url + "iscore_pe_vuln"
    check_task_url = pe_api_url + "iscore_pe_vuln/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_vuln endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged iscore_pe_vuln status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
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
    else:
        raise Exception("iscore_pe_vuln query task failed, details: ", check_task_resp)


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
    create_task_url = pe_api_url + "iscore_pe_cred"
    check_task_url = pe_api_url + "iscore_pe_cred/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_cred endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged iscore_pe_cred status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
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
    else:
        raise Exception("iscore_pe_cred query task failed, details: ", check_task_resp)


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
    create_task_url = pe_api_url + "iscore_pe_breach"
    check_task_url = pe_api_url + "iscore_pe_breach/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_breach endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_pe_breach status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
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
    else:
        raise Exception(
            "iscore_pe_breach query task failed, details: ", check_task_resp
        )


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
    create_task_url = pe_api_url + "iscore_pe_darkweb"
    check_task_url = pe_api_url + "iscore_pe_darkweb/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_darkweb endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_pe_darkweb status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
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
    else:
        raise Exception(
            "iscore_pe_darkweb query task failed, details: ", check_task_resp
        )


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
    create_task_url = pe_api_url + "iscore_pe_protocol"
    check_task_url = pe_api_url + "iscore_pe_protocol/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_pe_protocol endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_pe_protocol status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
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
    else:
        raise Exception(
            "iscore_pe_protocol query task failed, details: ", check_task_resp
        )


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
    create_task_url = pe_api_url + "iscore_was_vuln"
    check_task_url = pe_api_url + "iscore_was_vuln/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_was_vuln endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_was_vuln status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
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
    else:
        raise Exception("iscore_was_vuln query task failed, details: ", check_task_resp)


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
    create_task_url = pe_api_url + "iscore_was_vuln_prev"
    check_task_url = pe_api_url + "iscore_was_vuln_prev/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"specified_orgs": org_list, "start_date": start_date, "end_date": end_date}
    )
    try:
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for iscore_was_vuln_prev endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged iscore_was_vuln_prev status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
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
    else:
        raise Exception(
            "iscore_was_vuln_prev query task failed, details: ", check_task_resp
        )


def api_kev_list():
    """
    Query API for list of all KEVs.

    Return:
        List of all KEVs
    """
    # Endpoint info
    create_task_url = pe_api_url + "kev_list"
    check_task_url = pe_api_url + "kev_list/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info("Created task for kev_list endpoint query, task_id: ", task_id)
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged kev_list status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("kev_list query task failed, details: ", check_task_resp)


# ---------- Misc. Score Related API Queries ----------
def api_xs_stakeholders():
    """
    Query API for list of all XS stakeholders.

    Return:
        List of all XS stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "xs_stakeholders"
    check_task_url = pe_api_url + "xs_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for xs_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged xs_stakeholders status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("xs_stakeholders query task failed, details: ", check_task_resp)


def api_s_stakeholders():
    """
    Query API for list of all S stakeholders.

    Return:
        List of all S stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "s_stakeholders"
    check_task_url = pe_api_url + "s_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for s_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged s_stakeholders status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("s_stakeholders query task failed, details: ", check_task_resp)


def api_m_stakeholders():
    """
    Query API for list of all M stakeholders.

    Return:
        List of all M stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "m_stakeholders"
    check_task_url = pe_api_url + "m_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for m_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged m_stakeholders status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("m_stakeholders query task failed, details: ", check_task_resp)


def api_l_stakeholders():
    """
    Query API for list of all L stakeholders.

    Return:
        List of all L stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "l_stakeholders"
    check_task_url = pe_api_url + "l_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for l_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged l_stakeholders status endpoint, status:", task_status)
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("l_stakeholders query task failed, details: ", check_task_resp)


def api_xl_stakeholders():
    """
    Query API for list of all XL stakeholders.

    Return:
        List of all XL stakeholders
    """
    # Endpoint info
    create_task_url = pe_api_url + "xl_stakeholders"
    check_task_url = pe_api_url + "xl_stakeholders/task/"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Create task for query
        create_task_result = requests.post(create_task_url, headers=headers).json()
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for xl_stakeholders endpoint query, task_id: ", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"
        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged xl_stakeholders status endpoint, status:", task_status
            )
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
        result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
        return result_df
    else:
        raise Exception("xl_stakeholders query task failed, details: ", check_task_resp)
