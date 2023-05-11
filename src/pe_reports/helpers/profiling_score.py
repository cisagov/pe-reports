
# Third-Party Libraries
import numpy as np
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
from psycopg2.extensions import AsIs
import psycopg2.extras as extras
from sshtunnel import SSHTunnelForwarder
import logging
from datetime import datetime

# from .config import config, staging_config
# cisagov Libraries
from pe_reports.data.db_query import (
    connect,
    close
)

LOGGER = logging.getLogger(__name__)

def get_profiling_score(report_period_year, report_period_month):
    this_month = datetime(report_period_year, report_period_month, 1)
    next_month = get_next_month(report_period_year, report_period_month)
    df_orgs = get_stakeholders()
    conditions = [df_orgs['total_ips'] <= 100, (df_orgs['total_ips'] > 100) & (df_orgs['total_ips'] <= 1000), (df_orgs['total_ips'] > 1000) & (df_orgs['total_ips'] <= 10000), (df_orgs['total_ips'] > 10000) & (df_orgs['total_ips'] <= 100000), df_orgs['total_ips'] > 100000]
    groups = ["XS", "S", "M", "L", "XL"]
    df_orgs["group"] = np.select(conditions, groups)

    df_web_apps = summarize_vuln_webapps(df_orgs)
    df_port_scans = summarize_port_scans(df_orgs, this_month, next_month)
    df_software = summarize_software(df_orgs, this_month, next_month)
    df_norm_software = normalize_software(df_software)
    df_hosts = summarize_hosts(df_orgs, this_month, next_month)

    profiling_score_list = []
    for index, org in df_orgs.iterrows():
        org_id = org['organizations_uid']

        df_port_scans_org = df_port_scans.loc[df_port_scans['organizations_uid'] == org_id]
        vuln_ports = (100 - df_port_scans_org['percent_vuln_ports']) * .2
        vuln_protocols = (100 - df_port_scans_org['percent_vuln_protocols']) * .2
        vuln_services = (100 - df_port_scans_org['percent_vuln_services']) * .2

        df_software_org = df_norm_software.loc[df_norm_software['organizations_uid'] == org_id]
        total_software = (100 - df_software_org['norm_software']) * .2

        df_web_apps_org = df_web_apps.loc[df_web_apps['organizations_uid'] == org_id]
        vuln_web_apps = (100 - df_web_apps_org['percent_vuln_webapps']) * .1

        df_hosts_orgs = df_hosts.loc[df_hosts['organizations_uid'] == org_id]
        vuln_hosts = (100 - df_hosts_orgs['percent_vuln_hosts']) * .1

        metrics_aggregation = float(vuln_ports) + float(vuln_protocols) + float(vuln_services) + float(total_software) + float(vuln_web_apps) + float(vuln_hosts)
        profiing_score = 100.0 - metrics_aggregation
        rescaled_profiing_score= round((profiing_score * .4) + 60.0, 2)
        profiling_score_list.append([org['organizations_uid'], org['cyhy_db_name'], rescaled_profiing_score, get_letter_grade(rescaled_profiing_score)])
    df_profiling_score = pd.DataFrame(profiling_score_list, columns= ["organizations_uid", "cyhy_db_name", "profiling_score", "letter_grade"])
    
    return df_profiling_score

def get_stakeholders():
    conn = connect()
    try:
        sql = """select mvfti.organizations_uid, mvfti.cyhy_db_name, mvfti.total_ips, o.fceb, o.report_on 
        from mat_vw_fceb_total_ips mvfti 
        inner join organizations o on 
        o.organizations_uid = mvfti.organizations_uid 
        where o.fceb = true"""
        pe_orgs_df = pd.read_sql(sql, conn)
        return pe_orgs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)

def average_numbers(vuln_count, total):
    if total == 0:
        return 0.0
    else:
        return round((vuln_count/total) * 100, 2)

def get_was_stakeholders():
    conn = connect()
    try:
        sql = """select o.organizations_uid, o.cyhy_db_name, wm.was_org_id, o.fceb, o.fceb_child, o.parent_org_uid 
        from organizations o
        right join was_map wm on
        o.organizations_uid = wm.pe_org_id 
        where o.fceb = true or o.fceb_child  = true"""
        fceb_orgs_df = pd.read_sql(sql, conn)
        return fceb_orgs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)

def get_was_summary():
    conn = connect()
    try:
        sql = """SELECT ws.was_org_id, wm.pe_org_id, ws.webapp_count, ws.webapp_with_vulns_count, max(ws.last_updated)
        from was_summary ws 
        left join was_map wm on
        ws.was_org_id = wm.was_org_id 
        where wm.pe_org_id notnull
        group by ws.was_org_id, wm.pe_org_id, ws.webapp_count, ws.webapp_with_vulns_count"""
        was_data_df = pd.read_sql(sql, conn)
        return was_data_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)

def get_hosts(start_date, end_date):
    conn = connect()
    try:
        sql = """select o.organizations_uid, o.cyhy_db_name, cs.host_count, cs.vulnerable_host_count, o.parent_org_uid
        from organizations o 
        left join cyhy_snapshots cs on
        o.organizations_uid = cs.organizations_uid 
        where o.report_on  = true and cs.cyhy_last_change between %(start_date)s AND %(end_date)s"""
        snapshots_df = pd.read_sql(sql, conn, params={"start_date": start_date, "end_date": end_date})
        return snapshots_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)

def get_software(start_date, end_date):
    conn = connect()
    try:
        sql = """select o.organizations_uid, o.cyhy_db_name, o.parent_org_uid, count(cvs.plugin_name)
        from organizations o 
        left join cyhy_vuln_scans cvs on
        o.organizations_uid = cvs.organizations_uid 
        where (o.fceb = true or o.fceb_child = true) and cvs.plugin_name = 'Unsupported Web Server Detection' and cvs.cyhy_time between %(start_date)s AND %(end_date)s
        group by o.organizations_uid, o.cyhy_db_name, o.parent_org_uid"""
        vuln_scans_df = pd.read_sql(sql, conn, params={"start_date": start_date, "end_date": end_date})
        return vuln_scans_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)

def summarize_software(orgs_df, this_month, next_month):
    df_software = get_software(this_month, next_month)
    software_list = []
    for index, org in orgs_df.iterrows():
        total_software = 0
        for index2, software in df_software.iterrows():
            if org['organizations_uid'] == software['organizations_uid'] or org['organizations_uid'] == software['parent_org_uid']:
                total_software = total_software + software['count']
        software_list.append([org['organizations_uid'], org['cyhy_db_name'], org['group'], total_software])
    df_port_scans = pd.DataFrame(software_list, columns= ["organizations_uid", "cyhy_db_name", "group", "total_software"])
    return df_port_scans

def get_port_scans(start_date, end_date):
    conn = connect()
    try:
        sql = """select mvcpc.organizations_uid, mvcpc.cyhy_db_name, mvcpc.report_period, mvcpc.ports, mvcpc.risky_ports, mvcpc2.protocols, mvcrpc.risky_protocols, mvcsc2.services, o.parent_org_uid 
        from mat_vw_cyhy_port_counts mvcpc 
        inner join mat_vw_cyhy_protocol_counts mvcpc2 on
        mvcpc2.organizations_uid  = mvcpc.organizations_uid
        inner join mat_vw_cyhy_risky_protocol_counts mvcrpc on
        mvcrpc.organizations_uid  = mvcpc.organizations_uid
        inner join organizations o on 
        o.organizations_uid = mvcpc.organizations_uid 
        inner join mat_vw_cyhy_services_counts mvcsc on
        mvcsc.organizations_uid = mvcpc.organizations_uid 
        inner join mat_vw_cyhy_services_counts mvcsc2 on 
        mvcsc2.organizations_uid  = mvcpc.organizations_uid
        where mvcpc.report_period between %(start_date)s AND %(end_date)s"""
        df_port_scans = pd.read_sql(sql, conn, params={"start_date": start_date, "end_date": end_date})
        return df_port_scans
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn) 

def summarize_port_scans(orgs_df, this_month, next_month):
    df_port_scans = get_port_scans(this_month, next_month)
    port_scans_list = []
    for index, org in orgs_df.iterrows():
        this_month_total_ports = 0
        this_month_vuln_ports = 0
        this_month_total_protocols = 0
        this_month_vuln_protocols = 0
        this_month_total_services = 0
        this_month_vuln_services = 0
        for index2, ports in df_port_scans.iterrows():
            if org['organizations_uid'] == ports['organizations_uid'] or org['organizations_uid'] == ports['parent_org_uid']:
                this_month_total_ports = this_month_total_ports + ports['ports']
                this_month_vuln_ports = this_month_vuln_ports + ports['risky_ports']
                this_month_total_protocols = this_month_total_protocols + ports['protocols']
                this_month_vuln_protocols = this_month_vuln_protocols + ports['risky_protocols']
                this_month_total_services = this_month_total_services + ports['services']

        percent_vuln_ports = average_numbers(this_month_vuln_ports, this_month_total_ports)
        percent_vuln_protocols = average_numbers(this_month_vuln_protocols, this_month_total_protocols)
        percent_vuln_services = average_numbers(this_month_vuln_services, this_month_total_services)
        
        port_scans_list.append([org['organizations_uid'], org['cyhy_db_name'], org['group'], percent_vuln_ports, percent_vuln_protocols, percent_vuln_services])
    df_port_scans = pd.DataFrame(port_scans_list, columns= ["organizations_uid", "cyhy_db_name", "group", "percent_vuln_ports", "percent_vuln_protocols", "percent_vuln_services"])
    return df_port_scans 

def normalize_software(df_software):
    software_list = []
    for index, org in df_software.iterrows():
        group = org['group']
        df = df_software.loc[df_software['group'] == group]
        software_max = df['total_software'].max()
        software_min = df['total_software'].min()

        norm_software = 0
        if software_max == 0 or software_max - software_min == 0:
            norm_software = 75 
        else:
            norm_software = ((org['total_software'] - software_min) / (software_max - software_min)) * 100

        software_list.append([org['organizations_uid'], org['group'], norm_software])
    df_norm_soft = pd.DataFrame(software_list, columns= ["organizations_uid", "group", "norm_software"])   
    return df_norm_soft

def summarize_vuln_webapps(orgs_df):
    was_orgs = get_was_stakeholders()
    was_ids = was_orgs['cyhy_db_name'].values
    conditions = [orgs_df['cyhy_db_name'].isin(was_ids), ~orgs_df['cyhy_db_name'].isin(was_ids)]
    was_customer = ["Yes", "No"]
    orgs_df["was_org"] = np.select(conditions, was_customer)
    was_orgs_df = orgs_df.loc[orgs_df['was_org'] == "Yes"]
    vs_orgs_df = orgs_df.loc[orgs_df['was_org'] == "No"]
    df_was_sum = get_was_summary()
    web_apps_list = []
    for index, org in was_orgs_df.iterrows():
        total_web_apps = 0
        vuln_web_apps = 0
        for index2, was in df_was_sum.iterrows():
            if org['organizations_uid'] == was['pe_org_id']:
                total_web_apps = total_web_apps + was['webapp_count']
                vuln_web_apps = vuln_web_apps + was['webapp_with_vulns_count']
        percent_vuln_webapps = average_numbers(vuln_web_apps, total_web_apps)
        web_apps_list.append([org['organizations_uid'], org['group'], org['cyhy_db_name'], percent_vuln_webapps])
    was_df_attr = pd.DataFrame(web_apps_list, columns= ["organizations_uid", "group", "cyhy_db_name", "percent_vuln_webapps"])
    for index, org in vs_orgs_df.iterrows():
        group = org['group']
        df = was_df_attr.loc[was_df_attr['group'] == group]
        percent_vuln_webapps = df['percent_vuln_webapps'].mean()
        web_apps_list.append([org['organizations_uid'], org['cyhy_db_name'], org['group'], percent_vuln_webapps])
    df_web_apps = pd.DataFrame(web_apps_list, columns= ["organizations_uid", "cyhy_db_name", "group", "percent_vuln_webapps"])
    return df_web_apps
    
def summarize_hosts(orgs_df, this_month, next_month):
    df_hosts = get_hosts(this_month, next_month)
    hosts_list = []
    for index, org in orgs_df.iterrows():
        total_hosts = 0
        total_vuln_hosts = 0
        for index2, hosts in df_hosts.iterrows():
            if org['organizations_uid'] == hosts['organizations_uid'] or org['organizations_uid'] == hosts['parent_org_uid']:
                total_hosts = total_hosts + hosts['host_count']
                total_vuln_hosts = total_vuln_hosts + hosts['vulnerable_host_count']
        percent_vuln_hosts = average_numbers(total_vuln_hosts, total_hosts)
        hosts_list.append([org['organizations_uid'], org['cyhy_db_name'], org['group'], percent_vuln_hosts])
    df_hosts = pd.DataFrame(hosts_list, columns= ["organizations_uid", "cyhy_db_name", "group", "percent_vuln_hosts"])
    return df_hosts
        
def get_next_month(report_period_year, report_period_month):
    next_report_period_month = 0
    next_report_period_year = 0
    if report_period_month == 12:
        next_report_period_month = 1
        next_report_period_year = report_period_year + 1
    else:
        next_report_period_month = report_period_month + 1
        next_report_period_year = report_period_year
    next_report_period_date = datetime(next_report_period_year, next_report_period_month, 1)
    return next_report_period_date
     
def get_letter_grade(score):
    if score < 65.0:
        return "F"
    elif score >= 65.0 and score < 67.0:
        return "D"
    elif score >= 67.0 and score < 70.0:
        return "D+"
    elif score >= 70.0 and score < 73.0:
        return "C-"
    elif score >= 73.0 and score < 77.0:
        return "C"
    elif score >= 77.0 and score < 80.0:
        return "C+"
    elif score >= 80.0 and score < 83.0:
        return "B-"
    elif score >= 83.0 and score < 87.0:
        return "B"
    elif score >= 87.0 and score < 90.0:
        return "B+"
    elif score >= 90.0 and score < 93.0:
        return "A-"
    elif score >= 93.0 and score < 97.0:
        return "A"
    else:
        return "A+"
