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
import math

# from .config import config, staging_config
# cisagov Libraries

from pe_scorecard.data.db_query import (
    connect,
    close,
    get_stakeholders,
    get_was_stakeholders,
    get_hosts,
    get_port_scans,
    get_was_summary,
    get_software
)

from pe_scorecard.scores.score_helper_functions import (
    get_letter_grade,
    get_next_month,
    average_numbers
)

LOGGER = logging.getLogger(__name__)

# df_orgs_df is a datframe of stakeholders with two columns: organizations_uid and cyhy_db_name
def get_profiling_score(df_orgs_df, report_period_month, report_period_year):
    this_month = datetime(report_period_year, report_period_month, 1)
    next_month = get_next_month(report_period_year, report_period_month)

    df_org_info = get_stakeholders()
    df_orgs = df_orgs_df.merge(df_org_info, on='organizations_uid', how='left')

    df_web_apps = summarize_vuln_webapps(df_orgs)
    df_port_scans = summarize_port_scans(df_orgs, this_month, next_month)
    df_software = summarize_software(df_orgs, this_month, next_month)
    df_norm_software = normalize_software(df_software)
    df_hosts = summarize_hosts(df_orgs, this_month, next_month)

    profiling_score_list = []
    for index, org in df_orgs.iterrows():
        org_id = org['organizations_uid']

        df_port_scans_org = df_port_scans.loc[df_port_scans['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see profiling score documentation)
        vuln_ports = (100.0 - df_port_scans_org['percent_vuln_ports']) * .2
        vuln_protocols = (100.0 - df_port_scans_org['percent_vuln_protocols']) * .2
        vuln_services = (100.0 - df_port_scans_org['percent_vuln_services']) * .2

        df_software_org = df_norm_software.loc[df_norm_software['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see profiling score documentation)
        total_software = (100.0 - df_software_org['norm_software']) * .2

        df_web_apps_org = df_web_apps.loc[df_web_apps['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see profiling score documentation)
        vuln_web_apps = (100.0 - df_web_apps_org['percent_vuln_webapps']) * .1

        df_hosts_orgs = df_hosts.loc[df_hosts['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see profiling score documentation)
        vuln_hosts = (100.0 - df_hosts_orgs['percent_vuln_hosts']) * .1

        metrics_aggregation = float(vuln_ports) + float(vuln_protocols) + float(vuln_services) + float(total_software) + float(vuln_web_apps) + float(vuln_hosts)
        profiing_score = 100.0 - metrics_aggregation
        rescaled_profiing_score = round((profiing_score * .4) + 60.0, 2)
        profiling_score_list.append([org['organizations_uid'], org['cyhy_db_name'], rescaled_profiing_score, get_letter_grade(rescaled_profiing_score)])
    df_profiling_score = pd.DataFrame(profiling_score_list, columns= ["organizations_uid", "cyhy_db_name", "profiling_score", "letter_grade"])
    
    return df_profiling_score

def summarize_software(orgs_df, this_month, next_month):
    org_list = orgs_df['organizations_uid'].values.tolist()
    df_software = get_software(this_month, next_month, org_list)
    software_list = []
    for index, org in orgs_df.iterrows():
        total_software = 0.0
        org_id = org['organizations_uid']
        org_df_software = df_software.loc[((df_software['organizations_uid'] == org_id) | (df_software['parent_org_uid'] == org_id))] 
        for index2, software in org_df_software.iterrows():
            total_software = total_software + software['count']
        software_list.append([org['organizations_uid'], org['cyhy_db_name'], total_software])
    df_port_scans = pd.DataFrame(software_list, columns= ["organizations_uid", "cyhy_db_name", "total_software"])
    return df_port_scans

def summarize_port_scans(orgs_df, this_month, next_month):
    org_list = orgs_df['organizations_uid'].values.tolist()
    df_port_scans = get_port_scans(this_month, next_month, org_list)
    port_scans_list = []
    for index, org in orgs_df.iterrows():
        this_month_total_ports = 0.0
        this_month_vuln_ports = 0.0
        this_month_total_protocols = 0.0
        this_month_vuln_protocols = 0.0
        this_month_total_services = 0.0
        this_month_vuln_services = 0.0
        org_id = org['organizations_uid']
        org_df_ports = df_port_scans.loc[((df_port_scans['organizations_uid'] == org_id) | (df_port_scans['parent_org_uid'] == org_id))] 
        for index2, ports in org_df_ports.iterrows():
            this_month_total_ports = this_month_total_ports + ports['ports']
            this_month_vuln_ports = this_month_vuln_ports + ports['risky_ports']
            this_month_total_protocols = this_month_total_protocols + ports['protocols']
            this_month_vuln_protocols = this_month_vuln_protocols + ports['risky_protocols']
            this_month_total_services = this_month_total_services + ports['services']

        percent_vuln_ports = average_numbers(this_month_vuln_ports, this_month_total_ports)
        percent_vuln_protocols = average_numbers(this_month_vuln_protocols, this_month_total_protocols)
        percent_vuln_services = average_numbers(this_month_vuln_services, this_month_total_services)
        port_scans_list.append([org['organizations_uid'], org['cyhy_db_name'], percent_vuln_ports, percent_vuln_protocols, percent_vuln_services])
    df_port_scans = pd.DataFrame(port_scans_list, columns= ["organizations_uid", "cyhy_db_name", "percent_vuln_ports", "percent_vuln_protocols", "percent_vuln_services"])
    return df_port_scans 

def normalize_software(df_software):
    software_list = []
    for index, org in df_software.iterrows():
        software_max = float(df_software['total_software'].max())
        software_min = float(df_software['total_software'].min())

        norm_software = 0.0
        if software_max == 0.0 or software_max - software_min == 0.0:
            norm_software = 75.0
        else:
            norm_software = ((org['total_software'] - software_min) / (software_max - software_min)) * 100.0

        software_list.append([org['organizations_uid'], norm_software])
    df_norm_soft = pd.DataFrame(software_list, columns= ["organizations_uid", "norm_software"])   
    return df_norm_soft

def summarize_vuln_webapps(orgs_df):
    was_orgs = get_was_stakeholders()
    was_ids = was_orgs['cyhy_db_name'].values
    conditions = [orgs_df['cyhy_db_name'].isin(was_ids), ~orgs_df['cyhy_db_name'].isin(was_ids)]
    was_customer = ["Yes", "No"]
    orgs_df["was_org"] = np.select(conditions, was_customer)
    was_orgs_df = orgs_df.loc[orgs_df['was_org'] == "Yes"]
    vs_orgs_df = orgs_df.loc[orgs_df['was_org'] == "No"]
    org_list = orgs_df['cyhy_db_name'].values.tolist()
    df_was_sum = get_was_summary(org_list)
    web_apps_list = []
    for index, org in was_orgs_df.iterrows():
        total_web_apps = 0.0
        vuln_web_apps = 0.0
        for index2, was in df_was_sum.iterrows():
            if org['organizations_uid'] == was['pe_org_id']:
                total_web_apps = total_web_apps + was['webapp_count']
                vuln_web_apps = vuln_web_apps + was['webapp_with_vulns_count']
        percent_vuln_webapps = average_numbers(vuln_web_apps, total_web_apps)
        web_apps_list.append([org['organizations_uid'], org['cyhy_db_name'], percent_vuln_webapps])
    was_df_attr = pd.DataFrame(web_apps_list, columns= ["organizations_uid", "cyhy_db_name", "percent_vuln_webapps"])
    
    percent_vuln_webapps = was_df_attr['percent_vuln_webapps'].mean()
    for index, org in vs_orgs_df.iterrows():
        web_apps_list.append([org['organizations_uid'], org['cyhy_db_name'], percent_vuln_webapps])
    df_web_apps = pd.DataFrame(web_apps_list, columns= ["organizations_uid", "cyhy_db_name", "percent_vuln_webapps"])
    return df_web_apps
    
def summarize_hosts(orgs_df, this_month, next_month):
    org_list = orgs_df['organizations_uid'].values.tolist()
    df_hosts = get_hosts(this_month, next_month, org_list)
    hosts_list = []
    for index, org in orgs_df.iterrows():
        total_hosts = 0.0
        total_vuln_hosts = 0.0
        org_id = org['organizations_uid']
        org_df_hosts = df_hosts.loc[((df_hosts['organizations_uid'] == org_id) | (df_hosts['parent_org_uid'] == org_id))] 
        for index2, hosts in org_df_hosts.iterrows():
            total_hosts = total_hosts + hosts['host_count']
            total_vuln_hosts = total_vuln_hosts + hosts['vulnerable_host_count']
        percent_vuln_hosts = average_numbers(total_vuln_hosts, total_hosts)
        hosts_list.append([org['organizations_uid'], org['cyhy_db_name'], percent_vuln_hosts])
    df_hosts = pd.DataFrame(hosts_list, columns= ["organizations_uid", "cyhy_db_name", "percent_vuln_hosts"])
    return df_hosts
