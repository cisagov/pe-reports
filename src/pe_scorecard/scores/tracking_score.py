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
from datetime import timezone

# from .config import config, staging_config
# cisagov Libraries
from pe_reports.data.db_query import (
    connect,
    close
)

from pe_scorecard.data.db_query import (
    connect,
    close,
    get_stakeholders,
    get_was_stakeholders,
    get_bod_18,
    get_ports_protocols,
    get_was_closed_vulns,
    get_was_open_vulns,
    get_vs_closed_vulns,
    get_vs_open_vulns,
    get_kevs,
    get_pe_vulns
)

from pe_scorecard.scores.score_helper_functions import (
    get_letter_grade,
    get_next_month,
    get_last_month,
    average_list,
    average_numbers
)

LOGGER = logging.getLogger(__name__)

# df_orgs_df is a datframe of stakeholders with two columns: organizations_uid and cyhy_db_name
def get_tracking_score(df_orgs_df, report_period_year, report_period_month):
    LOGGER.info("Calculating tracking score")
    last_month = get_last_month(report_period_year, report_period_month)
    this_month = datetime(report_period_year, report_period_month, 1)
    next_month = get_next_month(report_period_year, report_period_month)

    df_org_info = get_stakeholders()
    df_orgs = df_orgs_df.merge(df_org_info, on='organizations_uid', how='left')

    df_bod_18 = summarize_bod_18(df_orgs)
    df_bod_19_22 = get_bod_19_22(df_orgs)
    df_was_bod_19 = summarize_was_bod_19(df_orgs, this_month, next_month)
    df_vs_attr = summarize_vs_attr(df_orgs, this_month, next_month)
    df_was_atr = summarize_was_attr(df_orgs, this_month, next_month)

    LOGGER.info("Summarize counts")
    # Data before Normalization
    df_pe_vulns = summarize_pe_vuln_counts(df_orgs, last_month, this_month, next_month)
    df_vs_vulns = summarize_vs_vuln_counts(df_orgs, this_month)
    df_was_vulns = summarize_was_vuln_counts(df_orgs, last_month, this_month, next_month)
    df_ports_prot= summarize_port_scans(df_orgs, last_month, this_month, next_month)

    LOGGER.info("Normalize data")
    # #Data after Normalization
    df_norm_vs_vulns = normalize_vulns(df_vs_vulns, "VS")
    df_norm_was_vulns = normalize_vulns(df_was_vulns, "WAS")
    df_norm_pe_vulns = normalize_vulns(df_pe_vulns, "PE")
    df_norm_ports_prot = normalize_port_scans(df_ports_prot)

    tracking_score_list = []
    for index, org in df_orgs.iterrows():
        LOGGER.info(index)
        LOGGER.info(org['organizations_uid'])
        org_id = org['organizations_uid']

        df_bod_18_org = df_bod_18.loc[df_bod_18['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see tracking score documentation)
        bod_18_email = (100.0 - df_bod_18_org['email_bod_compliance']) * .125
        bod_18_web = (100.0 - df_bod_18_org['web_bod_compliance']) * .125

        vs_df_bod_19_22_org = df_bod_19_22.loc[df_bod_19_22['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see tracking score documentation)
        vs_bod_22_kevs = (100.0 - vs_df_bod_19_22_org['percent_compliance_kevs']) * .25
        vs_bod_19_crits = (100.0 - vs_df_bod_19_22_org['percent_compliance_crits']) * .2
        vs_bod_19_highs = (100.0 - vs_df_bod_19_22_org['percent_compliance_highs']) * .15
        vs_bod_19_meds = (100.0 - vs_df_bod_19_22_org['percent_compliance_meds']) * .1
        vs_bod_19_lows = (100.0 - vs_df_bod_19_22_org['percent_compliance_lows']) * .05

        # Multiplying by predetermined weights for metric subsections (see tracking score documentation)
        vs_overdue_vuln_section = (float(bod_18_email) + float(bod_18_web) + float(vs_bod_22_kevs) + float(vs_bod_19_crits) + float(vs_bod_19_highs) + float(vs_bod_19_meds) + float(vs_bod_19_lows)) * .5

        df_vs_attr_org = df_vs_attr.loc[df_vs_attr['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see tracking score documentation)
        vs_attr_kevs = (100.0 - df_vs_attr_org['attr_kevs']) * .4
        vs_attr_crits = (100.0 - df_vs_attr_org['attr_crits']) * .35
        vs_attr_highs = (100.0 - df_vs_attr_org['attr_highs']) * .25

        # Multiplying by predetermined weights for metric subsections (see tracking score documentation)
        vs_attr_section = (vs_attr_kevs + vs_attr_crits + vs_attr_highs) * .25

        df_vs_vulns_org = df_norm_vs_vulns.loc[df_norm_vs_vulns['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see tracking score documentation)
        vs_kevs = (100.0 - df_vs_vulns_org['norm_kevs']) * .2
        vs_crits = (100.0 - df_vs_vulns_org['norm_crits']) * .15
        vs_highs = (100.0 - df_vs_vulns_org['norm_highs']) * .1
        vs_meds = (100.0 - df_vs_vulns_org['norm_meds']) * .08
        vs_lows = (100.0 - df_vs_vulns_org['norm_lows']) * .05

        df_vs_ports_org = df_norm_ports_prot.loc[df_norm_ports_prot['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see tracking score documentation)
        vs_ports = (100.0 - df_vs_ports_org['norm_ports']) * .14
        vs_protocols = (100.0 - df_vs_ports_org['norm_protocols']) * .14
        vs_services = (100.0 - df_vs_ports_org['norm_services']) * .14

        # Multiplying by predetermined weights for metric subsections (see tracking score documentation)
        vs_historical_trend_section = (vs_kevs + vs_crits + vs_highs + vs_meds + vs_lows + vs_ports + vs_protocols + vs_services) * .25
        
        df_pe_vulns_org = df_norm_pe_vulns.loc[df_norm_pe_vulns['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see tracking score documentation)
        pe_kevs = (100.0 - df_pe_vulns_org['norm_kevs']) * .2
        pe_crits = (100.0 - df_pe_vulns_org['norm_crits']) * .15
        pe_highs = (100.0 - df_pe_vulns_org['norm_highs']) * .1
        pe_meds = (100.0 - df_pe_vulns_org['norm_meds']) * .08
        pe_lows = (100.0 - df_pe_vulns_org['norm_lows']) * .05

        # Multiplying by predetermined weights for metric subsections (see tracking score documentation)
        pe_historical_trend_section = (pe_kevs + pe_crits + pe_highs + pe_meds + pe_lows)

        df_was_vulns_org = df_norm_was_vulns.loc[df_norm_was_vulns['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see tracking score documentation)
        was_crits = (100.0 - df_was_vulns_org['norm_crits']) * .4
        was_highs = (100.0 - df_was_vulns_org['norm_highs']) * .3
        was_meds = (100.0 - df_was_vulns_org['norm_meds']) * .2
        was_lows = (100.0 - df_was_vulns_org['norm_lows']) * .1

        # Multiplying by predetermined weights for metric subsections (see tracking score documentation)
        was_historical_trend_section = (was_crits + was_highs + was_meds + was_lows) * .25

        df_was_bod_19_org = df_was_bod_19.loc[df_was_bod_19['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see tracking score documentation)
        was_bod_19_crits = (100.0 - df_was_bod_19_org['percent_compliance_crits']) * .4
        was_bod_19_highs = (100.0 - df_was_bod_19_org['percent_compliance_highs']) * .3
        was_bod_19_meds = (100.0 - df_was_bod_19_org['percent_compliance_meds']) * .2
        was_bod_19_lows = (100.0 - df_was_bod_19_org['percent_compliance_lows']) * .1
        
        # Multiplying by predetermined weights for metric subsections (see tracking score documentation)
        was_overdue_vuln_section = (was_bod_19_crits + was_bod_19_highs + was_bod_19_meds + was_bod_19_lows) * .5

        df_was_attr_org = df_was_atr.loc[df_was_atr['organizations_uid'] == org_id]
        # Multiplying by predetermined weights for base metrics (see tracking score documentation)
        was_attr_crits = (100.0 - df_was_attr_org['attr_compl_crits']) * .55
        was_attr_highs = (100.0 - df_was_attr_org['attr_compl_highs']) * .45

        # Multiplying by predetermined weights for metric subsections (see tracking score documentation)
        was_attr_section = (was_attr_crits + was_attr_highs) * .25
        
        # Multiplying by predetermined weights for team sections (see tracking score documentation)
        vs_section = (vs_attr_section + vs_overdue_vuln_section + vs_historical_trend_section) * .5
        pe_section = pe_historical_trend_section * .2
        was_section = (was_attr_section + was_overdue_vuln_section + was_historical_trend_section) * .3

        metrics_aggregation = float(pe_section) + float(was_section) + float(vs_section)
        tracking_score = 100.0 - metrics_aggregation
        rescaled_tracking_score = round((tracking_score * .4) + 60.0, 2)
        tracking_score_list.append([org['organizations_uid'], org['cyhy_db_name'], rescaled_tracking_score, get_letter_grade(rescaled_tracking_score)])
    df_tracking_score = pd.DataFrame(tracking_score_list, columns= ["organizations_uid", "cyhy_db_name", "tracking_score", "letter_grade"])   
    LOGGER.info("Finished Calculating Tracking Score")
    return df_tracking_score

def summarize_vs_attr(orgs_df, this_month, next_month):
    org_list = orgs_df['organizations_uid'].values.tolist()
    df_closed_vulns = get_vs_closed_vulns(this_month, next_month, org_list)
    kevs_df = get_kevs()
    average_time_to_remediate_list = []
    for index, org in orgs_df.iterrows():
        org_kevs = []
        org_crits = []
        org_highs = []
        for index2, vuln in df_closed_vulns.iterrows():
            if org['organizations_uid'] == vuln['organizations_uid'] or org['organizations_uid'] == vuln['parent_org_uid']:
                time_to_remediate = get_age(vuln['time_opened'], vuln['time_closed'])
                if vuln['cve'] in kevs_df['kev'].values:
                    org_kevs.append(time_to_remediate)
                if vuln['cvss_base_score'] >= 9.0:
                    org_crits.append(time_to_remediate)
                if vuln['cvss_base_score'] >= 7.0 and vuln['cvss_base_score'] < 9.0:
                    org_highs.append(time_to_remediate)
        average_kevs = average_list(org_kevs)
        average_crits = average_list(org_crits)
        average_highs = average_list(org_highs)
        average_time_to_remediate_list.append([org['organizations_uid'], org['cyhy_db_name'], calculate_attr_compliance(average_kevs, "KEV"), calculate_attr_compliance(average_crits, "CRIT"), calculate_attr_compliance(average_highs, "HIGH")])
    df_attr = pd.DataFrame(average_time_to_remediate_list, columns= ["organizations_uid", "cyhy_db_name", "attr_kevs", "attr_crits", "attr_highs"])
    
    return df_attr

def calculate_attr_compliance(vuln_attr, type):
    compliance_min = 0.0
    compliance_max = 0.0
    if vuln_attr == "N/A":
        return 100.0
    if type == "KEV":
        compliance_min = 14.0
        compliance_max = 28.0
    elif type == "CRIT":
        compliance_min = 15.0
        compliance_max = 30.0
    else:
        compliance_min = 30.0
        compliance_max = 60.0
    if vuln_attr <= compliance_min:
        return 100.0
    elif vuln_attr >= compliance_max:
        return 0.0
    else:
        return round((compliance_max-vuln_attr/compliance_min)*100, 2)

def get_bod_19_22(orgs_df):
    org_list = orgs_df['organizations_uid'].values.tolist()
    open_tickets_df = get_vs_open_vulns(org_list)
    kevs_df = get_kevs()

    bod_19_22_list = []
    for index, org in orgs_df.iterrows():
        total_kevs = 0.0
        overdue_kevs = 0.0
        total_crits = 0.0
        overdue_crits = 0.0
        total_highs = 0.0
        overdue_highs = 0.0
        total_medium = 0.0
        overdue_medium = 0.0
        total_low = 0.0
        overdue_low = 0.0
        for index2, ticket in open_tickets_df.iterrows():
            if org['cyhy_db_name'] == ticket['cyhy_db_name'] or org['organizations_uid'] == ticket['parent_org_uid']:
                time_opened = ticket['time_opened']
                now = datetime.now()
                age = get_age(time_opened, now)   
                if ticket['cve'] in kevs_df['kev'].values:
                    total_kevs = total_kevs + 1.0
                    if age > 14.0:
                        overdue_kevs = overdue_kevs + 1.0
                if ticket['cvss_base_score'] >= 9.0:
                    total_crits = total_crits + 1.0
                    if age > 15.0:
                        overdue_crits = overdue_crits + 1.0
                elif ticket['cvss_base_score'] >= 7.0 and ticket['cvss_base_score'] < 9.0:
                    total_highs = total_highs + 1.0
                    if age > 30.0:
                        overdue_highs = overdue_highs + 1.0
                elif ticket['cvss_base_score'] >= 4.0 and ticket['cvss_base_score'] < 7.0:
                    total_medium = total_medium + 1.0
                    if age > 90.0:
                        overdue_medium = overdue_medium + 1.0
                else:
                    total_low = total_low + 1.0
                    if age > 180.0:
                        overdue_low = overdue_low + 1.0
        percent_compliance_kevs = get_percent_compliance(total_kevs, overdue_kevs)
        percent_compliance_crits = get_percent_compliance(total_crits, overdue_crits)
        percent_compliance_highs = get_percent_compliance(total_highs, overdue_highs)
        percent_compliance_medium = get_percent_compliance(total_medium, overdue_medium)
        percent_compliance_low = get_percent_compliance(total_low, overdue_low)
        bod_19_22_list.append([org['organizations_uid'], org['cyhy_db_name'], percent_compliance_kevs, percent_compliance_crits, percent_compliance_highs, percent_compliance_medium, percent_compliance_low])

    df_bod_19_22 = pd.DataFrame(bod_19_22_list, columns= ["organizations_uid", "cyhy_db_name", "percent_compliance_kevs", "percent_compliance_crits", "percent_compliance_highs", "percent_compliance_meds", "percent_compliance_lows"])
    return df_bod_19_22

def get_percent_compliance(total, overdue):
    if total == 0.0:
        return 100.0
    else:
        return round(((total - overdue)/total)* 100.0, 2)

def get_age(start_time, end_time):
    start_time = str(start_time)
    end_time = str(end_time)
    if "." in start_time:
        start_time = start_time.split(".")[0]
    if "." in end_time:
        end_time = end_time.split(".")[0]
    start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
    start_time = start_time.timestamp()
    start_time = datetime.fromtimestamp(start_time, timezone.utc)
    start_time = start_time.replace(tzinfo=None)
    end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    end_time = end_time.timestamp()
    end_time = datetime.fromtimestamp(end_time, timezone.utc)
    end_time = end_time.replace(tzinfo=None)
    age = round((float(((end_time - start_time).total_seconds()))/60/60/24), 2)
    return age

def summarize_vs_vuln_counts(orgs_df, this_month):
    org_list = orgs_df['organizations_uid'].values.tolist()
    df_vulns = get_vs_open_vulns(org_list)
    df_kevs = get_kevs()
    vulns_list = []
    for index, org in orgs_df.iterrows():
        last_month_kevs = 0.0
        last_month_crits = 0.0
        last_month_highs = 0.0
        last_month_meds = 0.0
        last_month_lows = 0.0
        this_month_kevs = 0.0
        this_month_crits = 0.0
        this_month_highs = 0.0
        this_month_meds = 0.0
        this_month_lows = 0.0
        for index2, vulns in df_vulns.iterrows():
            if org['organizations_uid'] == vulns['organizations_uid'] or org['organizations_uid'] == vulns['parent_org_uid']:
                if vulns['time_opened'] >= this_month:
                    if vulns['cvss_base_score'] >= 9.0:
                        this_month_crits = this_month_crits + 1.0
                    elif vulns['cvss_base_score'] >= 7.0:
                        this_month_highs = this_month_highs + 1.0
                    elif vulns['cvss_base_score'] >= 4.0:
                        this_month_meds = this_month_meds + 1.0
                    else:
                        this_month_lows = this_month_lows + 1.0
                    if vulns['cve'] in df_kevs['kev'].values:
                            this_month_kevs = this_month_kevs + 1.0
                else:
                    if vulns['cvss_base_score'] >= 9.0:
                        last_month_crits = last_month_crits + 1.0
                    elif vulns['cvss_base_score'] >= 7.0:
                        last_month_highs = last_month_highs + 1.0
                    elif vulns['cvss_base_score'] >= 4.0:
                        last_month_meds = last_month_meds + 1.0
                    else:
                        last_month_lows = last_month_lows + 1.0
                    if vulns['cve'] in df_kevs['kev'].values:
                        last_month_kevs = last_month_kevs + 1.0
        change_in_kevs =  this_month_kevs - last_month_kevs
        change_in_crits = this_month_crits - last_month_crits
        change_in_highs = this_month_highs - last_month_highs
        change_in_meds = this_month_meds - last_month_meds
        change_in_lows = this_month_lows - last_month_lows
        vulns_list.append([org['organizations_uid'],org['cyhy_db_name'], change_in_kevs, change_in_crits, change_in_highs, change_in_meds, change_in_lows])
    df_vulns = pd.DataFrame(vulns_list, columns= ["organizations_uid", "cyhy_db_name", "change_in_kevs", "change_in_crits", "change_in_highs", "change_in_meds", "change_in_lows"])
    return df_vulns

def summarize_pe_vuln_counts(orgs_df, last_month, this_month, next_month):
    org_list = orgs_df['organizations_uid'].values.tolist()
    df_vulns = get_pe_vulns(last_month, next_month, org_list)
    df_kevs = get_kevs()
    vs_orgs = orgs_df.loc[orgs_df['report_on'] == False]
    pe_orgs = orgs_df.loc[orgs_df['report_on'] == True]
    vulns_list = []
    for index, org in pe_orgs.iterrows():
        last_month_kevs = 0.0
        last_month_crits = 0.0
        last_month_highs = 0.0
        last_month_meds = 0.0
        last_month_lows = 0.0
        this_month_kevs = 0.0
        this_month_crits = 0.0
        this_month_highs = 0.0
        this_month_meds = 0.0
        this_month_lows = 0.0
        for index2, vulns in df_vulns.iterrows():
            if org['cyhy_db_name'] == vulns['cyhy_db_name'] or org['organizations_uid'] == vulns['parent_org_uid']:
                if vulns['timestamp'] >= this_month:
                    if vulns['cvss'] >= 9.0:
                        this_month_crits = this_month_crits + 1.0
                    elif vulns['cvss'] >= 7.0:
                        this_month_highs = this_month_highs + 1.0
                    elif vulns['cvss'] >= 4.0:
                        this_month_meds = this_month_meds + 1.0
                    else:
                        this_month_lows = this_month_lows + 1.0
                    if vulns['cve'] in df_kevs['kev'].values:
                        this_month_kevs = this_month_kevs + 1.0
                else:
                    if vulns['cvss'] >= 9.0:
                        last_month_crits = last_month_crits + 1.0
                    elif vulns['cvss'] >= 7.0:
                        last_month_highs = last_month_highs + 1.0
                    elif vulns['cvss'] >= 4.0:
                        last_month_meds = last_month_meds + 1.0
                    else:
                        last_month_lows = last_month_lows + 1.0
                    if vulns['cve'] in df_kevs['kev'].values:
                        last_month_kevs = last_month_kevs + 1.0
        change_in_kevs =  this_month_kevs - last_month_kevs
        change_in_crits = this_month_crits - last_month_crits
        change_in_highs = this_month_highs - last_month_highs
        change_in_meds = this_month_meds - last_month_meds
        change_in_lows = this_month_lows - last_month_lows
        vulns_list.append([org['organizations_uid'], org['cyhy_db_name'], change_in_kevs, change_in_crits, change_in_highs, change_in_meds, change_in_lows])
    df_pe_vulns = pd.DataFrame(vulns_list, columns= ["organizations_uid", "cyhy_db_name", "change_in_kevs", "change_in_crits", "change_in_highs", "change_in_meds", "change_in_lows"])
    
    vs_change_in_kevs = df_pe_vulns['change_in_kevs'].mean()
    vs_change_in_crits = df_pe_vulns['change_in_crits'].mean()
    vs_change_in_highs = df_pe_vulns['change_in_highs'].mean()
    vs_change_in_meds = df_pe_vulns['change_in_meds'].mean()
    vs_change_in_lows = df_pe_vulns['change_in_lows'].mean()
    for index, org in vs_orgs.iterrows():
        vulns_list.append([org['organizations_uid'], org['cyhy_db_name'], vs_change_in_kevs, vs_change_in_crits, vs_change_in_highs, vs_change_in_meds, vs_change_in_lows])
    df_vulns = pd.DataFrame(vulns_list, columns= ["organizations_uid", "cyhy_db_name", "change_in_kevs", "change_in_crits", "change_in_highs", "change_in_meds", "change_in_lows"])
    return df_vulns

def summarize_was_vuln_counts(orgs_df, last_month, this_month, next_month):
    was_orgs = get_was_stakeholders()
    was_ids = was_orgs['cyhy_db_name'].values
    conditions = [orgs_df['cyhy_db_name'].isin(was_ids), ~orgs_df['cyhy_db_name'].isin(was_ids)]
    was_customer = ["Yes", "No"]
    orgs_df["was_org"] = np.select(conditions, was_customer)
    was_orgs_df = orgs_df.loc[orgs_df['was_org'] == "Yes"]
    vs_orgs_df = orgs_df.loc[orgs_df['was_org'] == "No"]
    org_list = orgs_df['cyhy_db_name'].values.tolist()
    was_open_vulns = get_was_open_vulns(last_month, next_month, org_list)
    vulns_list = []
    for index, org in was_orgs_df.iterrows():
        last_month_crits = 0.0
        last_month_highs = 0.0
        last_month_meds = 0.0
        last_month_lows = 0.0
        this_month_crits = 0.0
        this_month_highs = 0.0
        this_month_meds = 0.0
        this_month_lows = 0.0
        for index2, vulns in was_open_vulns.iterrows():
            if org['organizations_uid'] == vulns['pe_org_id']:
                last_detected = vulns['last_detected']
                last_detected = datetime(last_detected.year, last_detected.month, last_detected.day)
                if last_detected >= this_month:
                    if vulns['base_score'] >= 9.0:
                        this_month_crits = this_month_crits + 1.0
                    elif vulns['base_score'] >= 7.0:
                        this_month_highs = this_month_highs + 1.0
                    elif vulns['base_score'] >= 4.0:
                        this_month_meds = this_month_meds + 1.0
                    else:
                        this_month_lows = this_month_lows + 1.0
                else:
                    if vulns['base_score'] >= 9.0:
                        last_month_crits = last_month_crits + 1.0
                    elif vulns['base_score'] >= 7.0:
                        last_month_highs = last_month_highs + 1.0
                    elif vulns['base_score'] >= 4.0:
                        last_month_meds = last_month_meds + 1.0
                    else:
                        last_month_lows = last_month_lows + 1.0
        change_in_crits = this_month_crits - last_month_crits
        change_in_highs = this_month_highs - last_month_highs
        change_in_meds = this_month_meds - last_month_meds
        change_in_lows = this_month_lows - last_month_lows
        vulns_list.append([org['organizations_uid'], org['cyhy_db_name'], change_in_crits, change_in_highs, change_in_meds, change_in_lows])
    df_was_vulns = pd.DataFrame(vulns_list, columns= ["organizations_uid", "cyhy_db_name", "change_in_crits", "change_in_highs", "change_in_meds", "change_in_lows"])
    
    vs_change_in_crits = df_was_vulns['change_in_crits'].mean()
    vs_change_in_highs = df_was_vulns['change_in_highs'].mean()
    vs_change_in_meds = df_was_vulns['change_in_meds'].mean()
    vs_change_in_lows = df_was_vulns['change_in_lows'].mean()
    for index, org in vs_orgs_df.iterrows():
        vulns_list.append([org['organizations_uid'], org['cyhy_db_name'], vs_change_in_crits, vs_change_in_highs, vs_change_in_meds, vs_change_in_lows])
    df_vulns = pd.DataFrame(vulns_list, columns= ["organizations_uid", "cyhy_db_name", "change_in_crits", "change_in_highs", "change_in_meds", "change_in_lows"])
    return df_vulns

def summarize_bod_18(orgs_df):
    df_bod_18 = get_bod_18()
    bod_18_list = []
    for index, org in orgs_df.iterrows():
        #Giving 100% compliance to stakeholders whose data is not attainable for BOD 18-01
        email_bod_compliance = 100.0
        web_bod_compliance = 100.0
        for index2, bod in df_bod_18.iterrows():
            if org['organizations_uid'] == bod['organizations_uid']:
                if bod['email_compliance_pct'] is not None:
                    email_bod_compliance = bod['email_compliance_pct']
                if bod['https_compliance_pct'] is not None:
                    web_bod_compliance = bod['https_compliance_pct']
        bod_18_list.append([org['organizations_uid'], email_bod_compliance, web_bod_compliance])
        df_vulns = pd.DataFrame(bod_18_list, columns= ["organizations_uid", "email_bod_compliance", "web_bod_compliance"])
    return df_vulns

def summarize_was_bod_19(orgs_df, this_month, next_month):
    was_orgs = get_was_stakeholders()
    was_ids = was_orgs['cyhy_db_name'].values
    conditions = [orgs_df['cyhy_db_name'].isin(was_ids), ~orgs_df['cyhy_db_name'].isin(was_ids)]
    was_customer = ["Yes", "No"]
    orgs_df["was_org"] = np.select(conditions, was_customer)
    was_orgs_df = orgs_df.loc[orgs_df['was_org'] == "Yes"]
    vs_orgs_df = orgs_df.loc[orgs_df['was_org'] == "No"]
    org_list = orgs_df['cyhy_db_name'].values.tolist()
    was_open_vulns = get_was_open_vulns(this_month, next_month, org_list)
    vulns_list = []
    for index, org in was_orgs_df.iterrows():
        total_crits = 0.0
        overdue_crits = 0.0
        total_highs = 0.0
        overdue_highs = 0.0
        total_medium = 0.0
        overdue_medium = 0.0
        total_low = 0.0
        overdue_low = 0.0
        for index2, vulns in was_open_vulns.iterrows():
            if org['organizations_uid'] == vulns['pe_org_id']:
                last_detected = vulns['last_detected']
                last_detected = datetime(last_detected.year, last_detected.month, last_detected.day)
                first_detected = vulns['first_detected']
                first_detected = datetime(first_detected.year, first_detected.month, first_detected.day)
                age = get_age(first_detected, last_detected)
                if vulns['base_score'] >= 9.0:
                    total_crits = total_crits + 1.0
                    if age > 15.0:
                        overdue_crits = overdue_crits + 1.0
                elif vulns['base_score'] >= 7.0 and vulns['base_score'] < 9.0:
                    total_highs = total_highs + 1.0
                    if age >30.0:
                        overdue_highs = overdue_highs + 1.0
                elif vulns['base_score']>= 4.0 and vulns['base_score'] < 7.0:
                    total_medium = total_medium + 1.0
                    if age > 90.0:
                        overdue_medium = overdue_medium + 1.0
                else:
                    total_low = total_low + 1.0
                    if age > 180.0:
                        overdue_low = overdue_low + 1.0
        percent_compliance_crits = get_percent_compliance(total_crits, overdue_crits)
        percent_compliance_highs = get_percent_compliance(total_highs, overdue_highs)
        percent_compliance_medium = get_percent_compliance(total_medium, overdue_medium)
        percent_compliance_low = get_percent_compliance(total_low, overdue_low)
        vulns_list.append([org['organizations_uid'], org['cyhy_db_name'], percent_compliance_crits, percent_compliance_highs, percent_compliance_medium, percent_compliance_low])
    df_was_vulns = pd.DataFrame(vulns_list, columns= ["organizations_uid", "cyhy_db_name", "percent_compliance_crits", "percent_compliance_highs", "percent_compliance_meds", "percent_compliance_lows"])
    
    was_crits_compl = df_was_vulns['percent_compliance_crits'].mean()
    was_highs_compl = df_was_vulns['percent_compliance_highs'].mean()
    was_meds_compl = df_was_vulns['percent_compliance_meds'].mean()
    was_lows_compl = df_was_vulns['percent_compliance_lows'].mean()
    for index, org in vs_orgs_df.iterrows():
        vulns_list.append([org['organizations_uid'], org['cyhy_db_name'], was_crits_compl, was_highs_compl, was_meds_compl, was_lows_compl])
    df_vulns = pd.DataFrame(vulns_list, columns= ["organizations_uid", "cyhy_db_name", "percent_compliance_crits", "percent_compliance_highs", "percent_compliance_meds", "percent_compliance_lows"])
    return df_vulns

def summarize_was_attr(orgs_df, this_month, next_month):
    was_orgs = get_was_stakeholders()
    was_ids = was_orgs['cyhy_db_name'].values
    conditions = [orgs_df['cyhy_db_name'].isin(was_ids), ~orgs_df['cyhy_db_name'].isin(was_ids)]
    was_customer = ["Yes", "No"]
    orgs_df["was_org"] = np.select(conditions, was_customer)
    was_orgs_df = orgs_df.loc[orgs_df['was_org'] == "Yes"]
    vs_orgs_df = orgs_df.loc[orgs_df['was_org'] == "No"]
    org_list = orgs_df['cyhy_db_name'].values.tolist()
    df_closed_vulns = get_was_closed_vulns(this_month, next_month, org_list)
    average_time_to_remediate_list = []
    for index, org in was_orgs_df.iterrows():
        org_crits = []
        org_highs = []
        for index2, vuln in df_closed_vulns.iterrows():
            if org['organizations_uid'] == vuln['organizations_uid'] or org['organizations_uid'] == vuln['parent_org_uid']:
                time_to_remediate = get_age(vuln['first_detected'], vuln['last_detected'])
                if vuln['base_score'] >= 9.0:
                    org_crits.append(time_to_remediate)
                if vuln['base_score'] >= 7.0 and vuln['cvss_base_score'] < 9.0:
                    org_highs.append(time_to_remediate)
        average_crits = average_list(org_crits)
        average_highs = average_list(org_highs)
        average_time_to_remediate_list.append([org['organizations_uid'], org['cyhy_db_name'], average_crits, average_highs, calculate_attr_compliance(average_crits, "CRIT"), calculate_attr_compliance(average_highs, "HIGH")])
    was_df_attr = pd.DataFrame(average_time_to_remediate_list, columns= ["organizations_uid", "cyhy_db_name", "attr_crits", "attr_highs", "attr_compl_crits", "attr_compl_highs"])
    
    attr_crtis = was_df_attr['attr_crits'].mean()
    attr_highs = was_df_attr['attr_highs'].mean()
    for index, org in vs_orgs_df.iterrows():
        average_time_to_remediate_list.append([org['organizations_uid'], org['cyhy_db_name'], attr_crtis, attr_highs, calculate_attr_compliance(attr_crtis, "CRIT"), calculate_attr_compliance(attr_highs, "HIGH")])
    df_attr = pd.DataFrame(average_time_to_remediate_list, columns= ["organizations_uid", "cyhy_db_name", "attr_crits", "attr_highs", "attr_compl_crits", "attr_compl_highs"])
    return df_attr

def normalize_port_scans(df_ports):
    port_list = []
    for index, org in df_ports.iterrows():
        ports_max = float(df_ports['change_in_ports'].max())
        ports_min = float(df_ports['change_in_ports'].min())
        protocols_max = float(df_ports['change_in_protocols'].max())
        protocols_min = float(df_ports['change_in_protocols'].min())

        norm_ports = 0.0
        norm_protocols = 0.0
        
        if ports_max == 0.0 or ports_max - ports_min == 0.0:
            norm_ports = 75.0
        else:
            norm_ports = ((org['change_in_ports'] - ports_min) / (ports_max - ports_min)) * 100.0

        if protocols_max == 0.0 or protocols_max - protocols_min == 0.0:
            norm_protocols = 75.0
        else:
            norm_protocols = ((org['change_in_protocols'] - protocols_min) / (protocols_max - protocols_min)) * 100.0

        norm_services = 100.0

        port_list.append([org['organizations_uid'], norm_ports, norm_protocols, norm_services])
    df_vulns = pd.DataFrame(port_list, columns= ["organizations_uid", "norm_ports", "norm_protocols", "norm_services"])   
    return df_vulns
    
def summarize_port_scans(orgs_df, last_month, this_month, next_month):
    org_list = orgs_df['organizations_uid'].values.tolist()
    df_port_scans = df_port_scans = get_ports_protocols(last_month, next_month, org_list)
    port_scans_list = []
    for index, org in orgs_df.iterrows():
        last_month_total_ports = 0.0
        last_month_vuln_ports = 0.0
        last_month_total_protocols = 0.0
        last_month_vuln_protocols = 0.0
        this_month_total_ports = 0.0
        this_month_vuln_ports = 0.0
        this_month_total_protocols = 0.0
        this_month_vuln_protocols = 0.0
        for index2, ports in df_port_scans.iterrows():
            if org['organizations_uid'] == ports['organizations_uid'] or org['organizations_uid'] == ports['parent_org_uid']:
                if ports['report_period'] < this_month:
                    last_month_total_ports = last_month_total_ports + ports['ports']
                    last_month_vuln_ports = last_month_vuln_ports + ports['risky_ports']
                    last_month_total_protocols = last_month_total_protocols + ports['protocols']
                    last_month_vuln_protocols = last_month_vuln_protocols + ports['risky_protocols']
                else:
                    this_month_total_ports = this_month_total_ports + ports['ports']
                    this_month_vuln_ports = this_month_vuln_ports + ports['risky_ports']
                    this_month_total_protocols = this_month_total_protocols + ports['protocols']
                    this_month_vuln_protocols = this_month_vuln_protocols + ports['risky_protocols']

        change_in_ports = average_numbers(this_month_vuln_ports, this_month_total_ports) - average_numbers(last_month_vuln_ports, last_month_total_ports)
        change_in_protocols = average_numbers(this_month_vuln_protocols, this_month_total_protocols) - average_numbers(last_month_vuln_protocols, last_month_total_protocols)
        
        port_scans_list.append([org['organizations_uid'], org['cyhy_db_name'], change_in_ports, change_in_protocols])
    df_port_scans = pd.DataFrame(port_scans_list, columns= ["organizations_uid", "cyhy_db_name", "change_in_ports", "change_in_protocols"])
    return df_port_scans

def normalize_vulns(df_vulns, team):
    vulns_list = []
    for index, org in df_vulns.iterrows():

        kevs_max = 0.0
        kevs_min = 0.0
        if team != "WAS":
            kevs_max = float(df_vulns['change_in_kevs'].max())
            kevs_min = float(df_vulns['change_in_kevs'].min())
        crits_max = float(df_vulns['change_in_crits'].max())
        crits_min = float(df_vulns['change_in_crits'].min())
        highs_max = float(df_vulns['change_in_highs'].max())
        highs_min = float(df_vulns['change_in_highs'].min())
        meds_max = float(df_vulns['change_in_meds'].max())
        meds_min = float(df_vulns['change_in_meds'].min())
        lows_max = float(df_vulns['change_in_lows'].max())
        lows_min = float(df_vulns['change_in_lows'].min())

        norm_kevs = 0.0
        if team != "WAS":
            if kevs_max == 0.0 or kevs_max - kevs_min == 0.0:
                norm_kevs = 75.0
            else:
                norm_kevs = ((org['change_in_kevs'] - kevs_min) / (kevs_max - kevs_min)) * 100
        else:
            norm_kevs = "N/A"

        norm_crits = 0.0
        if crits_max == 0.0 or crits_max - crits_min == 0.0:
            norm_crits = 75.0 
        else:
            norm_crits = ((org['change_in_crits'] - crits_min) / (crits_max - crits_min)) * 100.0

        norm_highs = 0.0
        if highs_max == 0.0 or highs_max - highs_min == 0.0:
            norm_highs = 75.0
        else:
            norm_highs = ((org['change_in_highs'] - highs_min) / (highs_max - highs_min)) * 100.0

        norm_meds = 0.0
        if meds_max == 0.0 or meds_max - meds_min == 0.0:
            norm_meds = 75.0
        else:
            norm_meds = ((org['change_in_meds'] - meds_min) / (meds_max - meds_min)) * 100.0

        norm_lows = 0.0
        if lows_max == 0.0 or lows_max - lows_min == 0.0:
            norm_lows = 75.0
        else:
            norm_lows = (org['change_in_lows'] - lows_min) / (lows_max - lows_min)

        vulns_list.append([org['organizations_uid'], norm_kevs, norm_crits, norm_highs, norm_meds, norm_lows])
    df_vulns = pd.DataFrame(vulns_list, columns= ["organizations_uid", "norm_kevs", "norm_crits", "norm_highs", "norm_meds", "norm_lows"])   
    return df_vulns

