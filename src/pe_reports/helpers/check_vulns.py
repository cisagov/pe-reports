 import sys
# sys.path.append('Users/stewartc/Documents/GitHub/pe-reports/src/pe_reports/data')
# sys.path.append('Users/stewartc/Documents/GitHub/pe-reports/src/pe_asm/helpers')
# sys.path.append('Users/stewartc/Documents/GitHub/pe-reports/src/pe_reports')
# sys.path.append('Users/stewartc/Documents/GitHub/pe-reports/src/pe_asm')
# sys.path.append('Users/stewartc/Documents/GitHub/pe-reports/src')
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

# from pe_scorecard.data.db_query import (
#     # connect,
#     # close,
#     # get_stakeholders
#     # get_was_stakeholders,
#     # get_hosts,
#     # get_port_scans,
#     # get_was_summary,
#     # get_software
# )

from pe_reports.data.db_query import (
    connect,
    close
)

# from pe_scorecard.scores.score_helper_functions import (
#     get_letter_grade,
#     get_next_month,
#     average_numbers
# )

LOGGER = logging.getLogger(__name__)

def main():
    start_date = datetime(2023, 4, 1, 0, 0, 0, 0)
    end_date = datetime(2023, 6, 1, 0, 0, 0, 0)
    orgs_df = get_stakeholders()
    print(orgs_df)
    # mean_fp = []
    # for index, org in orgs_df.iterrows():
    #     vuln_list = []
    #     vuln_list.append([datetime(2022, 3, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 3, 1, 0, 0, 0, 0), datetime(2022, 4, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2022, 4, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 4, 1, 0, 0, 0, 0), datetime(2022, 5, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2022, 5, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 5, 1, 0, 0, 0, 0), datetime(2022, 6, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2022, 6, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 6, 1, 0, 0, 0, 0), datetime(2022, 7, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2022, 7, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 7, 1, 0, 0, 0, 0), datetime(2022, 8, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2022, 8, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 8, 1, 0, 0, 0, 0), datetime(2022, 9, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2022, 9, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 9, 1, 0, 0, 0, 0), datetime(2022, 10, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2022, 10, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 10, 1, 0, 0, 0, 0), datetime(2022, 11, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2022, 11, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 11, 1, 0, 0, 0, 0), datetime(2022, 12, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2022, 12, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2022, 12, 1, 0, 0, 0, 0), datetime(2023, 1, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2023, 1, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2023, 1, 1, 0, 0, 0, 0), datetime(2023, 2, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2023, 2, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2023, 2, 1, 0, 0, 0, 0), datetime(2023, 3, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     vuln_list.append([datetime(2023, 3, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2023, 3, 1, 0, 0, 0, 0), datetime(2023, 4, 1, 0, 0, 0, 0), org['organizations_uid'])])
    #     # vuln_list.append([datetime(2023, 4, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2023, 4, 1, 0, 0, 0, 0), datetime(2023, 5, 1, 0, 0, 0, 0))])
    #     # vuln_list.append([datetime(2023, 5, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2023, 5, 1, 0, 0, 0, 0), datetime(2023, 6, 1, 0, 0, 0, 0))])
    #     # vuln_list.append([datetime(2023, 6, 1, 0, 0, 0, 0), calculate_fp_perc(datetime(2023, 6, 1, 0, 0, 0, 0), datetime(2023, 7, 1, 0, 0, 0, 0))])

    #     df_vulns = pd.DataFrame(vuln_list, columns = ["Date", "FP_Percent"]) 
    #     org_mean_fp = round((df_vulns['FP_Percent']).mean(), 2)
    #     if org_mean_fp > 0.0:
    #         mean_fp.append([org['organizations_uid'], org_mean_fp]) 

    # df_mean_fp = pd.DataFrame(mean_fp, columns = ["organizations_uid", "org_mean_fp"])

    # print(df_mean_fp)

    vs_vulns = get_all_vs_vulns(start_date, end_date)
    print(vs_vulns)
    

def calculate_fp_perc(start_date, end_date, org_id):
    vs_vulns = get_vs_vulns(start_date, end_date, org_id)
    if vs_vulns is None or vs_vulns.empty:
        return 0
    else:
        vuln_count = len(vs_vulns)
        fp_df = vs_vulns.loc[vs_vulns['false_positive'] == True]
        fp_count = len(fp_df)
        return round(fp_count * 100.0 / vuln_count, 8)




def get_pe_vulns():
    conn = connect()
    try:
        sql = """select sv.organizations_uid, sv.cve, sv.ip,sv.is_verified, sv."timestamp"
        from shodan_vulns sv 
        where sv.cve notnull and sv.cve != 'NaN'
        group by sv.organizations_uid , sv.cve, sv.ip, sv.is_verified, sv."timestamp" """
        pe_vulns_df = pd.read_sql(sql, conn)
        return pe_vulns_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)

def get_vs_vulns(start_date, end_date, org_ids):
    conn = connect()
    try:
        #CHANGE TABLE BACL TO CYHY_TICKETS
        sql = """select ct.organizations_uid, ct.cve, ct.cvss_base_score, ct.ip, ct.false_positive, ct.time_opened
        from cyhy_tickets_temp ct
        where ct.time_opened >= %(start_date)s and ct.time_opened < %(end_date)s and ct.organizations_uid::varchar = %(org_ids)s
        group by ct.organizations_uid, ct.cve, ct.cvss_base_score, ct.false_positive, ct.time_opened"""
        vs_vulns_df = pd.read_sql(sql, conn, params={"start_date": start_date, "end_date": end_date, "org_id": org_ids})
        return vs_vulns_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)

def get_all_vs_vulns(start_date, end_date):
    conn = connect()
    try:
        sql = """select ct.organizations_uid, ct.cve, ct.cvss_base_score, ct.ip, ct.false_positive, ct.time_opened
        from cyhy_tickets ct
        where ct.time_opened >= %(start_date)s and ct.time_opened < %(end_date)s
        group by ct.organizations_uid, ct.cve, ct.cvss_base_score, ct.false_positive, ct.time_opened"""
        vs_vulns_df = pd.read_sql(sql, conn, params={"start_date": start_date, "end_date": end_date})
        return vs_vulns_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)

def get_stakeholders():
    conn = connect()
    try:
        sql = """select organizations_uid, report_on from organizations where retired = False"""
        pe_orgs_df = pd.read_sql(sql, conn)
        return pe_orgs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)



if __name__ == "__main__":
    main()
