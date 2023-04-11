"""Calculate the average time to remediate for all orgs."""
# Standard Python Libraries
import logging

# Third-Party Libraries
import pandas as pd
import psycopg2

# cisagov Libraries
# from .config import config, staging_config
from pe_reports.data.cyhy_db_query import pe_db_staging_connect as connect
from pe_reports.data.cyhy_db_query import query_pe_orgs as get_orgs

# from pe_reports.data.db_query import (
#     connect,
#     close,
#     get_orgs
# )

LOGGER = logging.getLogger(__name__)


def calculate_time_to_remediate(start_date, end_date):
    """Calculate the time to remediate for all orgs."""
    conn = connect()
    orgs_df = get_orgs(conn)
    tickets_df = get_tickets(start_date, end_date)
    kevs_df = get_kevs()

    fceb_kevs = []
    fceb_crits = []
    fceb_highs = []

    average_time_to_remediate_list = []
    for index, org in orgs_df.iterrows():
        org_kevs = []
        org_crits = []
        org_highs = []
        for index2, ticket in tickets_df.iterrows():
            if org["cyhy_db_name"] == ticket["cyhy_db_name"]:
                time_opened = ticket["time_opened"]
                time_closed = ticket["time_closed"]
                time_to_remediate = get_age(time_opened, time_closed)
                if ticket["cve"] in kevs_df["kev"].values:
                    org_kevs.append(time_to_remediate)
                    fceb_kevs.append(time_to_remediate)
                if ticket["cvss_base_score"] >= 9.0:
                    org_crits.append(time_to_remediate)
                    fceb_crits.append(time_to_remediate)
                if ticket["cvss_base_score"] >= 7.0 and ticket["cvss_base_score"] < 9.0:
                    org_highs.append(time_to_remediate)
                    fceb_highs.append(time_to_remediate)

        average_kevs = average_list(org_kevs)
        average_crits = average_list(org_crits)
        average_highs = average_list(org_highs)
        average_time_to_remediate_list.append(
            [org["cyhy_db_name"], average_kevs, average_crits, average_highs]
        )

    average_fceb_kevs = average_list(fceb_kevs)
    average_fceb_crits = average_list(fceb_crits)
    average_fceb_highs = average_list(fceb_highs)
    fceb_results = {
        "name": "FCEB",
        "ATTR KEVs": average_fceb_kevs,
        "ATTR Crits": average_fceb_crits,
        "ATTR Highs": average_fceb_highs,
    }
    # average_time_to_remediate_list.append(["FCEB", average_fceb_kevs, average_fceb_crits, average_fceb_highs])
    df_attr = pd.DataFrame(
        average_time_to_remediate_list,
        columns=["cyhy_db_name", "ATTR KEVs", "ATTR Crits", "ATTR Highs"],
    )
    return (df_attr, fceb_results)


def average_list(list):
    """Average a list of numbers."""
    if len(list) == 0:
        return None
    else:
        return round(sum(list) / len(list), 2)


def get_age(start_time, end_time):
    """Calculate the age between two timestamps."""
    # if "." in end_time:
    #     end_time = end_time.split(".")[0]
    # if "." in start_time:
    #     start_time = start_time.split(".")[0]
    # end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    # start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
    age = round((float((end_time - start_time).total_seconds()) / 60 / 60 / 24), 2)
    return age


def get_tickets(start_date, end_date):
    """Query cyhy tickets between two dates."""
    conn = connect()
    try:
        sql = """select o.cyhy_db_name, o.fceb, o.report_on, ct.cvss_base_score, ct.cve, ct.time_opened, ct.time_closed
        from cyhy_tickets ct
        left join organizations o on
        o.organizations_uid = ct.organizations_uid
        where ct.false_positive = 'False' and ct.time_closed >= %(start_date)s and ct.time_closed < %(end_date)s and o.fceb = 'True'"""
        tickets_df = pd.read_sql(
            sql, conn, params={"start_date": start_date, "end_date": end_date}
        )
        return tickets_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            conn.close()


def get_kevs():
    """Query all the kevs from the database."""
    conn = connect()
    try:
        sql = """select kev from cyhy_kevs"""
        kevs_df = pd.read_sql(sql, conn)
        return kevs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            conn.close
