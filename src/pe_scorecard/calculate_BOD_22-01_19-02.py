"""Calculate BOD-22-01 data."""
# Standard Python Libraries
from datetime import datetime, timezone
import logging

# Third-Party Libraries
# import numpy as np
import pandas as pd
import psycopg2

# cisagov Libraries
# from .config import config, staging_config
from pe_reports.data.db_query import close, connect

# from pe_reports.data.cyhy_db_query import pe_db_staging_connect as connect


# from psycopg2 import OperationalError
# from psycopg2.extensions import AsIs
# import psycopg2.extras as extras
# from sshtunnel import SSHTunnelForwarder


LOGGER = logging.getLogger(__name__)


def calculate_2201_1902_bod_compliance():
    """Run calculations to identify BOD compliance."""
    orgs_df = get_orgs()
    open_tickets_df = get_open_tickets()
    kevs_df = get_kevs()

    average_time_to_remediate_list = []
    for index, org in orgs_df.iterrows():
        total_kevs = 0
        overdue_kevs = 0
        total_crits = 0
        overdue_crits = 0
        total_highs = 0
        overdue_highs = 0
        for index2, ticket in open_tickets_df.iterrows():
            if org["cyhy_db_name"] == ticket["cyhy_db_name"]:
                time_opened = ticket["time_opened"]
                now = datetime.now()
                age = get_age(time_opened, now)
                if ticket["cve"] in kevs_df["kev"].values:
                    total_kevs = total_kevs + 1
                    if age > 14.0:
                        overdue_kevs = overdue_kevs + 1
                if ticket["cvss_base_score"] >= 9.0:
                    total_crits = total_crits + 1
                    if age > 15.0:
                        overdue_crits = overdue_crits + 1
                if ticket["cvss_base_score"] >= 7.0 and ticket["cvss_base_score"] < 9.0:
                    total_highs = total_highs + 1
                    if age > 30.0:
                        overdue_highs = overdue_highs + 1
        percent_compliance_kevs = get_percent_compliance(total_kevs, overdue_kevs)
        percent_compliance_crits = get_percent_compliance(total_crits, overdue_crits)
        percent_compliance_highs = get_percent_compliance(total_highs, overdue_highs)
        average_time_to_remediate_list.append(
            [
                org["cyhy_db_name"],
                percent_compliance_kevs,
                percent_compliance_crits,
                percent_compliance_highs,
            ]
        )

    df_attr = pd.DataFrame(
        average_time_to_remediate_list,
        columns=[
            "cyhy_db_name",
            "BOD 22-01 Compliance",
            "BOD 19-02 Critical Compliance",
            "BOD 19-02 High Compliance",
        ],
    )
    df_attr.to_csv("bod-2201.csv")
    print(df_attr.values)


def get_percent_compliance(total, overdue):
    """Calculate percentage of compliance."""
    if total == 0:
        return 100.0
    else:
        return round(((total - overdue) / total) * 100, 2)


def get_age(start_time, end_time):
    """Identify age of open vulnerability."""
    # if "." in start_time:
    #     start_time = start_time.split(".")[0]
    # start_time = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
    start_time = start_time.timestamp()
    start_time = datetime.fromtimestamp(start_time, timezone.utc)
    start_time = start_time.replace(tzinfo=None)
    end_time = end_time.timestamp()
    end_time = datetime.fromtimestamp(end_time, timezone.utc)
    end_time = end_time.replace(tzinfo=None)
    age = round((float((end_time - start_time).total_seconds()) / 60 / 60 / 24), 2)
    return age


def get_orgs():
    """Get orgs to analyze time since open."""
    conn = connect()
    try:
        sql = """select cyhy_db_name, fceb
        from organizations o
        where fceb = 'True'"""
        orgs_df = pd.read_sql(sql, conn)
        return orgs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_open_tickets():
    """Get open vulnerability tickets."""
    conn = connect()
    try:
        sql = """select o.cyhy_db_name, o.fceb, ct.cvss_base_score, ct.cve, ct.time_opened, ct.time_closed
        from cyhy_tickets ct
        left join organizations o on
        o.organizations_uid = ct.organizations_uid
        where ct.false_positive = False and ct.time_closed is Null and o.fceb = True and (ct.cve != null or (ct.cvss_base_score != 'Nan' and ct.cvss_base_score >= 7.0))"""
        open_tickets_df = pd.read_sql(sql, conn)
        return open_tickets_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


def get_kevs():
    """Query all active KEVs."""
    conn = connect()
    try:
        sql = """select kev from cyhy_kevs"""
        kevs_df = pd.read_sql(sql, conn)
        return kevs_df
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)
