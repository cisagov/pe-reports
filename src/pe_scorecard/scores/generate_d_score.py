"""A file containing the Discovery Score (D-Score) algorithm, version 1.0."""
# Standard Python Libraries
import sys
import os
import datetime
import time

# Third-Party Libraries
import numpy as np
import pandas as pd

# Help python find db_query file
sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

# cisagov Libraries
from score_helper_functions import rescale, get_prev_startstop

from pe_scorecard.data.db_query import (
    #    # VS queries
    query_dscore_vs_data_cert,
    query_dscore_vs_data_mail,
    #    # PE queries
    query_dscore_pe_data_ip,
    query_dscore_pe_data_domain,
    #    # WAS queries
    query_dscore_was_data_webapp,
    #    # Stakeholder lists by sector
    query_fceb_parent_list,
    query_xs_stakeholder_list,
    query_s_stakeholder_list,
    query_m_stakeholder_list,
    query_l_stakeholder_list,
    query_xl_stakeholder_list,
)


# ---------- Misc. Helper Functions ----------
# Helper functions that assist in the calculation of this
# score are stored in the "score_helper_functions.py" file

# ---------- Data Import Function ----------
def import_discov_data(curr_start, curr_end):
    """
    Retrieve all data required for calculating discovery score.

    Args:
        curr_start: start date of current report period
        curr_end: end date of current report period

    Returns:
        A single dataframe containing all data necessary for Discovery Score calculation.
    """
    # --------------- Import Team Data from Database: ---------------
    # Retrieve all the data needed from the database
    # ----- Retrieve VS data: -----
    print("Retrieving VS certificate data for D-Score...")
    # vs_data_cert = query_dscore_vs_data_cert()
    print("\tDone!")
    print("Retrieving VS mail data for D-Score...")
    # vs_data_mail = query_dscore_vs_data_mail()
    print("\tDone!")
    # ----- Retrieve PE data: -----
    print("Retrieving PE IP data for D-Score...")
    # pe_data_ip = query_dscore_pe_data_ip()
    print("\tDone!")
    print("Retrieving PE domain data for D-Score...")
    # pe_data_domain = query_dscore_pe_data_domain()
    print("\tDone!")
    # ----- Retrieve WAS data: -----
    print("Retrieving WAS domain data for D-Score...")
    # pe_data_domain = query_dscore_pe_data_domain()
    print("\tDone!")

    # --------------- Import Other Data from Database: ---------------
    # Retrieve any other necessary data from the database
    # ----- Retrieve full FCEB list: -----
    print("Retrieving FCEB parent stakeholder list for D-Score...")
    # fceb_list = query_fceb_parent_list()
    print("\tDone!")

    # TEMPORARY TESTING:
    vs_data_cert = pd.read_csv("dscore_vs_cert_2023-04-20.csv")
    vs_data_mail = pd.read_csv("dscore_vs_mail_2023-04-20.csv")
    pe_data_ip = pd.read_csv("dscore_pe_ip_2023-04-20.csv")
    pe_data_domain = pd.read_csv("dscore_pe_domain_2023-04-20.csv")
    was_data_webapp = pd.read_csv("dscore_was_webapp_2023-04-20.csv")
    fceb_parent_list = pd.read_csv("Full_FCEB_List.csv")

    # --------------- Process VS Data: ---------------
    # Requires 2 Views:
    # - certificate data: vw_dscore_vs_cert
    # - mail dmarc/spf data: vw_dscore_vs_mail
    # ----- VS Certificate Data -----
    # Calculate percent monitored
    vs_data_cert["percent_monitor_cert"] = 0
    # Catch divide by zero (0 identified)
    vs_data_cert.loc[vs_data_cert["num_ident_cert"] == 0, "percent_monitor_cert"] = 100
    # Otherwise, calculate percentage
    vs_data_cert.loc[vs_data_cert["num_ident_cert"] != 0, "percent_monitor_cert"] = (
        vs_data_cert["num_monitor_cert"] / vs_data_cert["num_ident_cert"]
    ) * 100

    # ----- VS Mail Data -----
    # Calculate percent monitored
    vs_data_mail["percent_secure_mail"] = 0
    # Catch divide by zero (0 identified)
    vs_data_mail.loc[
        vs_data_mail["total_mail_domains"] == 0, "percent_secure_mail"
    ] = 100
    # Otherwise, calculate percentage
    vs_data_mail.loc[vs_data_mail["total_mail_domains"] != 0, "percent_secure_mail"] = (
        vs_data_mail["num_valid_dmarc_or_spf"] / vs_data_mail["total_mail_domains"]
    ) * 100

    # --------------- Process PE Data: ---------------
    # Requires 2 Views:
    # - ip data: vw_dscore_pe_ip
    # - domain data: vw_dscore_pe_domain
    # ----- PE IP Data -----
    # Calculate percent monitored
    pe_data_ip["percent_monitor_ip"] = 0
    # Catch divide by zero (0 identified)
    pe_data_ip.loc[pe_data_ip["num_ident_ip"] == 0, "percent_monitor_ip"] = 100
    # Otherwise, calculate percentage
    pe_data_ip.loc[pe_data_ip["num_ident_ip"] != 0, "percent_monitor_ip"] = (
        pe_data_ip["num_monitor_ip"] / pe_data_ip["num_ident_ip"]
    ) * 100

    # ----- PE Domain Data -----
    # Calculate percent monitored
    pe_data_domain["percent_monitor_domain"] = 0
    # Catch divide by zero (0 identified)
    pe_data_domain.loc[
        pe_data_domain["num_ident_domain"] == 0, "percent_monitor_domain"
    ] = 100
    # Otherwise, calculate percentage
    pe_data_domain.loc[
        pe_data_domain["num_ident_domain"] != 0, "percent_monitor_domain"
    ] = (
        pe_data_domain["num_monitor_domain"] / pe_data_domain["num_ident_domain"]
    ) * 100

    # --------------- Process WAS Data: ---------------
    # Requires 1 Views:
    # - webapp data: vw_dscore_was_webapp
    # Calculate percent monitored
    was_data_webapp["percent_monitor_webapp"] = 0
    # Catch divide by zero (0 identified)
    was_data_webapp.loc[
        was_data_webapp["num_ident_webapp"] == 0, "percent_monitor_webapp"
    ] = 100
    # Otherwise, calculate percentage
    was_data_webapp.loc[
        was_data_webapp["num_ident_webapp"] != 0, "percent_monitor_webapp"
    ] = (
        was_data_webapp["num_monitor_webapp"] / was_data_webapp["num_ident_webapp"]
    ) * 100

    # --------------- Combine All Team Data: ---------------
    # Combining all team data into a single dataframe
    discov_data_df = pd.merge(
        pd.merge(
            pd.merge(
                pd.merge(
                    pd.merge(
                        fceb_parent_list,
                        vs_data_cert,
                        on="organizations_uid",
                        how="inner",
                    ),
                    vs_data_mail,
                    on="organizations_uid",
                    how="inner",
                ),
                pe_data_ip,
                on="organizations_uid",
                how="inner",
            ),
            pe_data_domain,
            on="organizations_uid",
            how="inner",
        ),
        was_data_webapp,
        on="organizations_uid",
        how="inner",
    )

    # Return dataframe containing all
    # data needed for discovery score
    return discov_data_df


# ---------- Calculate D-Score Function ----------
def calc_discov_scores(discov_data, stakeholder_list):
    """
    Calculate Discovery Scores for the specified stakeholder list.

    Args:
        discov_data: The full dataframe of D-Score data for all FCEB stakeholders
        stakeholder_list: The specific list of orgs that you want to generate D-Scores for
    Returns:
        Dataframe containing D-Score and letter grade for each org in the specified stakeholder list
    """

    # Cut down dataframe to only include data for the specified stakeholder list
    discov_data_df = pd.merge(
        stakeholder_list,
        discov_data,
        on=["organizations_uid", "cyhy_db_name"],
        how="left",
    )

    # Impute column means to use for filling in missing data later
    vs_mail_col_means = discov_data_df.iloc[:, 5:10].mean()
    # pe_namserv_col_means = discov_data_df.iloc[:, #:#].mean()

    # ---------- VS-Subscribed Data ----------
    # Index locations of VS metrics
    vs_cert_locs = list(range(2, 5))
    vs_mail_locs = list(range(5, 10))

    # VS Mail Feature:
    # Penalty amount for VS mail feature
    vs_mail_penalty = 0.2
    # Apply penalty to any organizations whose mail security percent is < 90%
    discov_data_df.loc[
        discov_data_df["percent_secure_mail"] < 90, "percent_secure_mail"
    ] = discov_data_df["percent_secure_mail"] * (1 - vs_mail_penalty)

    # ---------- PE-Subscribed Data ----------
    # Index locations of PE metrics
    pe_ip_locs = list(range(10, 13))
    pe_domain_locs = list(range(13, 16))

    # PE Nameserver Feature:
    # Nameserver data not yet available, but
    # would apply penalties for the following
    # - Only 1 nameserver ISP
    # - Only 1 nameserver domain
    # - Only 1 nameserver geolocation

    # ---------- WAS-Subscribed Data ----------
    # Index locations of WAS metrics
    was_webapp_locs = list(range(16, 19))

    # Feature?:

    # ---------- Impute Missing Data ----------
    # Use these column means calculated earlier to fill any missing data due to partial subscriptions
    # Filling VS mail data:
    discov_data_df.loc[
        discov_data_df["total_mail_domains"].isnull(),
        [
            "num_valid_dmarc",
            "num_valid_spf",
            "num_valid_dmarc_or_spf",
            "total_mail_domains",
            "percent_secure_mail",
        ],
    ] = vs_mail_col_means.values

    # Filling PE nameserver data:

    # ---------- Aggregate Metrics ----------
    # Notes:
    # - VS cert percent monitor = want to minimize (higher/over 100 is actually bad)
    # - VS mail data = want to maximize (more mail security  = good)
    # - PE ip percent monitor = want to minimize (higher/over 100 is actually bad)
    # - PE domain percent monitor = want to minimize (higher/over 100 is actually bad)
    # - WAS webapp percent monitor = want to minimize (higher/over 100 is actually bad)
    # indicies of core percent monitored metrics
    # - 4, 12, 15, 18

    # Rescaling metrics 0-45 for final aggregation
    for col_idx in range(2, 19):
        discov_data_df.iloc[:, col_idx] = rescale(
            discov_data_df.iloc[:, col_idx], 45, 0
        )

    # Inverting VS mail metrics for aggregation (we want to maximize them)
    discov_data_df.iloc[:, vs_mail_locs] = 45 - discov_data_df.iloc[:, vs_mail_locs]

    # If there are still NA's remaining in the data at this point,
    # then that means one of the cyhy teams has absolutely 0 subscribers
    # In this case, force completely missing team data to be 11.25
    # which is the equivalent of getting a 75% for a team section (C)
    discov_data_df.fillna(11.25, inplace=True)

    # Combine metrics into subsection totals
    # VS Subsections:
    discov_data_df["vs_monitor_subsection"] = (
        discov_data_df["percent_monitor_cert"] * 1.00
    )
    discov_data_df["vs_mail_subsection"] = discov_data_df["percent_secure_mail"] * 1.00
    # PE Subsections:
    discov_data_df["pe_monitor_subsection"] = (
        discov_data_df["percent_monitor_ip"] * 0.5
    ) + (discov_data_df["percent_monitor_domain"] * 0.5)
    # WAS Subsections:
    discov_data_df["was_monitor_subsection"] = (
        discov_data_df["percent_monitor_webapp"] * 1.00
    )

    # Combine subsections into team sections
    # VS Section:
    discov_data_df["vs_section"] = (discov_data_df["vs_monitor_subsection"] * 0.6) + (
        discov_data_df["vs_mail_subsection"] * 0.4
    )
    # PE Section:
    discov_data_df["pe_section"] = discov_data_df["pe_monitor_subsection"] * 1.00
    # WAS Section:
    discov_data_df["was_section"] = discov_data_df["was_monitor_subsection"] * 1.0

    # Combine team sections into single value
    discov_data_df["discov_score"] = (
        (discov_data_df["vs_section"] * 0.30)
        + (discov_data_df["pe_section"] * 0.40)
        + (discov_data_df["was_section"] * 0.30)
    )

    # Take complement of that single value
    discov_data_df["discov_score"] = (
        (100 - discov_data_df["discov_score"]).astype(float).round(2)
    )
    discov_data_df = discov_data_df.sort_values(
        by="discov_score", ascending=False
    ).reset_index(drop=True)

    # Convert to letter grade
    letter_ranges = [
        discov_data_df["discov_score"] < 65,  # F
        (discov_data_df["discov_score"] >= 65)
        & (discov_data_df["discov_score"] < 67),  # D
        (discov_data_df["discov_score"] >= 67)
        & (discov_data_df["discov_score"] < 70),  # D+
        (discov_data_df["discov_score"] >= 70)
        & (discov_data_df["discov_score"] < 73),  # C-
        (discov_data_df["discov_score"] >= 73)
        & (discov_data_df["discov_score"] < 77),  # C
        (discov_data_df["discov_score"] >= 77)
        & (discov_data_df["discov_score"] < 80),  # C+
        (discov_data_df["discov_score"] >= 80)
        & (discov_data_df["discov_score"] < 83),  # B-
        (discov_data_df["discov_score"] >= 83)
        & (discov_data_df["discov_score"] < 87),  # B
        (discov_data_df["discov_score"] >= 87)
        & (discov_data_df["discov_score"] < 90),  # B+
        (discov_data_df["discov_score"] >= 90)
        & (discov_data_df["discov_score"] < 93),  # A-
        (discov_data_df["discov_score"] >= 93)
        & (discov_data_df["discov_score"] < 97),  # A
        (discov_data_df["discov_score"] >= 97)
        & (discov_data_df["discov_score"] <= 100),  # A+
    ]
    letter_grades = ["F", "D", "D+", "C-", "C", "C+", "B-", "B", "B+", "A-", "A", "A+"]
    discov_data_df["letter_grade"] = np.select(letter_ranges, letter_grades)

    # Isolate final D-Score score data
    discov_data_df = discov_data_df[["cyhy_db_name", "discov_score", "letter_grade"]]

    # Return finished discovery score dataframe
    return discov_data_df


def gen_discov_scores(curr_date):
    """
    Generate the Discovery Scores for each of the stakeholder sector groups.

    Args:
        curr_date: current report period date (i.e. 2022-08-15)
    Returns:
        List of dataframes containing the D-Scores/letter grades for each stakeholder sector group
    """
    # Calculate start/end dates of current and previous report periods
    report_periods = get_prev_startstop(curr_date, 2)
    [curr_start, curr_end] = [report_periods[0][0], report_periods[1][1]]

    # Retrieve the necessary Discovery Score data for all FCEB orgs
    discov_data_df = import_discov_data(curr_start, curr_end)

    # Get Stakeholder Sector Lists:
    # xs_fceb = query_xs_stakeholder_list()
    # s_fceb = query_s_stakeholder_list()
    # m_fceb = query_m_stakeholder_list()
    # l_fceb = query_l_stakeholder_list()
    # xl_fceb = query_xl_stakeholder_list()
    # TEMPORARY
    xs_fceb = pd.read_csv("xs_fceb_orgs.csv")
    s_fceb = pd.read_csv("s_fceb_orgs.csv")
    m_fceb = pd.read_csv("m_fceb_orgs.csv")
    l_fceb = pd.read_csv("l_fceb_orgs.csv")
    xl_fceb = pd.read_csv("xl_fceb_orgs.csv")
    sector_lists = [
        xs_fceb,
        s_fceb,
        m_fceb,
        l_fceb,
        xl_fceb,
    ]

    # Empty list to hold d-score dataframes for each sector group
    dscore_dfs = []
    sector_counter = 1

    # For each sector group, calculate d-scores
    for sector_list in sector_lists:
        curr_dscores = calc_discov_scores(discov_data_df, sector_list)
        dscore_dfs.append(curr_dscores)
        print(
            f"Calculated D-Scores for {sector_counter} / {len(sector_lists)} Sectors..."
        )
        sector_counter += 1

    # Return list of finished d-score dataframes
    return dscore_dfs


# DEMO:
# Total Runtime ~= 6min 30sec
# - VS cert query ~= 1sec
# - VS mail query ~= 25sec
# - PE IP query ~= 6min <-- major slow down
# - PE domain query ~= 1sec
# - WAS webapp query ~= 1sec
# - Actual calculation of scores ~=1sec

# Testing Staging DB Connection
# test = query_dscore_vs_data_cert()
# print(test)
# x = 5 / 0

# Current report period date (end of month)
curr_date = datetime.datetime(2022, 11, 30)

# Start Timer
start_time = time.time()

# Run D-Score Algorithm
results = gen_discov_scores(curr_date)

# Stop Timer
d_scores_time = time.time() - start_time

for result in results:
    print(result)

print("All group's d-scores calculated: %s seconds" % d_scores_time)
