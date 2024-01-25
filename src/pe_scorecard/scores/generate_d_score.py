"""A file containing the Discovery Score (D-Score) algorithm, version 1.0."""
# Standard Python Libraries
import logging
import os
import sys

# Third-Party Libraries
import numpy as np
import pandas as pd

# cisagov Libraries
from pe_scorecard.data.db_query import (  # VS queries; PE queries; WAS queries; FCEB Stakeholder sectors by size
    dscore_pe_domain,
    dscore_pe_ip,
    dscore_vs_cert,
    dscore_vs_mail,
    dscore_was_webapp,
    fceb_status,
)

# l_stakeholders,
# m_stakeholders,
# s_stakeholders,
# xl_stakeholders,
# xs_stakeholders,
from pe_scorecard.scores.score_helper_functions import (
    get_prev_startstop,
    rescale,
    split_parent_child_records,
)

# Help python find db_query file
sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

# Setup logging to central file
LOGGER = logging.getLogger(__name__)


# ---------- Misc. Helper Functions ----------
# Helper functions that assist in the calculation of this
# score are stored in the "score_helper_functions.py" file


# ---------- Data Import Function ----------
def import_discov_data(curr_start, curr_end, stakeholder_list):
    """
    Retrieve all data required for calculating discovery score.

    Args:
        curr_start: start date of current report period
        curr_end: end date of current report period
        stakeholder_list: dataframe containing the organizations_uid and cyhy_db_name of all the orgs to generate scores for
    Returns:
        A single dataframe containing all data necessary for Discovery Score calculation.
    """
    # --------------- Import Team Data from Database: ---------------
    # Retrieve all the data needed from the database
    # ----- Retrieve VS data: -----
    LOGGER.info("Retrieving VS certificate data for D-Score...")
    vs_data_cert = dscore_vs_cert(stakeholder_list)
    LOGGER.info("\tDone!")
    LOGGER.info("Retrieving VS mail data for D-Score...")
    vs_data_mail = dscore_vs_mail(stakeholder_list)
    LOGGER.info("\tDone!")
    # ----- Retrieve PE data: -----
    LOGGER.info("Retrieving PE IP data for D-Score...")
    pe_data_ip = dscore_pe_ip(stakeholder_list)
    LOGGER.info("\tDone!")
    LOGGER.info("Retrieving PE domain data for D-Score...")
    pe_data_domain = dscore_pe_domain(stakeholder_list)
    LOGGER.info("\tDone!")
    # ----- Retrieve WAS data: -----
    LOGGER.info("Retrieving WAS domain data for D-Score...")
    was_data_webapp = dscore_was_webapp(stakeholder_list)
    LOGGER.info("\tDone!")

    # --------------- Import Other Data from Database: ---------------
    # Retrieve any other necessary data from the database
    # ----- FCEB status of each org in this sector: -----
    LOGGER.info("Retrieving FCEB status data for D-Score...")
    fceb_status_results = fceb_status(stakeholder_list)
    LOGGER.info("\tDone!")
    # ----- List of orgs for this sector: -----
    org_list = stakeholder_list

    # ---------- Preprocessing for Rollup Support -----------
    # Split parent/child records to support rollup functionality
    vs_data_cert = split_parent_child_records(vs_data_cert)
    vs_data_mail = split_parent_child_records(vs_data_mail)
    pe_data_ip = split_parent_child_records(pe_data_ip)
    pe_data_domain = split_parent_child_records(pe_data_domain)
    was_data_webapp = split_parent_child_records(was_data_webapp)

    # Replace Nones with 0s in vs_data_mail total_mail_domains column
    vs_data_mail["total_mail_domains"].fillna(0, inplace=True)

    # Re-Groupby organizations_uid again to consolidate parent org data
    vs_data_cert = vs_data_cert.groupby("organizations_uid", as_index=False).sum()
    vs_data_mail = vs_data_mail.groupby("organizations_uid", as_index=False).sum()
    pe_data_ip = pe_data_ip.groupby("organizations_uid", as_index=False).sum()
    pe_data_domain = pe_data_domain.groupby("organizations_uid", as_index=False).sum()
    was_data_webapp = was_data_webapp.groupby("organizations_uid", as_index=False).sum()

    # Add FCEB status to organization list
    org_list = pd.merge(
        org_list, fceb_status_results, on="organizations_uid", how="inner"
    )

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
                        org_list,
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
        discov_data: The dataframe of D-Score data for this specific sector
        stakeholder_list: The specific list of orgs that you want to generate D-Scores for
    Returns:
        Dataframe containing D-Score and letter grade for each org in the specified stakeholder list
    """
    discov_data_df = discov_data

    # Impute column means to use for filling in missing data later
    vs_mail_col_means = discov_data_df.iloc[:, 5:10].mean()

    # ---------- VS-Subscribed Data ----------
    # Index locations of VS metrics
    # vs_cert_locs = list(range(3, 6))
    vs_mail_locs = list(range(6, 11))

    # Temporary fix, give 100% score to non-FCEB organizations
    # in the VS certificate (ED 19-01) and VS mail (BOD 18-01) sections
    discov_data_df["percent_monitor_cert"] = np.where(
        discov_data_df["fceb"] == False, 100, discov_data_df["percent_monitor_cert"]
    )
    discov_data_df["percent_secure_mail"] = np.where(
        discov_data_df["fceb"] == False, 100, discov_data_df["percent_secure_mail"]
    )

    # VS Mail Feature:
    # Penalty amount for VS mail feature
    vs_mail_penalty = 0.2
    # Apply penalty to any organizations whose mail security percent is < 90%
    discov_data_df.loc[
        discov_data_df["percent_secure_mail"] < 90, "percent_secure_mail"
    ] = discov_data_df["percent_secure_mail"] * (1 - vs_mail_penalty)

    # ---------- PE-Subscribed Data ----------
    # Index locations of PE metrics
    # pe_ip_locs = list(range(11, 14))
    # pe_domain_locs = list(range(14, 17))

    # PE Nameserver Feature:
    # Nameserver data not yet available, but
    # would apply penalties for the following
    # - Only 1 nameserver ISP
    # - Only 1 nameserver domain
    # - Only 1 nameserver geolocation
    # Will be included in future revisions

    # ---------- WAS-Subscribed Data ----------
    # Index locations of WAS metrics
    # was_webapp_locs = list(range(17, 20))

    # No WAS features yet, but maybe in future revisions

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
    # Rescaling metrics 0-45 for final aggregation
    for col_idx in range(3, 20):
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
    discov_data_df = discov_data_df[
        ["organizations_uid", "cyhy_db_name", "discov_score", "letter_grade"]
    ]

    # Return finished discovery score dataframe
    return discov_data_df


# ---------- Main D-Score Function -----------
def gen_discov_scores(curr_date, stakeholder_list):
    """
    Generate the Discovery Scores for each of the stakeholder sector groups.

    Args:
        curr_date: current report period date (i.e. 20xx-xx-30 or 20xx-xx-31)
        stakeholder_list: dataframe containing the organizations_uid and cyhy_db_name of all the orgs to generate scores for
    Returns:
        List of dataframes containing the D-Scores/letter grades for each stakeholder sector group
    """
    # Calculate start/end dates of current report period
    report_periods = get_prev_startstop(curr_date, 2)
    [curr_start, curr_end] = [report_periods[0][0], report_periods[1][1]]

    # Query D-Score data for this sector
    dscore_data = import_discov_data(curr_start, curr_end, stakeholder_list)

    # Calculate D-Scores for this sector
    dscores = calc_discov_scores(dscore_data, stakeholder_list)
    LOGGER.info(f"Finished calculating D-Scores for {curr_date}")

    # Return datframe of d-scores for the specified sector/report period
    return dscores


# Demo/Performance Notes:

# Usage:
# To get D-Scores, call the function -> gen_discov_score(curr_date, stakeholder_list)
# ex:
#   curr_date = datetime.datetime(2023, 3, 31)
#   xs_fceb = query_xs_stakeholder_list()
#   dscores = gen_discov_score(curr_date, xs_fceb)
#
# This will return a dataframe containing the d-scores for the
# specified list of stakeholders/report period.

# Total Runtime ~= 6min 30sec
# - VS cert query ~= 1sec
# - VS mail query ~= 25sec
# - PE IP query ~= 6min <-- major slow down
# - PE domain query ~= 1sec
# - WAS webapp query ~= 1sec
# - Actual calculation of scores ~=1sec

# Once you have the d-scores, plug that info
# into the dictionary to display on the scorecard
