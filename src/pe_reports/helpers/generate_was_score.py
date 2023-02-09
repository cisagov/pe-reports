"""A file containing the WAS scoring algorithm, version 1.0."""
# Standard Python Libraries
import calendar
import datetime
import math

# Third-Party Libraries
from dateutil.relativedelta import relativedelta
import numpy as np
import pandas as pd
from retry import retry
from functools import reduce
from scipy.stats import zscore
import requests
import json

# cisagov Libraries
# from pe_reports.data.db_query import get_orgs_df, query_score_data

# VERSION 1.0 of the WAS scoring algorithm, still a WIP

# ---------- Misc. Helper Functions ----------


def get_prev_startstop(curr_date, num_periods):
    """
    Get the start/stop dates for the specified number of preceding report periods, given the current date.
    i.e. If curr_date = 2022-08-15 and num_periods = 3, it'll return: [[7/1, 7/15], [7/16, 7/31], [8/1, 8/15]]
    Args:
        curr_date: current report period date (i.e. 2022-08-15)
        num_periods: number of preceding report periods to calculate (i.e. 15)
    Returns:
        The start and stop dates for the specified number or report periods preceding the current date
    """
    # Array to hold start/stop dates
    start_stops = []
    month_diff = []
    # Calculating month difference array
    for n in range(0, math.ceil(num_periods / 2) + 1):
        month_diff.append(n)
        month_diff.append(n)
    # Calculate start/stop dates
    if curr_date.day == 15:
        month_diff = month_diff[1 : num_periods + 1]
        for i in range(0, num_periods):
            if (i % 2) == 0:
                # Even idx 1 - 15
                start_date = (curr_date + relativedelta(months=-month_diff[i])).replace(
                    day=1
                )
                end_date = curr_date + relativedelta(months=-month_diff[i])
                start_stops.insert(0, [start_date.date(), end_date.date()])
            else:
                # odd idx 16 - 30/31
                start_date = (curr_date + relativedelta(months=-month_diff[i])).replace(
                    day=16
                )
                end_date = curr_date + relativedelta(months=-month_diff[i])
                end_date = end_date.replace(
                    day=calendar.monthrange(end_date.year, end_date.month)[1]
                )
                start_stops.insert(0, [start_date.date(), end_date.date()])
    else:
        month_diff = month_diff[:num_periods]
        for i in range(0, num_periods):
            if (i % 2) == 0:
                # Even idx 16 - 30/31
                start_date = (curr_date + relativedelta(months=-month_diff[i])).replace(
                    day=16
                )
                end_date = curr_date + relativedelta(months=-month_diff[i])
                end_date = end_date.replace(
                    day=calendar.monthrange(end_date.year, end_date.month)[1]
                )
                start_stops.insert(0, [start_date.date(), end_date.date()])
            else:
                # odd idx 1 - 15
                start_date = (curr_date + relativedelta(months=-month_diff[i])).replace(
                    day=1
                )
                end_date = (curr_date + relativedelta(months=-month_diff[i])).replace(
                    day=15
                )
                start_stops.insert(0, [start_date.date(), end_date.date()])
    # Return 2D list of start/stop dates
    return start_stops


def rescale(values, width, offset):
    """
    Rescale Pandas Series of values to the specified width and offset.

    Args:
        values: Pandas Series of values that you want to rescale
        width: The new width of the rescaled values
        offset: The new starting point of the rescaled values
            examples:
            width = 42, offset = 5 results in values from 5-47
            width = 100, offset = -3 results in values from -3-97
    Returns:
        A Pandas Series of the new, re-scaled values
    """
    # Get min/max values
    min_val = values.min()
    max_val = values.max()
    # Catch edge case
    if min_val == 0 and max_val == 0:
        # If all zeros, just return all zeros
        return pd.Series([0] * values.size)
    else:
        # Otherwise, rescale 0-100
        values = ((values - min_val) / (max_val - min_val) * width) + offset
        return values


def import_was_data(curr_start, curr_end):
    """
    Bring in and prep all relevant data from database for WAS score calculation.

    Args:
        curr_start: start date of current report period
        curr_end: end date of current report period

    Returns:
        A single dataframe containing all data necessary for WAS score calculation.
    """
    # ----- MAKE API CALL -----
    # Make call to database API endpoints to get WAS score data
    # API endpoint URLs
    url_was_customer = "http://127.0.0.1:8000/apiv1/was_customer_metrics"
    url_was_findings = "http://127.0.0.1:8000/apiv1/was_finding_metrics"
    # API key
    headers = {
        "Content-Type": "application/json",
        # "access_token": f'{config("API_KEY")}',
        "access_token": "API_KEY",
    }
    # API Token
    payload = json.dumps(
        {
            # "refresh_token": f'{config("USER_REFRESH_TOKEN")}'
            "refresh_token": "USER_REFRESH_TOKEN"
        }
    )
    # Attempt to retrieve WAS customer data
    try:
        was_customer_resp = requests.post(
            url_was_customer, headers=headers, payload=payload
        ).json()
    except Exception as e_customer:
        print("WAS customer API error occured: " + e_customer)
    # Attempt to retrieve WAS finding data
    try:
        was_finding_resp = requests.post(
            url_was_findings, headers=headers, payload=payload
        ).json()
    except Exception as e_finding:
        print("WAS finding API error occured" + e_finding)

    # If API data sucessfully retrieved, convert to dataframe
    was_customer_df = pd.DataFrame(was_customer_resp)
    was_finding_df = pd.DataFrame(was_finding_resp)
    was_customer_df = pd.read_csv("test_customer_data_2023-02-15.csv")
    was_finding_df = pd.read_csv("test_finding_data_2023-02-15.csv")

    # ----- WAS CUSTOMER DATA -----
    # Convert date column to actual datetime.date objects
    was_customer_df["date"] = pd.to_datetime(was_customer_df["date"]).dt.date
    # Reformat API response into was customer dataframe
    was_customer_df = was_customer_df.rename(
        columns={
            "webapp_count": "num_webapp",
            "webapp_active_vuln_count": "num_webapp_vulns",
        }
    )
    was_customer_df = was_customer_df.drop(columns=["date"])

    # ----- WAS FINDING DATA -----
    # Convert date columns to actual datetime.date objects
    was_finding_df[["first_detected", "last_detected", "date"]] = was_finding_df[
        ["first_detected", "last_detected", "date"]
    ].apply(lambda x: pd.to_datetime(x).dt.date)
    # Add remediation time column to finding dataframe
    was_finding_df["remed_time"] = (
        was_finding_df["last_detected"] - was_finding_df["first_detected"]
    ).dt.days
    # Add crit vuln. w/ remed time greater than 30 days column
    was_finding_df["crit_remed_gt30days"] = np.where(
        (was_finding_df["base_score"] >= 9) & (was_finding_df["remed_time"] > 30),
        1,
        0,
    )
    # Add high vuln. w/ remed time greater than 90 days column
    was_finding_df["high_remed_gt90days"] = np.where(
        (was_finding_df["base_score"] >= 7)
        & (was_finding_df["base_score"] < 9)
        & (was_finding_df["remed_time"] > 90),
        1,
        0,
    )
    # Aggreagte API response finding dataframe
    was_finding_df = was_finding_df.groupby(["org_id"], as_index=False).agg(
        num_detected_gt10=("times_detected", (lambda x: (x > 10).sum())),
        # CVSS metrics
        num_cvss_low=("base_score", (lambda x: (x < 4).sum())),
        num_cvss_med=("base_score", (lambda x: ((x >= 4) & (x < 7)).sum())),
        num_cvss_high=("base_score", (lambda x: ((x >= 7) & (x < 9)).sum())),
        num_cvss_crit=("base_score", (lambda x: (x >= 9).sum())),
        max_cvss=("base_score", "max"),
        # OWASP metrics
        num_broken_access_control=(
            "owasp_category",
            (lambda x: (x == "Broken Access Control").sum()),
        ),
        num_crypto_fail=(
            "owasp_category",
            (lambda x: (x == "Cryptographic Failures").sum()),
        ),
        num_injection=("owasp_category", (lambda x: (x == "Injection").sum())),
        num_insec_design=("owasp_category", (lambda x: (x == "Insecure Design").sum())),
        num_sec_misconfig=(
            "owasp_category",
            (lambda x: (x == "Security Misconfiguration").sum()),
        ),
        num_vuln_outdated_comp=(
            "owasp_category",
            (lambda x: (x == "Vulnerable and Outdated Components").sum()),
        ),
        num_ident_auth_fail=(
            "owasp_category",
            (lambda x: (x == "Identification and Authentication Failures").sum()),
        ),
        num_soft_data_integ_fail=(
            "owasp_category",
            (lambda x: (x == "Software and Data Integrity Failures").sum()),
        ),
        num_sec_log_monitor_fail=(
            "owasp_category",
            (lambda x: (x == "Security Logging and Monitoring Failures").sum()),
        ),
        num_ssrf=(
            "owasp_category",
            (lambda x: (x == "Server Side Request Forgery (SSRF)").sum()),
        ),
        # Info Gathered Metrics <-- FIX ODD BEHAVIOR
        num_info_gathered=(
            "finding_type",
            (lambda x: (x == "INFORMATION GATHERED").sum()),
        ),
        num_diag_ig=("finding_type", (lambda x: (x == "DIAGNOSTIC").sum())),
        num_weak_ig=("finding_type", (lambda x: (x == "WEAKNESS").sum())),
        # Remediation Metrics
        avg_remed_time=("remed_time", "mean"),
        num_crit_remed_gt1=("crit_remed_gt30days", "sum"),
        num_high_remed_gt3=("high_remed_gt90days", "sum"),
    )

    # Combine into single dataframe
    was_data_df = pd.merge(
        was_customer_df, was_finding_df, on="org_id", how="left"
    ).fillna(0)

    # TEMP FIX: STAKEHOLDER WITH NO WEBAPPS???
    was_data_df["num_webapp"].mask(was_data_df["num_webapp"] == 0, 1, inplace=True)

    # Return completed dataframe
    return was_data_df


def get_was_scores(curr_date):
    """
    Calculate WAS scores for all orgs that are reported on.

    Args:
        curr_date: current report period date (i.e. 2022-08-15)
    Returns:
        Dataframe containing org_uid, org name, score, and letter grade
    """

    # ----- RETRIEVE WAS SCORE DATA -----
    # Calculate start/end date for current report period
    [start_date, end_date] = get_prev_startstop(curr_date, 1)[0]
    # Retrieve WAS score data for current report period
    was_data_df = import_was_data(start_date, end_date)

    # ----- NORMALIZE METRICS -----

    # Normalize metrics by dividing each by number of webapps
    was_norm_data_df = pd.concat(
        [
            # leave basic org info alone
            was_data_df.iloc[:, 0:2],
            # normalize columns idx [2, 7]
            was_data_df.iloc[:, 2:8].div(was_data_df["num_webapp"], axis=0),
            # leave max_cvss alone
            was_data_df["max_cvss"],
            # normalize columns idx [9, 21]
            was_data_df.iloc[:, 9:22].div(was_data_df["num_webapp"], axis=0),
            # leave avg_remed_time alone
            was_data_df["avg_remed_time"],
            # normalize columns idx [23, 24]
            was_data_df.iloc[:, 23:25].div(was_data_df["num_webapp"], axis=0),
        ],
        axis=1,
    )

    # ----- REMEDIATION STATS FEATURE -----

    # Re-Scale only remediation metrics 0-100
    for col_idx in range(22, 25):
        was_norm_data_df.iloc[:, col_idx] = rescale(
            was_norm_data_df.iloc[:, col_idx], 100, 0
        )

    # Aggregate remediation metrics into a single value "remediation score"
    was_norm_data_df["remed_score"] = (
        (was_norm_data_df["avg_remed_time"] * 0.50)
        + (was_norm_data_df["num_crit_remed_gt1"] * 0.30)
        + (was_norm_data_df["num_high_remed_gt3"] * 0.20)
    )

    # Convert this remediation score to z-score relative to all other WAS orgs
    remed_score_avg = was_norm_data_df["remed_score"].mean()
    remed_score_std = was_norm_data_df["remed_score"].std()
    was_norm_data_df["remed_score"] = (
        was_norm_data_df["remed_score"] - remed_score_avg
    ) / remed_score_std

    # Re-scale z-score values to be between -1 and 1
    max_abs_zscore = was_norm_data_df["remed_score"].abs().max()
    was_norm_data_df["remed_score"] = was_norm_data_df["remed_score"] / max_abs_zscore

    # Based on this z-score, apply penalty/reward to vulnerability related metrics
    # - negative z-score = quicker remediation/better remediation stats = better overall score
    # - positive z-score = slower remediation/worse remediation stats = worse overall score

    # The maximum amount the remediation feature can change a metric
    remed_modifier = 0.50
    # Apply remediation feature modifier to vulnerability-related metrics
    remed_multipliers = 1 + (was_norm_data_df["remed_score"] * remed_modifier)
    was_norm_data_df.iloc[:, 2:19] = was_norm_data_df.iloc[:, 2:19].apply(
        lambda x: x * remed_multipliers
    )

    # ----- AGGREGATE METRICS -----

    # Re-Scale all aggregation metrics to be between 0 - 100
    for col_idx in range(2, 25):
        was_norm_data_df.iloc[:, col_idx] = rescale(
            was_norm_data_df.iloc[:, col_idx], 100, 0
        )

    # Aggregate metrics into single value
    was_data_agg = pd.DataFrame(was_norm_data_df.iloc[:, 0])

    # General Metrics Section Score
    was_data_agg["WAS_base_section"] = (was_norm_data_df["num_webapp_vulns"] * 0.70) + (
        was_norm_data_df["num_detected_gt10"] * 0.30
    )
    # CVSS Metrics Section Score
    was_data_agg["WAS_cvss_section"] = (
        (was_norm_data_df["num_cvss_low"] * 0.15)
        + (was_norm_data_df["num_cvss_med"] * 0.20)
        + (was_norm_data_df["num_cvss_high"] * 0.25)
        + (was_norm_data_df["num_cvss_crit"] * 0.30)
        + (was_norm_data_df["max_cvss"] * 0.10)
    )
    # OWASP Metrics Section Score (ranked by descending importance)
    was_data_agg["WAS_owasp_section"] = (
        (was_norm_data_df["num_broken_access_control"] * 0.14)
        + (was_norm_data_df["num_crypto_fail"] * 0.14)
        + (was_norm_data_df["num_injection"] * 0.12)
        + (was_norm_data_df["num_insec_design"] * 0.12)
        + (was_norm_data_df["num_sec_misconfig"] * 0.10)
        + (was_norm_data_df["num_vuln_outdated_comp"] * 0.10)
        + (was_norm_data_df["num_ident_auth_fail"] * 0.08)
        + (was_norm_data_df["num_soft_data_integ_fail"] * 0.08)
        + (was_norm_data_df["num_sec_log_monitor_fail"] * 0.06)
        + (was_norm_data_df["num_ssrf"] * 0.06)
    )
    # Info Gathered Metrics Section Score
    was_data_agg["WAS_ig_section"] = (
        (was_norm_data_df["num_info_gathered"] * 0.20)
        + (was_norm_data_df["num_diag_ig"] * 0.10)
        + (was_norm_data_df["num_weak_ig"] * 0.70)
    )
    # Combining Sections
    was_data_agg["WAS_score"] = (
        (was_data_agg["WAS_base_section"] * 0.25)
        + (was_data_agg["WAS_cvss_section"] * 0.30)
        + (was_data_agg["WAS_owasp_section"] * 0.25)
        + (was_data_agg["WAS_ig_section"] * 0.20)
    )
    # Taking the complement of the fully aggregated score to get the final WAS score
    # (100 - aggregated score = WAS Score)
    was_data_agg["WAS_score"] = (100 - was_data_agg["WAS_score"]).astype(float).round(2)
    was_data_agg = was_data_agg.sort_values(
        by="WAS_score", ascending=False
    ).reset_index(drop=True)

    # TEMP FIX: STAKEHOLDER WITH NO WEBAPPS???
    was_data_agg = was_data_agg.fillna(0)

    # Converting numeric WAS score to letter grade scale
    letter_ranges = [
        was_data_agg["WAS_score"] < 65,  # F
        (was_data_agg["WAS_score"] >= 65) & (was_data_agg["WAS_score"] < 67),  # D
        (was_data_agg["WAS_score"] >= 67) & (was_data_agg["WAS_score"] < 70),  # D+
        (was_data_agg["WAS_score"] >= 70) & (was_data_agg["WAS_score"] < 73),  # C-
        (was_data_agg["WAS_score"] >= 73) & (was_data_agg["WAS_score"] < 77),  # C
        (was_data_agg["WAS_score"] >= 77) & (was_data_agg["WAS_score"] < 80),  # C+
        (was_data_agg["WAS_score"] >= 80) & (was_data_agg["WAS_score"] < 83),  # B-
        (was_data_agg["WAS_score"] >= 83) & (was_data_agg["WAS_score"] < 87),  # B
        (was_data_agg["WAS_score"] >= 87) & (was_data_agg["WAS_score"] < 90),  # B+
        (was_data_agg["WAS_score"] >= 90) & (was_data_agg["WAS_score"] < 93),  # A-
        (was_data_agg["WAS_score"] >= 93) & (was_data_agg["WAS_score"] < 97),  # A
        (was_data_agg["WAS_score"] >= 97) & (was_data_agg["WAS_score"] <= 100),  # A+
    ]
    letter_grades = ["F", "D", "D+", "C-", "C", "C+", "B-", "B", "B+", "A-", "A", "A+"]
    was_data_agg["letter_grade"] = np.select(letter_ranges, letter_grades)

    # Isolate final WAS score data
    was_data_agg = was_data_agg[["org_id", "WAS_score", "letter_grade"]]

    # Return dataframe with WAS scores
    return was_data_agg


# Demo:
# curr_date = datetime.datetime(2022, 8, 15)  # current report period date
# print(get_was_scores(curr_date).to_string())
