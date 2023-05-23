"""A file containing the helper functions for various scoring algorithms."""
# Standard Python Libraries
import calendar
import math
from datetime import datetime

# Third-Party Libraries
import pandas as pd
from dateutil.relativedelta import relativedelta


# Add skewness function?


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
    if min_val == max_val:
        # If all the same number, just return all zeros
        return pd.Series([0] * values.size)
    else:
        # Otherwise, rescale 0-100
        values = ((values - min_val) / (max_val - min_val) * width) + offset
        return values


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
    elif score >= 97.0:
        return "A+"
    else:
        return "N/A"


def get_next_month(report_period_year, report_period_month):
    next_report_period_month = 0
    next_report_period_year = 0
    if report_period_month == 12:
        next_report_period_month = 1
        next_report_period_year = report_period_year + 1
    else:
        next_report_period_month = report_period_month + 1
        next_report_period_year = report_period_year
    next_report_period_date = datetime(
        next_report_period_year, next_report_period_month, 1
    )
    return next_report_period_date


def get_last_month(report_period_year, report_period_month):
    last_report_period_month = 0
    last_report_period_year = 0
    if report_period_month == 1:
        last_report_period_month = 12
        last_report_period_year = report_period_year - 1
    else:
        last_report_period_month = report_period_month - 1
        last_report_period_year = report_period_year
    last_report_period_date = datetime(
        last_report_period_year, last_report_period_month, 1
    )
    return last_report_period_date


def average_list(list):
    if len(list) == 0:
        return 0
    else:
        return round(sum(list) / len(list), 2)


def average_numbers(vuln_count, total):
    if total == 0:
        return 0.0
    else:
        return round((vuln_count / total) * 100, 2)


def split_parent_child_records(df):
    """
    Splits rows with both an organizations_uid and parent_uid into two rows for roll up support.

    Args:
        df: Dataframe of database view data containing both organizations_uid and parent_org_uid columns

    Returns:
        Dataframe where any rows with both a organizations_uid and parent_org_uid have been split into two rows.
        One row has the organizations_uid, and the other row is an exact copy, but with the parent_org_uid.
        Returned dataframe only has a single organizations_uid column.
    """
    # For child orgs and standalone orgs that don't
    # have a parent, simply drop parent_uid column
    standalone_df = df.drop(columns="parent_org_uid")

    # For orgs that have an org_uid AND a parent_uid
    # Create a duplicate data row for the parent org
    parent_mask = df["parent_org_uid"].notnull() & df["organizations_uid"].notnull()
    duplicate_df = (
        df[parent_mask]
        .drop(columns="organizations_uid")
        .rename(columns={"parent_org_uid": "organizations_uid"})
    )

    # Combine standalone/child orgs rows and duplicated
    # parent rows into the final dataframe
    final_df = pd.concat([standalone_df, duplicate_df], ignore_index=True)

    # Warning: final_df still needs aggregation after applying this function
    return final_df
