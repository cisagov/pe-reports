"""A file containing the PE scoring algorithm, version 1.0."""
# Standard Python Libraries
import calendar
import datetime
import math

# Third-Party Libraries
from dateutil.relativedelta import relativedelta
import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.ensemble import IsolationForest

# cisagov Libraries
from pe_reports.data.db_query import get_orgs_df, query_score_data

# Version 1.0 of the PE scoring algorithm, still a WIP

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
                start_stops.insert(0, [start_date, end_date])
            else:
                # odd idx 16 - 30/31
                start_date = (curr_date + relativedelta(months=-month_diff[i])).replace(
                    day=16
                )
                end_date = curr_date + relativedelta(months=-month_diff[i])
                end_date = end_date.replace(
                    day=calendar.monthrange(end_date.year, end_date.month)[1]
                )
                start_stops.insert(0, [start_date, end_date])
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
                start_stops.insert(0, [start_date, end_date])
            else:
                # odd idx 1 - 15
                start_date = (curr_date + relativedelta(months=-month_diff[i])).replace(
                    day=1
                )
                end_date = (curr_date + relativedelta(months=-month_diff[i])).replace(
                    day=15
                )
                start_stops.insert(0, [start_date, end_date])
    # Return array of start/stop dates
    return start_stops


def get_pe_scores(curr_date, num_periods):
    """
    Calculate PE scores for all orgs that are reported on.

    Args:
        curr_date: current report period date (i.e. 2022-08-15)
        num_periods: number of preceding report periods to grab for historical analysis (i.e. 15)

    Returns:
        Dataframe containing org_uid, org name, score, and letter grade
    """
    # ---------- Import PE Score Data ----------
    # Import all relevant data to calculate PE score

    # Convert curr_date to date object if a string is provided.
    if type(curr_date) is str:
        curr_date = datetime.datetime.strptime(curr_date, "%Y-%m-%d").date()
    # Get start/stop dates for each of the previous report periods
    start_stops = get_prev_startstop(curr_date, num_periods)
    # Get start/stop for current report period
    [curr_start, curr_stop] = start_stops[-1]
    # Get overall start/stop for historical data - use w/ sql functions
    [hist_start, hist_stop] = [start_stops[0][0], curr_stop]

    # ORG DATA: List of orgs PE is reporting on
    all_orgs = get_orgs_df()
    reported_orgs = all_orgs[all_orgs["report_on"] == True]
    reported_orgs = reported_orgs[["organizations_uid", "cyhy_db_name"]].reset_index(
        drop=True
    )

    # BASE DATA: Base Metric Data, current Report period only
    sql = "SELECT * FROM pes_base_metrics(%(start)s, %(end)s);"
    pe_base_data_df = query_score_data(
        curr_start.strftime("%m/%d/%Y"), curr_stop.strftime("%m/%d/%Y"), sql
    )

    # CVE DATA: verif and unverif CVE/CVSS data, current report period only:
    # Connect to SQL DB function:
    #   - pes_cve_metrics(curr_start, curr_stop)
    # CVEDat = pd.read_csv("PES_cveDat_2022_08_15.csv") WIP

    # HIST DATA: historical data for anomaly detection for the past n report periods:
    sql = """SELECT * FROM pes_hist_data_totcred(%(start)s, %(end)s);"""
    anomaly_data_cred = query_score_data(
        hist_start.strftime("%m/%d/%Y"), hist_stop.strftime("%m/%d/%Y"), sql
    )

    sql = """SELECT * FROM pes_hist_data_domalert(%(start)s, %(end)s);"""
    anomaly_data_domain = query_score_data(
        hist_start.strftime("%m/%d/%Y"), hist_stop.strftime("%m/%d/%Y"), sql
    )

    sql = """SELECT * FROM pes_hist_data_dwalert(%(start)s, %(end)s);"""
    anomaly_data_darkweb_alert = query_score_data(
        hist_start.strftime("%m/%d/%Y"), hist_stop.strftime("%m/%d/%Y"), sql
    )

    sql = """SELECT * FROM pes_hist_data_dwment(%(start)s, %(end)s);"""
    anomaly_data_darkweb_mention = query_score_data(
        hist_start.strftime("%m/%d/%Y"), hist_stop.strftime("%m/%d/%Y"), sql
    )

    # ---------- Aggregate Historical Data ----------
    # Prep historical data for use in anomaly detection
    # Converting string date to datetime objects
    anomaly_data_cred["mod_date"] = pd.to_datetime(
        anomaly_data_cred["mod_date"]
    ).dt.date
    anomaly_data_domain["mod_date"] = pd.to_datetime(
        anomaly_data_domain["mod_date"]
    ).dt.date
    anomaly_data_darkweb_alert["mod_date"] = pd.to_datetime(
        anomaly_data_darkweb_alert["mod_date"]
    ).dt.date
    anomaly_data_darkweb_mention["date"] = pd.to_datetime(
        anomaly_data_darkweb_mention["date"]
    ).dt.date

    # Separate lists of dataframes for each metric
    periods_total_cred = []
    periods_domain_alert = []
    periods_darkweb_alert = []
    periods_darkweb_mention = []
    end_dates = []
    # Iterate through all preceding report periods:
    # Create a dataframe for each report period that contains the
    # data on all reported orgs for that report period
    for period in start_stops:
        # Keep track of report period dates
        end_dates.append(period[1])

        # Getting all data for the current report period
        current_total_cred = anomaly_data_cred.loc[
            (anomaly_data_cred["mod_date"] >= period[0])
            & (anomaly_data_cred["mod_date"] <= period[1])
        ]
        current_domain_alert = anomaly_data_domain.loc[
            (anomaly_data_domain["mod_date"] >= period[0])
            & (anomaly_data_domain["mod_date"] <= period[1])
        ]
        current_darkweb_alert = anomaly_data_darkweb_alert.loc[
            (anomaly_data_darkweb_alert["mod_date"] >= period[0])
            & (anomaly_data_darkweb_alert["mod_date"] <= period[1])
        ]
        current_darkweb_mention = anomaly_data_darkweb_mention.loc[
            (anomaly_data_darkweb_mention["date"] >= period[0])
            & (anomaly_data_darkweb_mention["date"] <= period[1])
        ]

        # Aggregating the data for the current report period
        current_total_cred = current_total_cred.groupby(
            ["organizations_uid", "cyhy_db_name"], as_index=False
        ).agg({"no_password": "sum", "password_included": "sum", "total_creds": "sum"})

        current_domain_alert = current_domain_alert.groupby(
            ["organizations_uid", "cyhy_db_name"], as_index=False
        )["mod_date"].count()
        current_domain_alert = current_domain_alert.rename(
            columns={"mod_date": "num_domAlerts"}
        )

        current_darkweb_alert = current_darkweb_alert.groupby(
            ["organizations_uid", "cyhy_db_name"], as_index=False
        )["mod_date"].count()
        current_darkweb_alert = current_darkweb_alert.rename(
            columns={"mod_date": "num_DWAlerts"}
        )

        current_darkweb_mention = current_darkweb_mention.groupby(
            ["organizations_uid", "cyhy_db_name"], as_index=False
        ).agg({"num_mentions": "sum"})
        current_darkweb_mention = current_darkweb_mention.rename(
            columns={"num_mentions": "num_DWMents"}
        )

        # Left join results with reported orgs list
        # (Only grabbing data for orgs we report on)
        current_total_cred = current_total_cred.drop(["cyhy_db_name"], axis=1)
        current_domain_alert = current_domain_alert.drop(["cyhy_db_name"], axis=1)
        current_darkweb_alert = current_darkweb_alert.drop(["cyhy_db_name"], axis=1)
        current_darkweb_mention = current_darkweb_mention.drop(["cyhy_db_name"], axis=1)
        current_total_cred = reported_orgs.merge(
            current_total_cred, on="organizations_uid", how="left"
        )
        current_domain_alert = reported_orgs.merge(
            current_domain_alert, on="organizations_uid", how="left"
        )
        current_darkweb_alert = reported_orgs.merge(
            current_darkweb_alert, on="organizations_uid", how="left"
        )
        current_darkweb_mention = reported_orgs.merge(
            current_darkweb_mention, on="organizations_uid", how="left"
        )

        # Adjusting columns
        current_total_cred = current_total_cred[
            [
                "organizations_uid",
                "cyhy_db_name",
                "no_password",
                "password_included",
                "total_creds",
            ]
        ]
        current_domain_alert = current_domain_alert[
            [
                "organizations_uid",
                "cyhy_db_name",
                "num_domAlerts",
            ]
        ]
        current_darkweb_alert = current_darkweb_alert[
            [
                "organizations_uid",
                "cyhy_db_name",
                "num_DWAlerts",
            ]
        ]
        current_darkweb_mention = current_darkweb_mention[
            [
                "organizations_uid",
                "cyhy_db_name",
                "num_DWMents",
            ]
        ]

        # Replace NaNs with 0.0
        current_total_cred = current_total_cred.fillna(0.0)
        current_domain_alert = current_domain_alert.fillna(0.0)
        current_darkweb_alert = current_darkweb_alert.fillna(0.0)
        current_darkweb_mention = current_darkweb_mention.fillna(0.0)

        # Append finished dataframe to list
        periods_total_cred.append(current_total_cred)
        periods_domain_alert.append(current_domain_alert)
        periods_darkweb_alert.append(current_darkweb_alert)
        periods_darkweb_mention.append(current_darkweb_mention)

    # ---------- Anomaly Detection (CART) Feature of PE Score ----------
    # Check if the current report period is anomalous for various metrics
    # If current report period is an anomaly, administer a penalty to PE score
    # Anomaly flags are contained in a dedicated columns containing only -1/1
    # (1=normal, -1=anomaly)

    # Columns to hold anomaly flags (default to 1)
    pe_base_data_df["anomaly_totCred"] = 1
    pe_base_data_df["anomaly_domAlert"] = 1
    pe_base_data_df["anomaly_DWAlert"] = 1
    pe_base_data_df["anomaly_DWMent"] = 1

    # Iterate over all orgs PE reports on
    for org in reported_orgs.iloc[:, 1]:
        print("\nDoing anomaly search on: ", org)
        # Arrays to hold historic counts for each preceding report period
        count_hist_total_cred = []
        count_hist_domain_alert = []
        count_hist_darkweb_alert = []
        count_hist_darkweb_mention = []
        for period in periods_total_cred:
            count_hist_total_cred.append(
                period.loc[period["cyhy_db_name"] == org, "total_creds"].values[0]
            )
        for period in periods_domain_alert:
            count_hist_domain_alert.append(
                period.loc[period["cyhy_db_name"] == org, "num_domAlerts"].values[0]
            )
        for period in periods_darkweb_alert:
            count_hist_darkweb_alert.append(
                period.loc[period["cyhy_db_name"] == org, "num_DWAlerts"].values[0]
            )
        for period in periods_darkweb_mention:
            count_hist_darkweb_mention.append(
                period.loc[period["cyhy_db_name"] == org, "num_DWMents"].values[0]
            )

        # Formatting historic data for CART anomaly detection:
        current_data_total_creds = pd.DataFrame(
            count_hist_total_cred, columns=["counts"]
        )
        current_data_domain_alerts = pd.DataFrame(
            count_hist_domain_alert, columns=["counts"]
        )
        current_data_darkweb_alerts = pd.DataFrame(
            count_hist_darkweb_alert, columns=["counts"]
        )
        current_data_darkweb_mentions = pd.DataFrame(
            count_hist_darkweb_mention, columns=["counts"]
        )

        scaler = preprocessing.StandardScaler()
        np_scaled_total_cred = scaler.fit_transform(
            current_data_total_creds.values.reshape(-1, 1)
        )
        np_scaled_domain_alert = scaler.fit_transform(
            current_data_domain_alerts.values.reshape(-1, 1)
        )
        np_scaled_darkweb_alert = scaler.fit_transform(
            current_data_darkweb_alerts.values.reshape(-1, 1)
        )
        np_scaled_darkweb_mention = scaler.fit_transform(
            current_data_darkweb_mentions.values.reshape(-1, 1)
        )
        scale_data_total_cred = pd.DataFrame(np_scaled_total_cred)
        scale_data_domain_alert = pd.DataFrame(np_scaled_domain_alert)
        scale_data_darkweb_alert = pd.DataFrame(np_scaled_darkweb_alert)
        scale_data_darkweb_mention = pd.DataFrame(np_scaled_darkweb_mention)

        # Setting anomaly contamination parameter:
        outlier_fraction_total_cred = float(0.15)
        outlier_fraction_domain_alert = float(0.15)
        outlier_fraction_dark_alert = float(0.15)
        outlier_fraction_dark_mention = float(0.15)
        # False positive anomalies = parameter is too high
        # False negative anomalies = parameter is too low
        # Contamination refers to how many outliers are in the data set,
        # i.e. 0.15 suggests 15% of data is going to be an anomaly

        # Train isolation forest model
        model_total_cred = IsolationForest(contamination=outlier_fraction_total_cred)
        model_domain_alert = IsolationForest(
            contamination=outlier_fraction_domain_alert
        )
        model_darkweb_alert = IsolationForest(contamination=outlier_fraction_dark_alert)
        model_darkweb_mention = IsolationForest(
            contamination=outlier_fraction_dark_mention
        )
        # Fit isolation forest model to data
        model_total_cred.fit(scale_data_total_cred)
        model_domain_alert.fit(scale_data_domain_alert)
        model_darkweb_alert.fit(scale_data_darkweb_alert)
        model_darkweb_mention.fit(scale_data_darkweb_mention)
        # Detect anomalies using model
        current_data_total_creds["anomaly"] = model_total_cred.predict(
            scale_data_total_cred
        )
        current_data_domain_alerts["anomaly"] = model_domain_alert.predict(
            scale_data_domain_alert
        )
        current_data_darkweb_alerts["anomaly"] = model_darkweb_alert.predict(
            scale_data_darkweb_alert
        )
        current_data_darkweb_mentions["anomaly"] = model_darkweb_mention.predict(
            scale_data_darkweb_mention
        )

        # Record flags in dedicated columns for organizations where
        # the current report period is a positive, increase anomaly
        if current_data_total_creds["anomaly"].iloc[-1] == -1 and (
            current_data_total_creds["counts"].iloc[-1]
            > current_data_total_creds["counts"].iloc[-2]
        ):
            print("\t", org, " current total creds is an anomaly")
            # Set flag for anomaly
            pe_base_data_df.loc[
                pe_base_data_df["cyhy_db_name"] == org, "anomaly_totCred"
            ] = -1
        if current_data_domain_alerts["anomaly"].iloc[-1] == -1 and (
            current_data_domain_alerts["counts"].iloc[-1]
            > current_data_domain_alerts["counts"].iloc[-2]
        ):
            print("\t", org, " current domain alerts is an anomaly")
            # Set flag for anomaly
            pe_base_data_df.loc[
                pe_base_data_df["cyhy_db_name"] == org, "anomaly_domAlert"
            ] = -1
        if current_data_darkweb_alerts["anomaly"].iloc[-1] == -1 and (
            current_data_darkweb_alerts["counts"].iloc[-1]
            > current_data_darkweb_alerts["counts"].iloc[-2]
        ):
            print("\t", org, " current dark web alerts is an anomaly")
            # Set flag for anomaly
            pe_base_data_df.loc[
                pe_base_data_df["cyhy_db_name"] == org, "anomaly_DWAlert"
            ] = -1

        if current_data_darkweb_mentions["anomaly"].iloc[-1] == -1 and (
            current_data_darkweb_mentions["counts"].iloc[-1]
            > current_data_darkweb_mentions["counts"].iloc[-2]
        ):
            print("\t", org, " current dark web mentions is an anomaly")
            # Set flag for anomaly
            pe_base_data_df.loc[
                pe_base_data_df["cyhy_db_name"] == org, "anomaly_DWMent"
            ] = -1

    # Apply penalties based on anomaly flags
    pe_base_data_df["num_total_creds"] = np.where(
        pe_base_data_df["anomaly_totCred"] == -1,
        pe_base_data_df["num_total_creds"] * 1.5,  # penalty
        pe_base_data_df["num_total_creds"],
    )
    pe_base_data_df["num_alert_domain"] = np.where(
        pe_base_data_df["anomaly_domAlert"] == -1,
        pe_base_data_df["num_alert_domain"] * 1.5,  # penalty
        pe_base_data_df["num_alert_domain"],
    )
    pe_base_data_df["num_dw_alerts"] = np.where(
        pe_base_data_df["anomaly_DWAlert"] == -1,
        pe_base_data_df["num_dw_alerts"] * 1.5,  # penalty
        pe_base_data_df["num_dw_alerts"],
    )
    pe_base_data_df["num_dw_mentions"] = np.where(
        pe_base_data_df["anomaly_DWMent"] == -1,
        pe_base_data_df["num_dw_mentions"] * 1.5,  # penalty
        pe_base_data_df["num_dw_mentions"],
    )

    # ---------- CVE/CVSS Feature of PE Score WIP ----------
    # Get CVSS/Severity info for all verif and unverif CVES
    # Reference DB table with all CVE info for better performance
    # (compared to sequential Circl API calls)
    # WIP, pending CVE_info table setup in staging DB...

    # ---------- Re-Scale Base & Attack Surface Metrics ----------
    # Re-Scale all metrics (base and attack surface) so that they take on a value from 0 - 100.
    for col_idx in range(2, 18):
        pe_base_data_df.iloc[:, col_idx] = (
            (pe_base_data_df.iloc[:, col_idx] - min(pe_base_data_df.iloc[:, col_idx]))
            / (
                max(pe_base_data_df.iloc[:, col_idx])
                - min(pe_base_data_df.iloc[:, col_idx])
            )
            * 100
        )

    # ---------- Calculate Aggregate Attack Surface Value ----------
    # Calculate aggregate attack surface value based on specified weights (1 - 101)
    # *** Note: adding +1 to aggregate attack surface value to avoid dividing by zero,
    #           weights still TBD...
    pe_base_data_df["AASV"] = (
        (pe_base_data_df["num_ports"] * 0.50)
        + (pe_base_data_df["num_sub_domain"] * 0.20)
        + (pe_base_data_df["num_ips"] * 0.20)
        + (pe_base_data_df["num_root_domain"] * 0.10)
    ) + 1

    # ----------- Normalize All Metrics by Attack Surface Size ----------
    # Normalize all metrics by dividing them by the aggregate attack surface value
    # which serves as an approximation of organization size
    pe_data = pd.DataFrame()
    pe_data = pd.concat(
        [
            pe_base_data_df.iloc[:, 0:2],  # Org identifiers
            pe_base_data_df.iloc[:, 2:18].div(
                pe_base_data_df["AASV"], axis=0
            ),  # Base metrics
            pe_base_data_df.iloc[:, 18:21],  # Anomaly flags
        ],
        axis=1,
    )

    # Re-Scale metrics again to take on a value from 0 - 100
    for col_idx in range(2, 18):
        pe_data.iloc[:, col_idx] = (
            (pe_data.iloc[:, col_idx] - min(pe_data.iloc[:, col_idx]))
            / (max(pe_data.iloc[:, col_idx]) - min(pe_data.iloc[:, col_idx]))
            * 100
        )

    # ---------- Aggregate Metrics into Overall PE Score ----------
    # Begin the final process of combining all calculated PE metrics into a
    # single PE score based on specified weights

    # The final dataframe that will contain the PE score itself
    pe_data_agg = pd.DataFrame(pe_data.iloc[:, 0:2])

    # Calculating credential section score
    pe_data_agg["PE_cred_score"] = (
        pe_data["num_breaches"] * 0.20
        + pe_data["num_total_creds"] * 0.30
        + pe_data["num_pass_creds"] * 0.50
    )
    # Calculating domain section score
    pe_data_agg["PE_domain_score"] = (
        pe_data["num_alert_domain"] * 0.70 + pe_data["num_sus_domain"] * 0.30
    )
    # Calculating vulnerability (CVE) section score
    pe_data_agg["PE_vuln_score"] = (
        pe_data["num_insecure_ports"] * 0.25
        + pe_data["num_verif_vulns"] * 0.50
        + pe_data["num_assets_unverif_vulns"] * 0.25
    )
    # Calculating dark web section score
    pe_data_agg["PE_darkweb_score"] = (
        pe_data["num_dw_alerts"] * 0.30
        + pe_data["num_dw_mentions"] * 0.20
        + pe_data["num_dw_threats"] * 0.25
        + pe_data["num_dw_invites"] * 0.25
    )

    # Combining section scores into fully aggregated score
    pe_data_agg["PE_score"] = (
        (pe_data_agg["PE_cred_score"] * 0.25)
        + (pe_data_agg["PE_domain_score"] * 0.25)
        + (pe_data_agg["PE_vuln_score"] * 0.25)
        + (pe_data_agg["PE_darkweb_score"] * 0.25)
    )

    # The taking the complement of the fully aggregated score to get the final PE score
    # (100 - aggregated score = PE Score)
    pe_data_agg["PE_score"] = 100 - pe_data_agg["PE_score"]
    pe_data_agg = pe_data_agg.sort_values(by="PE_score", ascending=False).reset_index(
        drop=True
    )

    # Converting numeric PE score to letter grade scale
    letter_ranges = [
        pe_data_agg["PE_score"] < 65,  # F
        (pe_data_agg["PE_score"] >= 65) & (pe_data_agg["PE_score"] < 67),  # D
        (pe_data_agg["PE_score"] >= 67) & (pe_data_agg["PE_score"] < 70),  # D+
        (pe_data_agg["PE_score"] >= 70) & (pe_data_agg["PE_score"] < 73),  # C-
        (pe_data_agg["PE_score"] >= 73) & (pe_data_agg["PE_score"] < 77),  # C
        (pe_data_agg["PE_score"] >= 77) & (pe_data_agg["PE_score"] < 80),  # C+
        (pe_data_agg["PE_score"] >= 80) & (pe_data_agg["PE_score"] < 83),  # B-
        (pe_data_agg["PE_score"] >= 83) & (pe_data_agg["PE_score"] < 87),  # B
        (pe_data_agg["PE_score"] >= 87) & (pe_data_agg["PE_score"] < 90),  # B+
        (pe_data_agg["PE_score"] >= 90) & (pe_data_agg["PE_score"] < 93),  # A-
        (pe_data_agg["PE_score"] >= 93) & (pe_data_agg["PE_score"] < 97),  # A
        (pe_data_agg["PE_score"] >= 97) & (pe_data_agg["PE_score"] <= 100),  # A+
    ]
    letter_grades = ["F", "D", "D+", "C-", "C", "C+", "B-", "B", "B+", "A-", "A", "A+"]
    pe_data_agg["letter_grade"] = np.select(letter_ranges, letter_grades)

    # Isolate final PE score data
    pe_data_agg = pe_data_agg[
        ["organizations_uid", "cyhy_db_name", "PE_score", "letter_grade"]
    ]

    # Return dataframe with PE scores
    return pe_data_agg


# Demo:
# curr_date = datetime.datetime(2022, 8, 15)  # current report period date
# num_periods = 12  # number of preceding report periods for historical analysis/trending
# print(get_pe_scores(curr_date, num_periods).to_string())
