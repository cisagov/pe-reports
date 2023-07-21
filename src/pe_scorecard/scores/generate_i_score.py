"""A file containing the Identification Score (I-Score) algorithm, version 1.1."""
# Standard Python Libraries
import sys
import os
import logging

# Third-Party Libraries
import numpy as np
import pandas as pd

# Help python find db_query file
sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

# cisagov Libraries
from pe_scorecard.scores.score_helper_functions import (
    rescale,
    get_prev_startstop,
    split_parent_child_records,
)
from pe_scorecard.data.db_query import (
    # VS queries
    api_iscore_vs_vuln,
    api_iscore_vs_vuln_prev,
    # PE queries
    api_iscore_pe_vuln,
    api_iscore_pe_cred,
    api_iscore_pe_breach,
    api_iscore_pe_darkweb,
    api_iscore_pe_protocol,
    # WAS queries
    api_iscore_was_vuln,
    api_iscore_was_vuln_prev,
    # KEV list
    api_kev_list,
    # FCEB Stakeholder sectors by size
    api_xs_stakeholders,
    api_s_stakeholders,
    api_m_stakeholders,
    api_l_stakeholders,
    api_xl_stakeholders,
)

# Setup logging to central file
LOGGER = logging.getLogger(__name__)


# ---------- Misc. Helper Functions ----------
# Helper functions that assist in the calculation of this
# score are stored in the "score_helper_functions.py" file


# ---------- Data Import Function ----------
# Suppressing divide by 0 or NaN runtime warning
# This is expected and part of the I-Score calculation
@np.errstate(divide="ignore", invalid="ignore")
def import_ident_data(prev_start, prev_end, curr_start, curr_end, stakeholder_list):
    """
    Retrieve all data required for calculating identification score.

    Args:
        prev_start: start date of previous report period
        prev_end: end date of previous report period
        curr_start: start date of current report period
        curr_end: end date of current report period
        stakeholder_list: dataframe containing the organizations_uid and cyhy_db_name of all the orgs to generate scores for
    Returns:
        A single dataframe containing all data necessary for Identification Score calculation.
    """
    # --------------- Import Team Data from Database: ---------------
    # Retrieve all the data needed from the database
    # ----- Retrieve VS data: -----
    LOGGER.info("Retrieving VS vuln data for I-Score...")
    vs_data_vuln = api_iscore_vs_vuln(stakeholder_list)
    LOGGER.info("\tDone!")
    # ----- Retrieve PE data: -----
    LOGGER.info("Retrieving PE vuln data for I-Score...")
    pe_data_vuln = api_iscore_pe_vuln(stakeholder_list, curr_start, curr_end)
    LOGGER.info("\tDone!")
    LOGGER.info("Retrieving PE cred data for I-Score...")
    pe_data_cred = api_iscore_pe_cred(stakeholder_list, curr_start, curr_end)
    LOGGER.info("\tDone!")
    LOGGER.info("Retrieving PE breach data for I-Score...")
    pe_data_breach = api_iscore_pe_breach(stakeholder_list, curr_start, curr_end)
    LOGGER.info("\tDone!")
    LOGGER.info("Retrieving PE dark web data for I-Score...")
    pe_data_dw = api_iscore_pe_darkweb(stakeholder_list, curr_start, curr_end)
    LOGGER.info("\tDone!")
    LOGGER.info("Retrieving PE protocol data for I-Score...")
    pe_data_proto = api_iscore_pe_protocol(stakeholder_list, curr_start, curr_end)
    LOGGER.info("\tDone!")
    # ----- Retrieve WAS data: -----
    LOGGER.info("Retrieving WAS vuln data for I-Score...")
    was_data_vuln = api_iscore_was_vuln(stakeholder_list, curr_start, curr_end)
    LOGGER.info("\tDone!")

    # --------------- Import Historical Data: ---------------
    LOGGER.info("Retrieving previous VS vuln data for I-Score...")
    vs_data_vuln_prev = api_iscore_vs_vuln_prev(stakeholder_list, prev_start, prev_end)
    LOGGER.info("\tDone!")
    LOGGER.info("Retrieving previous PE vuln data for I-Score...")
    pe_data_vuln_prev = api_iscore_pe_vuln(stakeholder_list, prev_start, prev_end)
    LOGGER.info("\tDone!")
    LOGGER.info("Retrieving previous WAS vuln data for I-Score...")
    was_data_vuln_prev = api_iscore_was_vuln(stakeholder_list, prev_start, prev_end)
    LOGGER.info("\tDone!")

    # --------------- Import Other Necessary Info: ---------------
    # ----- Retrieve KEV list: -----
    # List of all CVE-IDs that are considered KEVs
    LOGGER.info("Retrieving KEV list...")
    kev_list = api_kev_list()
    LOGGER.info("\tDone!")
    # ----- List of orgs for this sector: -----
    org_list = stakeholder_list

    # ---------- Preprocessing for Rollup Support -----------
    # Split parent/child records to support rollup functionality
    vs_data_vuln = split_parent_child_records(vs_data_vuln)
    vs_data_vuln_prev = split_parent_child_records(vs_data_vuln_prev)
    pe_data_vuln = split_parent_child_records(pe_data_vuln)
    pe_data_vuln_prev = split_parent_child_records(pe_data_vuln_prev)
    pe_data_cred = split_parent_child_records(pe_data_cred)
    pe_data_breach = split_parent_child_records(pe_data_breach)
    pe_data_dw = split_parent_child_records(pe_data_dw)
    pe_data_proto = split_parent_child_records(pe_data_proto)
    was_data_vuln = split_parent_child_records(was_data_vuln)
    was_data_vuln_prev = split_parent_child_records(was_data_vuln_prev)

    # --------------- Process VS Data: ---------------
    # Requires 2 view:
    # - vuln data: vw_ident_vs_vuln
    # - historical vuln data: vw_ident_vs_vuln_prev
    # ----- VS Vuln. Data -----
    # Set KEV flags
    vs_data_vuln["is_kev"] = 0
    vs_data_vuln["is_kev"] = np.where(
        vs_data_vuln["cve_name"].isin(kev_list["kev"].values), 1, 0
    )
    # Set flags for low/med/high/crit KEVs
    [
        vs_data_vuln["low_kev"],
        vs_data_vuln["med_kev"],
        vs_data_vuln["high_kev"],
        vs_data_vuln["crit_kev"],
    ] = [
        np.where(
            (vs_data_vuln["cvss_score"] < 4) & (vs_data_vuln["is_kev"] == 1), 1, 0
        ),
        np.where(
            (vs_data_vuln["cvss_score"] >= 4)
            & (vs_data_vuln["cvss_score"] < 7)
            & (vs_data_vuln["is_kev"] == 1),
            1,
            0,
        ),
        np.where(
            (vs_data_vuln["cvss_score"] >= 7)
            & (vs_data_vuln["cvss_score"] < 9)
            & (vs_data_vuln["is_kev"] == 1),
            1,
            0,
        ),
        np.where(
            (vs_data_vuln["cvss_score"] >= 9) & (vs_data_vuln["is_kev"] == 1), 1, 0
        ),
    ]
    # Aggregate VS vuln data
    vs_data_vuln = vs_data_vuln.groupby(["organizations_uid"], as_index=False).agg(
        vs_total_num_vulns=("cve_name", "count"),
        vs_num_low_cve=("cvss_score", (lambda x: (x < 4).sum())),
        vs_num_med_cve=("cvss_score", (lambda x: ((x >= 4) & (x < 7)).sum())),
        vs_num_high_cve=("cvss_score", (lambda x: ((x >= 7) & (x < 9)).sum())),
        vs_num_crit_cve=("cvss_score", (lambda x: (x >= 9).sum())),
        vs_num_low_kev=("low_kev", "sum"),
        vs_num_med_kev=("med_kev", "sum"),
        vs_num_high_kev=("high_kev", "sum"),
        vs_num_crit_kev=("crit_kev", "sum"),
        vs_max_cvss=("cvss_score", "max"),
        vs_avg_cvss=("cvss_score", "mean"),
        vs_skewness_cvss=(
            "cvss_score",
            (
                # Calculating VS skewness metric
                lambda x: (
                    (
                        # Q3
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.75) - 1]
                    )
                    + (
                        # Q1
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.25) - 1]
                    )
                    - (
                        2
                        * (
                            # Q2
                            x.sort_values()
                            .reset_index(drop=True)
                            .iloc[round(len(x) * 0.5) - 1]
                        )
                    )
                )
                / (
                    (
                        # Q3
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.75) - 1]
                    )
                    - (
                        # Q1
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.25) - 1]
                    )
                )
            ),
        ),
    )
    # Handle NaNs in skewnesses
    vs_data_vuln["vs_skewness_cvss"].fillna(0, inplace=True)
    # Aggregate total VS vulns of previous month
    vs_data_vuln.insert(2, "vs_net_chng_vulns", 0)

    vs_data_vuln_prev = vs_data_vuln_prev.groupby(
        ["organizations_uid"], as_index=False
    ).agg(
        vs_total_num_vulns_prev=("cvss_score", "count"),
    )
    vs_data_vuln = pd.merge(
        vs_data_vuln, vs_data_vuln_prev, on="organizations_uid", how="outer"
    )
    # If no data from previous report period, set net change to 0
    vs_data_vuln["vs_total_num_vulns_prev"].fillna(
        vs_data_vuln["vs_total_num_vulns"], inplace=True
    )
    # Otherwise calculate net change in vulns
    vs_data_vuln["vs_net_chng_vulns"] = (
        vs_data_vuln["vs_total_num_vulns"] - vs_data_vuln["vs_total_num_vulns_prev"]
    )
    vs_data_vuln = vs_data_vuln.drop(columns=["vs_total_num_vulns_prev"]).reset_index()
    # Add cyhy_db_name column to vs vulns
    vs_data_df = pd.merge(
        org_list, vs_data_vuln, on="organizations_uid", how="left"
    ).drop(columns=["index", "cyhy_db_name"])

    # --------------- Process PE Data: ---------------
    # Requires 5 Views:
    # - vuln data: vw_ident_pe_vuln
    # - cred data: vw_ident_pe_cred, vw_ident_pe_breach
    # - dark web data: vw_ident_pe_dw
    # - protocol data: vw_ident_pe_proto
    # ~ historical vuln data: also uses vw_ident_pe_vuln
    # ----- PE Vuln. Data -----
    # Set KEV flags
    pe_data_vuln["is_kev"] = 0
    pe_data_vuln["is_kev"] = np.where(
        pe_data_vuln["cve_name"].isin(kev_list["kev"].values), 1, 0
    )
    # Set flags for low/med/high/crit KEVs
    [
        pe_data_vuln["low_kev"],
        pe_data_vuln["med_kev"],
        pe_data_vuln["high_kev"],
        pe_data_vuln["crit_kev"],
    ] = [
        np.where(
            (pe_data_vuln["cvss_score"] < 4) & (pe_data_vuln["is_kev"] == 1), 1, 0
        ),
        np.where(
            (pe_data_vuln["cvss_score"] >= 4)
            & (pe_data_vuln["cvss_score"] < 7)
            & (pe_data_vuln["is_kev"] == 1),
            1,
            0,
        ),
        np.where(
            (pe_data_vuln["cvss_score"] >= 7)
            & (pe_data_vuln["cvss_score"] < 9)
            & (pe_data_vuln["is_kev"] == 1),
            1,
            0,
        ),
        np.where(
            (pe_data_vuln["cvss_score"] >= 9) & (pe_data_vuln["is_kev"] == 1), 1, 0
        ),
    ]
    # Aggregate PE vuln data
    pe_data_vuln = pe_data_vuln.groupby(["organizations_uid"], as_index=False).agg(
        pe_total_num_vulns=("cve_name", "count"),
        pe_num_low_cve=("cvss_score", (lambda x: (x < 4).sum())),
        pe_num_med_cve=("cvss_score", (lambda x: ((x >= 4) & (x < 7)).sum())),
        pe_num_high_cve=("cvss_score", (lambda x: ((x >= 7) & (x < 9)).sum())),
        pe_num_crit_cve=("cvss_score", (lambda x: (x >= 9).sum())),
        pe_num_low_kev=("low_kev", "sum"),
        pe_num_med_kev=("med_kev", "sum"),
        pe_num_high_kev=("high_kev", "sum"),
        pe_num_crit_kev=("crit_kev", "sum"),
        pe_max_cvss=("cvss_score", "max"),
        pe_avg_cvss=("cvss_score", "mean"),
        pe_skewness_cvss=(
            "cvss_score",
            (
                # Calculating PE skewness metric
                lambda x: (
                    (
                        # Q3
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.75) - 1]
                    )
                    + (
                        # Q1
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.25) - 1]
                    )
                    - (
                        2
                        * (
                            # Q2
                            x.sort_values()
                            .reset_index(drop=True)
                            .iloc[round(len(x) * 0.5) - 1]
                        )
                    )
                )
                / (
                    (
                        # Q3
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.75) - 1]
                    )
                    - (
                        # Q1
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.25) - 1]
                    )
                )
            ),
        ),
    )
    # Handle NaNs in skewnesses
    pe_data_vuln["pe_skewness_cvss"].fillna(0, inplace=True)
    # Aggregate total PE vulns of previous month
    pe_data_vuln.insert(2, "pe_net_chng_vulns", 0)
    pe_data_vuln_prev = pe_data_vuln_prev.groupby(
        ["organizations_uid"], as_index=False
    ).agg(
        pe_total_num_vulns_prev=("cvss_score", "count"),
    )
    pe_data_vuln = pd.merge(
        pe_data_vuln, pe_data_vuln_prev, on="organizations_uid", how="outer"
    )
    # If no data from previous report period, set net change to 0
    pe_data_vuln["pe_total_num_vulns_prev"].fillna(
        pe_data_vuln["pe_total_num_vulns"], inplace=True
    )
    # Otherwise, calculate net change in vulns
    pe_data_vuln["pe_net_chng_vulns"] = (
        pe_data_vuln["pe_total_num_vulns"] - pe_data_vuln["pe_total_num_vulns_prev"]
    )
    pe_data_vuln = pe_data_vuln.drop(columns=["pe_total_num_vulns_prev"]).reset_index()

    # ----- PE Cred Data -----
    pe_data_cred = pe_data_cred.groupby(["organizations_uid"], as_index=False).agg(
        num_total_creds_exp=("total_creds", "sum"),
        num_creds_exp_password=("password_creds", "sum"),
    )

    # ----- PE Breach Data -----
    pe_data_breach = pe_data_breach.groupby(["organizations_uid"], as_index=False).agg(
        num_breaches=("breach_count", "sum"),
    )

    # ----- PE Dark Web Data -----
    pe_dw_mention_counts = (
        pe_data_dw.loc[pe_data_dw["alert_type"] == "MENTION"]
        .groupby(["organizations_uid"], as_index=False)
        .agg(num_dw_mention=("Count", "sum"))
    )
    pe_dw_threat_counts = (
        pe_data_dw.loc[pe_data_dw["alert_type"] == "POTENTIAL_THREAT"]
        .groupby(["organizations_uid"], as_index=False)
        .agg(num_dw_threat=("Count", "sum"))
    )
    pe_dw_asset_counts = (
        pe_data_dw.loc[pe_data_dw["alert_type"] == "ASSET"]
        .groupby(["organizations_uid"], as_index=False)
        .agg(num_dw_asset=("Count", "sum"))
    )
    pe_dw_invite_counts = (
        pe_data_dw.loc[pe_data_dw["alert_type"] == "INVITE-ONLY"]
        .groupby(["organizations_uid"], as_index=False)
        .agg(num_dw_invite=("Count", "sum"))
    )
    pe_data_dw = pd.merge(
        pd.merge(
            pd.merge(
                pe_dw_mention_counts,
                pe_dw_threat_counts,
                on="organizations_uid",
                how="outer",
            ),
            pe_dw_asset_counts,
            on="organizations_uid",
            how="outer",
        ),
        pe_dw_invite_counts,
        on="organizations_uid",
        how="outer",
    )
    pe_data_dw = pe_data_dw[
        [
            "organizations_uid",
            "num_dw_mention",
            "num_dw_threat",
            "num_dw_asset",
            "num_dw_invite",
        ]
    ]

    # ----- PE Protocol Data -----
    if pe_data_proto["organizations_uid"][0] == "test_org":
        pe_data_proto = pd.DataFrame(
            {
                "organizations_uid": "test_org",
                "num_unencrypt_protocol": 0,
                "num_affected_sockets": 0,
                "num_encrypt_protocol": 0,
                "percent_protocol_unencrypt": 0,
            },
            index=[0],
        )
    else:
        pe_data_proto = (
            pe_data_proto.drop(columns=["date"]).drop_duplicates().reset_index()
        )
        proto_unencrypt = (
            pe_data_proto.loc[pe_data_proto["protocol_type"] == "Unencrypted"]
            .groupby("organizations_uid", as_index=False)
            .agg(num_unencrypt_protocol=("protocol", "nunique"))
        )
        proto_affected_sockets = (
            (
                pe_data_proto.loc[
                    pe_data_proto["protocol_type"] == "Unencrypted",
                    ["organizations_uid", "port", "ip"],
                ]
            )
            .groupby("organizations_uid", as_index=False)
            .agg(num_affected_sockets=("port", "count"))
        )
        proto_encrypt = (
            pe_data_proto.loc[pe_data_proto["protocol_type"] == "Encrypted"]
            .groupby("organizations_uid", as_index=False)
            .agg(
                num_encrypt_protocol=("protocol", "nunique"),
            )
        )
        pe_data_proto = pd.merge(
            pd.merge(
                proto_unencrypt,
                proto_affected_sockets,
                on="organizations_uid",
                how="outer",
            ),
            proto_encrypt,
            on="organizations_uid",
            how="outer",
        ).fillna(0)
        pe_data_proto["percent_protocol_unencrypt"] = pe_data_proto[
            "num_unencrypt_protocol"
        ] / (
            pe_data_proto["num_unencrypt_protocol"]
            + pe_data_proto["num_encrypt_protocol"]
        )

    # Combine all PE data into single dataframe
    pe_data_df = pd.merge(
        pd.merge(
            pd.merge(
                pd.merge(
                    pd.merge(
                        org_list,
                        pe_data_vuln,
                        on="organizations_uid",
                        how="left",
                    ),
                    pe_data_cred,
                    on="organizations_uid",
                    how="left",
                ),
                pe_data_breach,
                on="organizations_uid",
                how="left",
            ),
            pe_data_dw,
            on="organizations_uid",
            how="left",
        ),
        pe_data_proto,
        on="organizations_uid",
        how="left",
    ).drop(columns=["cyhy_db_name", "index"])

    # --------------- Process WAS Data: ---------------
    # Requires 2 Views:
    # - vuln data: vw_ident_was_vuln
    # - historical vuln data: vw_ident_was_vuln_prev
    # ----- WAS Vuln Data -----
    # Set KEV flags
    was_data_vuln["is_kev"] = 0
    was_data_vuln["is_kev"] = np.where(
        was_data_vuln["cve_name"].isin(kev_list["kev"].values), 1, 0
    )
    # Set flags for low/med/high/crit KEVs
    [
        was_data_vuln["low_kev"],
        was_data_vuln["med_kev"],
        was_data_vuln["high_kev"],
        was_data_vuln["crit_kev"],
    ] = [
        np.where(
            (was_data_vuln["cvss_score"] < 4) & (was_data_vuln["is_kev"] == 1),
            1,
            0,
        ),
        np.where(
            (was_data_vuln["cvss_score"] >= 4)
            & (was_data_vuln["cvss_score"] < 7)
            & (was_data_vuln["is_kev"] == 1),
            1,
            0,
        ),
        np.where(
            (was_data_vuln["cvss_score"] >= 7)
            & (was_data_vuln["cvss_score"] < 9)
            & (was_data_vuln["is_kev"] == 1),
            1,
            0,
        ),
        np.where(
            (was_data_vuln["cvss_score"] >= 9) & (was_data_vuln["is_kev"] == 1),
            1,
            0,
        ),
    ]
    # Aggregate WAS vuln data
    was_data_vuln = was_data_vuln.groupby(["organizations_uid"], as_index=False).agg(
        was_total_num_vulns=("cvss_score", "count"),
        was_num_low_cve=("cvss_score", (lambda x: (x < 4).sum())),
        was_num_med_cve=("cvss_score", (lambda x: ((x >= 4) & (x < 7)).sum())),
        was_num_high_cve=("cvss_score", (lambda x: ((x >= 7) & (x < 9)).sum())),
        was_num_crit_cve=("cvss_score", (lambda x: (x >= 9).sum())),
        was_num_low_kev=("low_kev", "sum"),
        was_num_med_kev=("med_kev", "sum"),
        was_num_high_kev=("high_kev", "sum"),
        was_num_crit_kev=("crit_kev", "sum"),
        was_max_cvss=("cvss_score", "max"),
        was_avg_cvss=("cvss_score", "mean"),
        was_skewness_cvss=(
            "cvss_score",
            (
                # Calculating WAS skewness metric
                lambda x: (
                    (
                        # Q3
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.75) - 1]
                    )
                    + (
                        # Q1
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.25) - 1]
                    )
                    - (
                        2
                        * (
                            # Q2
                            x.sort_values()
                            .reset_index(drop=True)
                            .iloc[round(len(x) * 0.5) - 1]
                        )
                    )
                )
                / (
                    (
                        # Q3
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.75) - 1]
                    )
                    - (
                        # Q1
                        x.sort_values()
                        .reset_index(drop=True)
                        .iloc[round(len(x) * 0.25) - 1]
                    )
                )
            ),
        ),
        num_broken_access_ctrl=(
            "owasp_category",
            (lambda x: (x == "Broken Access Control").sum()),
        ),
        num_crypt_fail=(
            "owasp_category",
            (lambda x: (x == "Cryptographic Failures").sum()),
        ),
        num_injection=("owasp_category", (lambda x: (x == "Injection").sum())),
        num_insec_design=("owasp_category", (lambda x: (x == "Insecure Design").sum())),
        num_sec_misconfig=(
            "owasp_category",
            (lambda x: (x == "Security Misconfiguration").sum()),
        ),
        num_vuln_outdate_comp=(
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
            (lambda x: (x == "Server-Side Request Forgery (SSRF)").sum()),
        ),
    )
    # Handle NaNs in skewnesses
    was_data_vuln["was_skewness_cvss"].fillna(0, inplace=True)
    # Aggregate total WAS vulns of previous month
    was_data_vuln.insert(2, "was_net_chng_vulns", 0)
    # Select only most recent WAS vuln count for the prev report period
    was_data_vuln_prev = (
        (
            was_data_vuln_prev.sort_values("date")
            .groupby("organizations_uid", as_index=False)
            .tail(1)
        )
        .reset_index(drop=True)
        .drop(columns=["date"])
    )
    was_data_vuln = pd.merge(
        was_data_vuln, was_data_vuln_prev, on="organizations_uid", how="outer"
    )
    # If no data from previous report period, set net change to 0
    was_data_vuln["was_total_vulns_prev"].fillna(
        was_data_vuln["was_total_num_vulns"], inplace=True
    )
    # Otherwise, calculate net change in vulns
    was_data_vuln["was_net_chng_vulns"] = (
        was_data_vuln["was_total_num_vulns"] - was_data_vuln["was_total_vulns_prev"]
    )
    was_data_vuln = was_data_vuln.drop(columns=["was_total_vulns_prev"]).reset_index()
    was_data_df = pd.merge(
        org_list, was_data_vuln, on="organizations_uid", how="left"
    ).drop(columns=["cyhy_db_name", "index"])

    # --------------- Process PCA Data: ---------------
    # *** PCA data excluded for now
    pca_data_df = pd.DataFrame(
        {
            # General Identifiers
            "cyhy_db_name": "",
            # Phishing Metrics
            "total_phish_sent": 0,
            "total_phish_resp": 0,
            "overall_resp_rate": 0,
            "low_resp_rate": 0,
            "med_resp_rate": 0,
            "high_resp_rate": 0,
        },
        index=[0],
    )
    pca_data_df = (
        pd.merge(org_list, pca_data_df, on="cyhy_db_name", how="left")
        .fillna(0)
        .drop(columns="cyhy_db_name")
    )

    # --------------- Combine All Team Data into Single Dataframe: ---------------
    # Combining team dataframes
    ident_data_df = pd.merge(
        pd.merge(
            pd.merge(
                pd.merge(
                    org_list,
                    vs_data_df,
                    on="organizations_uid",
                    how="left",
                ),
                pe_data_df,
                on="organizations_uid",
                how="left",
            ),
            was_data_df,
            on="organizations_uid",
            how="left",
        ),
        pca_data_df,
        on="organizations_uid",
        how="left",
    )

    # Return the completed DF
    return ident_data_df


# ---------- Calculate I-Score Function ----------
def calc_ident_scores(ident_data, stakeholder_list):
    """
    Calculate Identification Scores for the specified stakeholder list.

    Args:
        ident_data: The dataframe of I-Score data for this specific sector
        stakeholder_list: The specific list orgs that you want to generate I-Scores for
    Returns:
        Dataframe containing I-Score/letter grade for each org in the specified stakeholder list
    """
    ident_data_df = ident_data
    print(ident_data_df)
    print(ident_data_df[["num_unencrypt_protocol", "num_encrypt_protocol"]])
    # Impute column means to use for filling in missing data later
    col_means = ident_data_df.mean()

    # ---------- VS-Subscribed Data ----------
    # Index locations of VS vuln metrics
    vs_vuln_locs = [2] + list(range(4, 14))

    # VS Net Change Vulns. Feature:
    # Check if std is positive, non-zero (i.e. not all the same number)
    if ident_data_df["vs_net_chng_vulns"].std() != 0:
        # Re-scale values to be between -1 and 1
        vs_net_chng_max_abs = ident_data_df["vs_net_chng_vulns"].abs().max()
        ident_data_df["vs_net_chng_vulns"] = (
            ident_data_df["vs_net_chng_vulns"] / vs_net_chng_max_abs
        )
    else:
        # Just set all to 0 b/c they're all the same number
        ident_data_df["vs_net_chng_vulns"] = 0
    # The maximum amount the VS net change in vulns feature can change metrics
    vs_net_chng_mod_limit = 0.20
    # Calculate multipliers for each organization
    vs_net_chng_multipliers = 1 + (
        ident_data_df["vs_net_chng_vulns"] * vs_net_chng_mod_limit
    )

    # VS CVSS Skewness Feature:
    # The maximum amount the VS skewness feature can change metrics
    vs_skewness_mod_limit = 0.20
    # Calculate multipliers for each organization
    vs_skewness_multipliers = 1 + (
        ident_data_df["vs_skewness_cvss"] * vs_skewness_mod_limit * -1
    )

    # Average vuln multipliers together:
    vs_vuln_multipliers = (vs_net_chng_multipliers + vs_skewness_multipliers) / 2
    # Administer overall penalty/reward to vuln metrics
    ident_data_df.iloc[:, vs_vuln_locs] = ident_data_df.iloc[:, vs_vuln_locs].apply(
        lambda x: x * vs_vuln_multipliers
    )

    # ---------- PE-Subscribed Data ----------
    # Index locations of PE vuln metrics
    pe_vuln_locs = [15] + list(range(17, 27))
    # Index locations of PE dark web metrics
    pe_dw_locs = list(range(31, 35))
    # Index locations of PE protocol metrics
    pe_proto_locs = list(range(35, 37))

    # PE Net Change Vulns. Feature:
    # Check if std is positive, non-zero (i.e. not all the same number)
    if ident_data_df["pe_net_chng_vulns"].std() != 0:
        # Re-scale values to be between -1 and 1
        pe_net_chng_max_abs = ident_data_df["pe_net_chng_vulns"].abs().max()
        ident_data_df["pe_net_chng_vulns"] = (
            ident_data_df["pe_net_chng_vulns"] / pe_net_chng_max_abs
        )
    else:
        # Just set all to 0 b/c they're all the same number
        ident_data_df["pe_net_chng_vulns"] = 0
    # The maximum amount the PE net change feature can change a metric
    pe_net_chng_mod_limit = 0.20
    # Calculate multipliers for each organization
    pe_net_chng_multipliers = 1 + (
        ident_data_df["pe_net_chng_vulns"] * pe_net_chng_mod_limit
    )

    # PE CVSS Skewness Feature:
    # The maximum amount the PE skewness feature can change metrics
    pe_skewness_mod_limit = 0.20
    # Calculate multipliers for each organization
    pe_skewness_multipliers = 1 + (
        ident_data_df["pe_skewness_cvss"] * pe_skewness_mod_limit * -1
    )

    # Average vuln multipliers together:
    pe_vuln_multipliers = (pe_net_chng_multipliers + pe_skewness_multipliers) / 2
    # Administer overall penalty/reward to vuln metrics
    ident_data_df.iloc[:, pe_vuln_locs] = ident_data_df.iloc[:, pe_vuln_locs].apply(
        lambda x: x * pe_vuln_multipliers
    )

    # Dark Web Mention Feature:
    if ident_data_df["num_dw_mention"].std() != 0:
        # Convert dark web mentions into z-scores
        dw_mention_avg = ident_data_df["num_dw_mention"].mean()
        dw_mention_std = ident_data_df["num_dw_mention"].std()
        dw_mention_zscores = (
            ident_data_df["num_dw_mention"] - dw_mention_avg
        ) / dw_mention_std
    else:
        # Just set all to 0 b/c they're all the same number
        dw_mention_zscores = pd.Series(
            0, index=np.arange(len(ident_data_df["num_dw_mention"]))
        )
    # The maximum amount the PE dark web mention feature can change metrics
    pe_dw_mention_mod_limit = 0.20
    # Calculate multipliers for each organization
    pe_dw_mention_multipliers = pd.Series(
        np.where(dw_mention_zscores > 3, (1 + pe_dw_mention_mod_limit), 1)
    )
    # Administer penalty to positive outliers where z-score > +3
    ident_data_df.iloc[:, pe_dw_locs] = ident_data_df.iloc[:, pe_dw_locs].apply(
        lambda x: x * pe_dw_mention_multipliers
    )

    # Percent Unencrypted Protocol Feature:
    # Check if std dev is positive, non-zero (i.e. not all the same number)
    if ident_data_df["percent_protocol_unencrypt"].std() != 0:
        # Convert overall unencrypted protocol percentage to z-scores
        percent_unencrypt_avg = ident_data_df["percent_protocol_unencrypt"].mean()
        percent_unencrypt_std = ident_data_df["percent_protocol_unencrypt"].std()
        ident_data_df["percent_protocol_unencrypt"] = (
            ident_data_df["percent_protocol_unencrypt"] - percent_unencrypt_avg
        ) / percent_unencrypt_std
        # Re-scale z-score values to be between -1 and 1
        percent_unencrypt_max_abs_zscore = (
            ident_data_df["percent_protocol_unencrypt"].abs().max()
        )
        ident_data_df["percent_protocol_unencrypt"] = (
            ident_data_df["percent_protocol_unencrypt"]
            / percent_unencrypt_max_abs_zscore
        )
    else:
        # Just set all to 0 b/c they're all the same number
        ident_data_df["percent_protocol_unencrypt"] = 0
    # Calculate penalty/reward based on z-score values
    pe_proto_modifier = 0.20
    pe_proto_multipliers = 1 + (
        ident_data_df["percent_protocol_unencrypt"] * pe_proto_modifier
    )
    # Administer penalty/reward based on percentage z-score value
    ident_data_df.iloc[:, pe_proto_locs] = ident_data_df.iloc[:, pe_proto_locs].apply(
        lambda x: x * pe_proto_multipliers
    )

    # ---------- WAS-Subscribed Data ----------
    # Index locations of WAS vuln metrics
    was_vuln_locs = [39] + list(range(41, 51))

    # WAS Net Change Vulns. Feature:
    # Check if std is positive, non-zero (i.e. not all the same number)
    if ident_data_df["was_net_chng_vulns"].std() != 0:
        # Re-scale values to be between -1 and 1
        was_net_chng_max_abs = ident_data_df["was_net_chng_vulns"].abs().max()
        ident_data_df["was_net_chng_vulns"] = (
            ident_data_df["was_net_chng_vulns"] / was_net_chng_max_abs
        )
    else:
        # Just set all to 0 b/c they're all the same number
        ident_data_df["was_net_chng_vulns"] = 0
    # The maximum amount the WAS net change feature can change a metric
    was_net_chng_mod_limit = 0.20
    # Calculate multipliers for each organization
    was_net_chng_multipliers = 1 + (
        ident_data_df["was_net_chng_vulns"] * was_net_chng_mod_limit
    )

    # WAS CVSS Skewness Feature:
    # The maximum amount the WAS skewness feature can change metrics
    was_skewness_mod_limit = 0.20
    # Calculate multipliers for each organization
    was_skewness_multipliers = 1 + (
        ident_data_df["was_skewness_cvss"] * was_skewness_mod_limit * -1
    )

    # Average vuln multipliers together:
    was_vuln_multipliers = (was_net_chng_multipliers + was_skewness_multipliers) / 2
    # Administer overall penalty/reward to vuln metrics
    ident_data_df.iloc[:, was_vuln_locs] = ident_data_df.iloc[:, was_vuln_locs].apply(
        lambda x: x * was_vuln_multipliers
    )

    # ---------- PCA-Subscribed Data ----------
    # Not using PCA for I-Score (maybe in the future?)

    # ---------- Impute Missing Data ----------
    # Use these column means calculated earlier to fill any missing data due to partial subscriptions
    ident_data_df.fillna(col_means, inplace=True)

    # ---------- Aggregate Metrics ----------
    # Re-Scale metrics to be between [0, 45]
    for col_idx in range(2, 68):
        ident_data_df.iloc[:, col_idx] = rescale(ident_data_df.iloc[:, col_idx], 45, 0)

    # If there are still NA's remaining in the data at this point,
    # then that means one of the cyhy teams has absolutely 0 subscribers
    # In this case, force completely missing team data to be 11.25
    # which is the equivalent of getting a 75% for a team section (C)
    ident_data_df.fillna(11.25, inplace=True)

    # Combine metrics into subsection totals
    # VS Subsections:
    ident_data_df["vs_vuln_subsection"] = ident_data_df["vs_total_num_vulns"]
    ident_data_df["vs_cvss_subsection"] = (
        (ident_data_df["vs_num_low_cve"] * 0.06)
        + (ident_data_df["vs_num_med_cve"] * 0.08)
        + (ident_data_df["vs_num_high_cve"] * 0.10)
        + (ident_data_df["vs_num_crit_cve"] * 0.12)
        + (ident_data_df["vs_num_low_kev"] * 0.08)
        + (ident_data_df["vs_num_med_kev"] * 0.10)
        + (ident_data_df["vs_num_high_kev"] * 0.12)
        + (ident_data_df["vs_num_crit_kev"] * 0.14)
        + (ident_data_df["vs_max_cvss"] * 0.1)
        + (ident_data_df["vs_avg_cvss"] * 0.1)
    )
    # PE Subsections:
    ident_data_df["pe_vuln_subsection"] = ident_data_df["pe_total_num_vulns"]
    ident_data_df["pe_cvss_subsection"] = (
        (ident_data_df["pe_num_low_cve"] * 0.06)
        + (ident_data_df["pe_num_med_cve"] * 0.08)
        + (ident_data_df["pe_num_high_cve"] * 0.10)
        + (ident_data_df["pe_num_crit_cve"] * 0.12)
        + (ident_data_df["pe_num_low_kev"] * 0.08)
        + (ident_data_df["pe_num_med_kev"] * 0.10)
        + (ident_data_df["pe_num_high_kev"] * 0.12)
        + (ident_data_df["pe_num_crit_kev"] * 0.14)
        + (ident_data_df["pe_max_cvss"] * 0.1)
        + (ident_data_df["pe_avg_cvss"] * 0.1)
    )
    ident_data_df["pe_cred_subsection"] = (
        (ident_data_df["num_total_creds_exp"] * 0.3)
        + (ident_data_df["num_creds_exp_password"] * 0.5)
        + (ident_data_df["num_breaches"] * 0.2)
    )
    ident_data_df["pe_dw_subsection"] = (
        (ident_data_df["num_dw_mention"] * 0.3)
        + (ident_data_df["num_dw_threat"] * 0.3)
        + (ident_data_df["num_dw_asset"] * 0.2)
        + (ident_data_df["num_dw_invite"] * 0.2)
    )
    ident_data_df["pe_proto_subsection"] = (
        ident_data_df["num_unencrypt_protocol"] * 0.6
    ) + (ident_data_df["num_affected_sockets"] * 0.4)
    # WAS Subsections:
    ident_data_df["was_vuln_subsection"] = ident_data_df["was_total_num_vulns"]
    ident_data_df["was_cvss_subsection"] = (
        (ident_data_df["was_num_low_cve"] * 0.06)
        + (ident_data_df["was_num_med_cve"] * 0.08)
        + (ident_data_df["was_num_high_cve"] * 0.10)
        + (ident_data_df["was_num_crit_cve"] * 0.12)
        + (ident_data_df["was_num_low_kev"] * 0.08)
        + (ident_data_df["was_num_med_kev"] * 0.10)
        + (ident_data_df["was_num_high_kev"] * 0.12)
        + (ident_data_df["was_num_crit_kev"] * 0.14)
        + (ident_data_df["was_max_cvss"] * 0.1)
        + (ident_data_df["was_avg_cvss"] * 0.1)
    )
    ident_data_df["was_owasp_subsection"] = (
        (ident_data_df["num_broken_access_ctrl"] * 0.14)
        + (ident_data_df["num_crypt_fail"] * 0.14)
        + (ident_data_df["num_injection"] * 0.12)
        + (ident_data_df["num_insec_design"] * 0.12)
        + (ident_data_df["num_sec_misconfig"] * 0.10)
        + (ident_data_df["num_vuln_outdate_comp"] * 0.10)
        + (ident_data_df["num_ident_auth_fail"] * 0.08)
        + (ident_data_df["num_soft_data_integ_fail"] * 0.08)
        + (ident_data_df["num_sec_log_monitor_fail"] * 0.06)
        + (ident_data_df["num_ssrf"] * 0.06)
    )
    # PCA Subsections: (will be excluded)
    ident_data_df["pca_subsection"] = (
        (ident_data_df["total_phish_resp"] * 0.40)
        + (ident_data_df["low_resp_rate"] * 0.15)
        + (ident_data_df["med_resp_rate"] * 0.20)
        + (ident_data_df["high_resp_rate"] * 0.25)
    )

    # Combine subsections into team sections
    # VS Section:
    ident_data_df["vs_section"] = (ident_data_df["vs_vuln_subsection"] * 0.3) + (
        ident_data_df["vs_cvss_subsection"] * 0.7
    )
    # PE Section:
    ident_data_df["pe_section"] = (
        (ident_data_df["pe_vuln_subsection"] * 0.2)
        + (ident_data_df["pe_cvss_subsection"] * 0.3)
        + (ident_data_df["pe_cred_subsection"] * 0.2)
        + (ident_data_df["pe_dw_subsection"] * 0.1)
        + (ident_data_df["pe_proto_subsection"] * 0.2)
    )
    # WAS Section:
    ident_data_df["was_section"] = (
        (ident_data_df["was_vuln_subsection"] * 0.2)
        + (ident_data_df["was_cvss_subsection"] * 0.6)
        + (ident_data_df["was_owasp_subsection"] * 0.2)
    )
    # PCA Section:
    ident_data_df["pca_section"] = ident_data_df["pca_subsection"]

    # Combine team sections into single value
    ident_data_df["ident_score"] = (
        (ident_data_df["vs_section"] * 0.50)
        + (ident_data_df["pe_section"] * 0.20)
        + (ident_data_df["was_section"] * 0.30)
    )

    # Take complement of that single value
    ident_data_df["ident_score"] = (
        (100 - ident_data_df["ident_score"]).astype(float).round(2)
    )
    ident_data_df = ident_data_df.sort_values(
        by="ident_score", ascending=False
    ).reset_index(drop=True)

    # Convert to letter grade
    letter_ranges = [
        ident_data_df["ident_score"] < 65,  # F
        (ident_data_df["ident_score"] >= 65) & (ident_data_df["ident_score"] < 67),  # D
        (ident_data_df["ident_score"] >= 67)
        & (ident_data_df["ident_score"] < 70),  # D+
        (ident_data_df["ident_score"] >= 70)
        & (ident_data_df["ident_score"] < 73),  # C-
        (ident_data_df["ident_score"] >= 73) & (ident_data_df["ident_score"] < 77),  # C
        (ident_data_df["ident_score"] >= 77)
        & (ident_data_df["ident_score"] < 80),  # C+
        (ident_data_df["ident_score"] >= 80)
        & (ident_data_df["ident_score"] < 83),  # B-
        (ident_data_df["ident_score"] >= 83) & (ident_data_df["ident_score"] < 87),  # B
        (ident_data_df["ident_score"] >= 87)
        & (ident_data_df["ident_score"] < 90),  # B+
        (ident_data_df["ident_score"] >= 90)
        & (ident_data_df["ident_score"] < 93),  # A-
        (ident_data_df["ident_score"] >= 93) & (ident_data_df["ident_score"] < 97),  # A
        (ident_data_df["ident_score"] >= 97)
        & (ident_data_df["ident_score"] <= 100),  # A+
    ]
    letter_grades = ["F", "D", "D+", "C-", "C", "C+", "B-", "B", "B+", "A-", "A", "A+"]
    ident_data_df["letter_grade"] = np.select(letter_ranges, letter_grades)

    # Isolate final I-Score data
    ident_data_df = ident_data_df[["organizations_uid", "ident_score", "letter_grade"]]

    # Reintroduce cyhy_db_name and sort
    ident_data_df = pd.merge(
        stakeholder_list, ident_data_df, on="organizations_uid", how="inner"
    ).sort_values(by="ident_score", ascending=False, ignore_index=True)

    # Return finished identification score dataframe
    return ident_data_df


# ---------- Main I-Score Function -----------
def gen_ident_scores(curr_date, stakeholder_list):
    """
    Generate the Identification Scores for each of the stakeholder sector groups.

    Args:
        curr_date: current report period date (i.e. 20xx-xx-30 or 20xx-xx-31)
        stakeholder_list: dataframe containing the organizations_uid and cyhy_db_name of all the orgs to generate scores for
    Returns:
        List of dataframes containing the I-Scores/letter grades for each stakeholder sector group
    """
    # Calculate start/end dates of current and previous report periods
    report_periods = get_prev_startstop(curr_date, 4)
    [prev_start, prev_end, curr_start, curr_end] = [
        report_periods[0][0],
        report_periods[1][1],
        report_periods[2][0],
        report_periods[3][1],
    ]

    # Query I-Score data for this sector
    iscore_data = import_ident_data(
        prev_start, prev_end, curr_start, curr_end, stakeholder_list
    )

    # Calculate I-Scores for this sector
    iscores = calc_ident_scores(iscore_data, stakeholder_list)
    LOGGER.info(f"Finished calculating I-Scores for {curr_date}")

    # Return list of finished i-score dataframes
    return iscores


# Demo/Performance Notes:

# Usage:
# To get I-Scores, call the function -> gen_discov_score(curr_date, stakeholder_list)
# ex:
#   curr_date = datetime.datetime(2023, 3, 31)
#   xs_fceb = query_xs_stakeholder_list()
#   iscores = gen_ident_score(curr_date, xs_fceb)
#
# This will return a dataframe containing the i-scores for the
# specified list of stakeholders/report period.

# Once you have the i-scores, plug that info
# into the dictionary to display on the scorecard
