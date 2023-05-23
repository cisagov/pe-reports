"""A tool for creating CISA unified scorecard.

Usage:
  pe-scorecard REPORT_MONTH REPORT_YEAR OUTPUT_DIRECTORY [--log-level=LEVEL] [--orgs=ORG_LIST] [--email] [--cancel-refresh] [--exclude_bods]

Options:
  -h --help                         Show this message.
  REPORT_MONTH                      Numeric month, format MM
  REPORT_YEAR                       Numeric year, format YYYY
  OUTPUT_DIRECTORY                  The directory where the final PDF
                                    reports should be saved.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
  -s --sectors=SECTOR_LIST          A comma-separated list of sectors to generate scorecards for.
                                    If not specified, scorecards will be generated for all sectors
                                    marked with the run_scorecard flag. If orgs are provided, the orgs
                                    will be run against the given sectors if they are linked.
                                    [default: all]
  -o --orgs=ORG_LIST                A comma-separated list of orgs to generate a scorecard for.
                                    If not specified, scorecards will be generated for all orgs
                                    related to a flagged scorecard. Orgs must be linked to a provided sector.
                                    Orgs in the list must match the IDs in the cyhy-db. E.g. DHS,DHS_ICE,DOC
                                    [default: all]
  -m --email                        If included, email report [default: False]
  -x --cancel-refresh               If included, don't refresh materialized views [default: False]
  -b --exclude_bods                 If included, bod data will be excluded [default: False]
"""

# Standard Python Libraries
import datetime
import logging
import os
import sys
import traceback
from typing import Any, Dict

# Third-Party Libraries
import docopt
import numpy as np
from schema import And, Schema, SchemaError, Use

# cisagov Libraries
import pe_scorecard

from ._version import __version__

# from .average_time_to_remediate import calculate_time_to_remediate
from .data.db_query import (
    execute_scorecard_summary_data,
    find_sub_sectors,
    get_scorecard_orgs,
    get_scorecard_sectors,
    insert_scores,
    query_scorecard_data,
    query_sector_ttr,
    query_was_sector_ttr,
    refresh_views,
)

# from .helpers.email_scorecard import email_scorecard_report
from .metrics import Scorecard
from .scores.generate_d_score import gen_discov_scores
from .scores.generate_i_score import gen_ident_scores
from .scores.profiling_score import get_profiling_score
from .scores.tracking_score import get_tracking_score
from .unified_scorecard_generator import create_scorecard

LOGGER = logging.getLogger(__name__)
ACCESSOR_AWS_PROFILE = os.getenv("ACCESSOR_PROFILE")


def generate_scorecards(
    month,
    year,
    output_directory,
    user_sectors_list="all",
    orgs_list="all",
    email=False,
    cancel_refresh=False,
    exclude_bods=False,
):
    """Generate scorecards for approved orgs."""
    # Get sectors flagged to run scorecards
    scorecard_sectors = get_scorecard_sectors()
    # Create a list of sector ids
    sectors = scorecard_sectors["id"].unique().tolist()
    # Query all the orgs associated with flagged sectors
    scorecard_orgs = get_scorecard_orgs()

    # report_orgs = scorecard_orgs[scorecard_orgs['receives_cyhy_report'] == True]

    # sectors = scorecard_orgs['sector_id'].unique().tolist()

    # Filter sectors down to user provided list
    if user_sectors_list != "all":
        temp_sectors = []
        for sector in user_sectors_list.split(","):
            if sector not in sectors:
                LOGGER.warning("%s is not set up to generate scorecards", sector)
            else:
                temp_sectors.append(sector)
        sectors = temp_sectors

    LOGGER.info("Running on the following sectors: %s", ",".join(map(str, sectors)))

    # Refresh materialized views unless canceled
    if not cancel_refresh:
        LOGGER.info("Refreshing Views")
        refresh_views()

    start_date = datetime.date(int(year), int(month), 1)
    end_date = (start_date + datetime.timedelta(days=32)).replace(day=1)
    failed = []
    # Loop through each selected sector
    for sector in sectors:
        # Query children sectors of a given sector that may link to orgs
        all_related_sectors = find_sub_sectors(sector)["id"].values.tolist()
        # Query orgs that can have scorecards delivered to them
        recipient_sector_orgs = scorecard_orgs[
            scorecard_orgs["sector_id"].isin(all_related_sectors)
            and scorecard_orgs["receives_cyhy_report"] == True
        ]
        # Query all orgs in the sector
        sector_orgs = scorecard_orgs[
            scorecard_orgs["sector_id"].isin(all_related_sectors)
        ]
        # If not "all", separate orgs string into a list of orgs
        if orgs_list == "all":
            recipient_orgs_df = recipient_sector_orgs
        else:
            # orgs_list = orgs_list.split(",")
            recipient_orgs_df = recipient_sector_orgs[
                recipient_sector_orgs["cyhy_db_name"].isin(orgs_list.split(","))
            ]

        if len(recipient_orgs_df) == 0:
            LOGGER.info("No orgs were identified for %s", sector)
            continue

        # Calculate sector level data
        (avg_time_to_remediate_df, vs_sector_results) = query_sector_ttr(
            int(month), int(year), sector
        )
        was_sector_ttr = query_was_sector_ttr(start_date, sector)

        # Loop through orgs that will get scorecards
        for i, org in recipient_orgs_df.iterrows():
            try:
                LOGGER.info(
                    "RUNNING SCORECARD ON %s in the %s sector",
                    org["cyhy_db_name"],
                    sector,
                )
                # If org is a parent grab the children to be included in rollup
                if org["is_parent"]:
                    children_df = sector_orgs[
                        (sector_orgs["parent_org_uid"] == org["organizations_uid"])
                        & (sector_orgs["retired"] == False)
                    ]
                    org_uid_list = children_df["organizations_uid"].values.tolist()
                    org_uid_list.append(org["organizations_uid"])
                    cyhy_id_list = children_df["cyhy_db_name"].values.tolist()
                    cyhy_id_list.append(org["cyhy_db_name"])

                else:
                    org_uid_list = [org["organizations_uid"]]
                    cyhy_id_list = [org["cyhy_db_name"]]

                # Calculate rollup level datapoints
                vs_time_to_remediate = avg_time_to_remediate_df[
                    avg_time_to_remediate_df["cyhy_db_name"].isin(cyhy_id_list)
                ]

                total_kevs = vs_time_to_remediate["kev_count"].sum()
                vs_time_to_remediate["weighted_kev"] = (
                    vs_time_to_remediate["kev_count"] / total_kevs
                ) * vs_time_to_remediate["kev_ttr"]

                total_critical = vs_time_to_remediate["critical_count"].sum()
                vs_time_to_remediate["weighted_critical"] = (
                    vs_time_to_remediate["critical_count"] / total_critical
                ) * vs_time_to_remediate["critical_ttr"]

                total_high = vs_time_to_remediate["high_count"].sum()
                vs_time_to_remediate["weighted_high"] = (
                    vs_time_to_remediate["high_count"] / total_high
                ) * vs_time_to_remediate["high_ttr"]

                # Instantiate Scorecard Variable
                scorecard = Scorecard(
                    month,
                    year,
                    sector,
                    org,
                    org_uid_list,
                    cyhy_id_list,
                    vs_time_to_remediate,
                    vs_sector_results,
                    was_sector_ttr,
                )
                scorecard.fill_scorecard_dict()

                # Insert dictionary into the summary table
                execute_scorecard_summary_data(scorecard.scorecard_dict)

            except Exception as e:
                LOGGER.error("Scorecard failed for %s: %s", org["cyhy_db_name"], e)
                LOGGER.error(traceback.format_exc())
                failed += org["cyhy_db_name"]

        # Calculate scores
        sectors_df = sector_orgs[["organizations_uid", "cyhy_db_name"]]
        discovery_scores = gen_discov_scores(
            end_date - datetime.timedelta(days=1), sectors_df
        )
        profiling_scores = get_profiling_score(sectors_df, year, month)
        identification_scores = gen_ident_scores(
            end_date - datetime.timedelta(days=1), sectors_df
        )
        tracking_scores = get_tracking_score(sectors_df, year, month)

        # Loop through orgs again to generate scorecards
        for i, org in recipient_orgs_df.iterrows():
            try:
                # Grab score and insert into database
                discovery_score = discovery_scores.loc[
                    discovery_scores["organizations_uid"] == org["organizations_uid"],
                    "discov_score",
                ].item()
                discovery_grade = discovery_scores.loc[
                    discovery_scores["organizations_uid"] == org["organizations_uid"],
                    "letter_grade",
                ].item()
                insert_scores(
                    start_date,
                    org["organizations_uid"],
                    discovery_score,
                    "discovery_score",
                    sector,
                )
                profiling_score = profiling_scores.loc[
                    profiling_scores["organizations_uid"] == org["organizations_uid"],
                    "profiling_score",
                ].item()
                profiling_grade = profiling_scores.loc[
                    profiling_scores["organizations_uid"] == org["organizations_uid"],
                    "letter_grade",
                ].item()
                insert_scores(
                    start_date,
                    org["organizations_uid"],
                    profiling_score,
                    "profiling_score",
                    sector,
                )
                identification_score = identification_scores.loc[
                    identification_scores["organizations_uid"]
                    == org["organizations_uid"],
                    "ident_score",
                ].item()
                identification_grade = identification_scores.loc[
                    identification_scores["organizations_uid"]
                    == org["organizations_uid"],
                    "letter_grade",
                ].item()
                insert_scores(
                    start_date,
                    org["organizations_uid"],
                    identification_score,
                    "identification_score",
                    sector,
                )
                tracking_score = tracking_scores.loc[
                    tracking_scores["organizations_uid"] == org["organizations_uid"],
                    "tracking_score",
                ].item()
                tracking_grade = tracking_scores.loc[
                    tracking_scores["organizations_uid"] == org["organizations_uid"],
                    "letter_grade",
                ].item()
                insert_scores(
                    start_date,
                    org["organizations_uid"],
                    tracking_score,
                    "tracking_score",
                    sector,
                )

                # Calculate Overall Score
                overall_score = (
                    (discovery_score * 0.2)
                    + (profiling_score * 0.2)
                    + (identification_score * 0.3)
                    + (tracking_score * 0.3)
                )
                insert_scores(
                    start_date,
                    org["organizations_uid"],
                    overall_score,
                    "score",
                    sector,
                )

                letter_ranges = [
                    overall_score < 65,  # F
                    (overall_score >= 65) & (overall_score < 67),  # D
                    (overall_score >= 67) & (overall_score < 70),  # D+
                    (overall_score >= 70) & (overall_score < 73),  # C-
                    (overall_score >= 73) & (overall_score < 77),  # C
                    (overall_score >= 77) & (overall_score < 80),  # C+
                    (overall_score >= 80) & (overall_score < 83),  # B-
                    (overall_score >= 83) & (overall_score < 87),  # B
                    (overall_score >= 87) & (overall_score < 90),  # B+
                    (overall_score >= 90) & (overall_score < 93),  # A-
                    (overall_score >= 93) & (overall_score < 97),  # A
                    (overall_score >= 97) & (overall_score <= 100),  # A+
                ]
                letter_grades = [
                    "F",
                    "D",
                    "D+",
                    "C-",
                    "C",
                    "C+",
                    "B-",
                    "B",
                    "B+",
                    "A-",
                    "A",
                    "A+",
                ]
                # Query the data for the scorecard
                scorecard_dict = query_scorecard_data(
                    org["organizations_uid"], start_date, sector
                )
                scorecard_dict["score"] = np.select(letter_ranges, letter_grades)
                # # Add scores to scorecard_dict
                # scorecard_dict['discovery_score'] = discovery_score
                scorecard_dict["discovery_grade"] = discovery_grade
                # scorecard_dict['profiling_score'] = profiling_score
                scorecard_dict["profiling_grade"] = profiling_grade
                # scorecard_dict['identification_score'] = identification_score
                scorecard_dict["identification_grade"] = identification_grade
                # scorecard_dict['tracking_score'] = tracking_score
                scorecard_dict["tracking_grade"] = tracking_grade

                # Create filename
                file_name = (
                    output_directory
                    + "/scorecard_"
                    + scorecard_dict["agency_id"]
                    + "_"
                    + scorecard_dict["sector_name"]
                    + "_"
                    + start_date.strftime("%b-%Y")
                    + ".pdf"
                )

                # Create Scorecard
                create_scorecard(scorecard_dict, file_name, True, False, exclude_bods)

                # If email, email the report out to customer
                # if email:
                #     # TODO: Encrypt the report
                #     email_scorecard_report(org["cyhy_db_name"], filename, month, year)

            except Exception as e:
                LOGGER.error("Scorecard failed for %s: %s", org["cyhy_db_name"], e)
                LOGGER.error(traceback.format_exc())
                failed += org["cyhy_db_name"]


def main():
    """Generate PDF reports."""
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)

    # Validate and convert arguments as needed
    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning", "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            str: object,  # Don't care about other keys, if any
        }
    )

    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)

    # Assign validated arguments to variables
    log_level: str = validated_args["--log-level"]

    # Setup logging to central file
    logging.basicConfig(
        filename=pe_scorecard.CENTRAL_LOGGING_FILE,
        filemode="a",
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S",
        level=log_level.upper(),
    )

    LOGGER.info("Loading Scorecard Report, Version : %s", __version__)

    # Create output directory
    if not os.path.exists(validated_args["OUTPUT_DIRECTORY"]):
        os.mkdir(validated_args["OUTPUT_DIRECTORY"])

    # Generate reports
    generate_scorecards(
        validated_args["REPORT_MONTH"],
        validated_args["REPORT_YEAR"],
        validated_args["OUTPUT_DIRECTORY"],
        validated_args["--sectors"],
        validated_args["--orgs"],
        validated_args["--email"],
        validated_args["--cancel-refresh"],
        validated_args["--exclude_bods"],
    )

    # Stop logging and clean up
    logging.shutdown()
