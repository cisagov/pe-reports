"""A tool for creating CISA unified scorecard.

Usage:
  pe-scorecard REPORT_MONTH REPORT_YEAR OUTPUT_DIRECTORY [--log-level=LEVEL]

Options:
  -h --help                         Show this message.
  REPORT_MONTH                      Numeric month, format MM
  REPORT_YEAR                       Numeric year, format YYYY
  OUTPUT_DIRECTORY                  The directory where the final PDF
                                    reports should be saved.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
"""

# Standard Python Libraries
import logging
import os
import sys
from typing import Any, Dict

# Third-Party Libraries
import docopt
from schema import And, Schema, SchemaError, Use

# cisagov Libraries
import pe_scorecard

from ._version import __version__
from .data.db_query import get_orgs
from .metrics import Scorecard

LOGGER = logging.getLogger(__name__)
ACCESSOR_AWS_PROFILE = os.getenv("ACCESSOR_PROFILE")


def generate_scorecards(month, year, output_directory):
    """Generate scorecards for approved orgs."""
    scorecard_orgs = get_orgs()

    # generated_scorecards = 0

    if not scorecard_orgs.empty:
        LOGGER.info("Orgs count: %d", len(scorecard_orgs))

        # If we need to generate all scores first, do so here:

        for index, org in scorecard_orgs.iterrows():
            if org["fceb"]:
                if org["cyhy_db_name"] not in ["DHS"]:
                    continue
                if org["is_parent"]:
                    # Gather list of children orgs
                    children_df = scorecard_orgs[
                        scorecard_orgs["parent_org_uid"] == org["organizations_uid"]
                    ]
                    org_uid_list = children_df["organizations_uid"].values.tolist()
                    org_uid_list.append(org["organizations_uid"])
                    cyhy_id_list = children_df["cyhy_db_name"].values.tolist()
                    cyhy_id_list.append(org["cyhy_db_name"])

                else:
                    org_uid_list = [org["organizations_uid"]]
                    cyhy_id_list = [org["cyhy_db_name"]]

                scorecard = Scorecard(month, year, org, org_uid_list, cyhy_id_list)
                scorecard.calculate_profiling_metrics()
                # scorecard.calculate_ips_counts()
                # print(scorecard.scorecard_dict)


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
    )

    # Stop logging and clean up
    logging.shutdown()
