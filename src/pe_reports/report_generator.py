"""A tool for creating Posture & Exposure reports.

Usage:
    pe-reports REPORT_DATE DATA_DIRECTORY OUTPUT_DIRECTORY [--db-creds-file=FILENAME] [--log-level=LEVEL]

Arguments:
  REPORT_DATE                   Date of the report, format YYYY-MM-DD.
  DATA_DIRECTORY                The directory where the Excel data files are located.
                                Organized by owner.
  OUTPUT_DIRECTORY              The directory where the final PDF reports should be saved.
  -c --db-creds-file=FILENAME   A YAML file containing the Cyber
                                Hygiene database credentials.
                                [default: /secrets/database_creds.yml]

Options:
  -h --help                     Show this message.
  -v --version                  Show version information.
  -l --log-level=LEVEL          If specified, then the log level will be set to
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
import pkg_resources
from pptx import Presentation
from schema import And, Schema, SchemaError, Use

from ._version import __version__
from .pages import Pages

# Configuration
REPORT_SHELL = pkg_resources.resource_filename("pe_reports", "data/shell/pe_shell.pptx")
REPORT_OUT = "Customer_ID_Posture_Exposure.pptx"


def load_template():
    """Load PowerPoint template into memory."""
    prs = Presentation(REPORT_SHELL)
    return prs


def export_set(prs, out_dir):
    """Export PowerPoint report set to output directory."""
    try:
        prs.save(os.path.join(out_dir, REPORT_OUT))
    except FileNotFoundError as not_found:
        logging.error("%s : Missing input data. No report generated.", not_found)


def generate_reports(data, data_dir, out_dir, db_creds_file):
    """Gather assets to produce reports."""


def main() -> None:
    """Set up logging and call the generate_reports function."""
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

    # Set up logging
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
    )

    # TODO: Add generate_reports func to handle cmd line arguments and function.
    # Issue 8: https://github.com/cisagov/pe-reports/issues/8
    generate_reports(
        # TODO: Improve use of schema to validate arguments.
        # Issue 19: https://github.com/cisagov/pe-reports/issues/19
        validated_args["REPORT_DATE"],
        validated_args["DATA_DIRECTORY"],
        validated_args["OUTPUT_DIRECTORY"],
        validated_args["--db-creds-file"],
    )

    logging.info(
        "Loading Posture & Exposure Report Template, Version : %s", __version__
    )
    prs = load_template()

    logging.info("Generating Graphs")
    Pages.cover(prs)
    Pages.overview(prs)

    export_set(prs, validated_args["OUTPUT_DIRECTORY"])

    # Stop logging and clean up
    logging.shutdown()
