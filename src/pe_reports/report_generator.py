"""cisagov/pe-reports: A tool for creating Posture & Exposure reports.

Usage:
  pe-reports REPORT_DATE OUTPUT_DIRECTORY [--log-level=LEVEL] [--soc_med_included]

Options:
  -h --help                         Show this message.
  REPORT_DATE                       Date of the report, format YYYY-MM-DD
  OUTPUT_DIRECTORY                  The directory where the final PDF
                                    reports should be saved.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
  -s --soc_med_included             Include social media posts from Cybersixgill in the report.
"""

# Standard Python Libraries
import logging
import os
import sys
from typing import Any, Dict

# Third-Party Libraries
import docopt
import fitz
from schema import And, Schema, SchemaError, Use

# cisagov Libraries
import pe_reports

from ._version import __version__
from .data.db_query import connect, get_orgs
from .pages import init
from .reportlab_core_generator import core_report_gen
from .reportlab_generator import report_gen

LOGGER = logging.getLogger(__name__)


def embed(
    output_directory,
    org_code,
    datestring,
    file,
    cred_json,
    da_json,
    vuln_json,
    mi_json,
    cred_xlsx,
    da_xlsx,
    vuln_xlsx,
    mi_xlsx,
):
    """Embed raw data into PDF and encrypt file."""
    doc = fitz.open(file)
    # Get the summary page of the PDF on page 4
    page = doc[4]
    output = f"{output_directory}/{org_code}/Posture_and_Exposure_Report-{org_code}-{datestring}.pdf"

    # Open json data as binary
    cc = open(cred_json, "rb").read()
    da = open(da_json, "rb").read()
    ma = open(vuln_json, "rb").read()
    if mi_json:
        mi = open(mi_json, "rb").read()

    # Open CSV data as binary
    cc_xl = open(cred_xlsx, "rb").read()
    da_xl = open(da_xlsx, "rb").read()
    ma_xl = open(vuln_xlsx, "rb").read()
    if mi_xlsx:
        mi_xl = open(mi_xlsx, "rb").read()

    # Insert link to CSV data in summary page of PDF.
    # Use coordinates to position them on the bottom.
    p1 = fitz.Point(300, 607)
    p2 = fitz.Point(300, 635)
    p3 = fitz.Point(300, 663)
    p4 = fitz.Point(300, 691)
    p5 = fitz.Point(340, 607)
    p6 = fitz.Point(340, 635)
    p7 = fitz.Point(340, 663)
    p8 = fitz.Point(340, 691)

    # Embed and add button icon
    page.add_file_annot(
        p1, cc, "compromised_credentials.json", desc="Open JSON", icon="Paperclip"
    )
    page.add_file_annot(
        p2, da, "domain_alerts.json", desc="Open JSON", icon="Paperclip"
    )
    page.add_file_annot(p3, ma, "vuln_alerts.json", desc="Open JSON", icon="Paperclip")
    if mi_json:
        page.add_file_annot(
            p4, mi, "mention_incidents.json", desc="Open JSON", icon="Paperclip"
        )
    page.add_file_annot(
        p5, cc_xl, "compromised_credentials.xlsx", desc="Open Excel", icon="Graph"
    )
    page.add_file_annot(
        p6, da_xl, "domain_alerts.xlsx", desc="Open Excel", icon="Graph"
    )
    page.add_file_annot(p7, ma_xl, "vuln_alerts.xlsx", desc="Open Excel", icon="Graph")
    if mi_xlsx:
        page.add_file_annot(
            p8, mi_xl, "mention_incidents.xlsx", desc="Open Excel", icon="Graph"
        )

    # Save doc and set garbage=4 to reduce PDF size using all 4 methods:
    # Remove unused objects, compact xref table, merge duplicate objects,
    # and check stream objects for duplication
    doc.save(
        output,
        garbage=4,
        deflate=True,
    )
    tooLarge = False
    # Throw error if file size is greater than 20MB
    filesize = os.path.getsize(output)
    if filesize >= 20000000:
        tooLarge = True

    return filesize, tooLarge, output


def generate_reports(datestring, output_directory, soc_med_included=False):
    """Process steps for generating report data."""
    # Get PE orgs from PE db
    conn = connect()
    if conn:
        pe_orgs = get_orgs(conn)
    else:
        return 1
    generated_reports = 0

    # Iterate over organizations
    if pe_orgs:
        LOGGER.info("PE orgs count: %d", len(pe_orgs))
        for org in pe_orgs:
            # Assign organization values
            org_uid = org[0]
            org_name = org[1]
            org_code = org[2]
            premium = org[8]

            LOGGER.info("Running on %s", org_code)

            # Create folders in output directory
            for dir_name in ("ppt", org_code):
                if not os.path.exists(f"{output_directory}/{dir_name}"):
                    os.mkdir(f"{output_directory}/{dir_name}")

            # Insert Charts and Metrics into PDF
            (
                report_dict,
                cred_json,
                da_json,
                vuln_json,
                mi_json,
                cred_xlsx,
                da_xlsx,
                vuln_xlsx,
                mi_xlsx,
            ) = init(
                datestring,
                org_name,
                org_code,
                org_uid,
                premium,
                output_directory,
                soc_med_included,
            )

            # Convert to HTML to PDF
            output_filename = f"{output_directory}/Posture_and_Exposure_Report-{org_code}-{datestring}.pdf"

            report_dict["filename"] = output_filename
            if premium:
                report_gen(report_dict, soc_med_included)
            else:
                core_report_gen(report_dict)

            # Grab the PDF
            pdf = f"{output_directory}/Posture_and_Exposure_Report-{org_code}-{datestring}.pdf"

            # Embed excel and Json files
            (filesize, tooLarge, output) = embed(
                output_directory,
                org_code,
                datestring,
                pdf,
                cred_json,
                da_json,
                vuln_json,
                mi_json,
                cred_xlsx,
                da_xlsx,
                vuln_xlsx,
                mi_xlsx,
            )

            # Log a message if the report is too large.  Our current mailer
            # cannot send files larger than 20MB.
            if tooLarge:
                LOGGER.info(
                    "%s is too large. File size: %s Limit: 20MB", org_code, filesize
                )

            generated_reports += 1
    else:
        LOGGER.error(
            "Connection to pe database failed and/or there are 0 organizations stored."
        )

    LOGGER.info("%s reports generated", generated_reports)
    return generated_reports


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
        filename=pe_reports.CENTRAL_LOGGING_FILE,
        filemode="a",
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S",
        level=log_level.upper(),
    )

    LOGGER.info("Loading Posture & Exposure Report, Version : %s", __version__)

    # Create output directory
    if not os.path.exists(validated_args["OUTPUT_DIRECTORY"]):
        os.mkdir(validated_args["OUTPUT_DIRECTORY"])

    # Generate reports
    generate_reports(
        validated_args["REPORT_DATE"],
        validated_args["OUTPUT_DIRECTORY"],
        validated_args["--soc_med_included"],
    )

    # Stop logging and clean up
    logging.shutdown()
