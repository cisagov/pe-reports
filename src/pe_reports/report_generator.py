"""cisagov/pe-reports: A tool for creating Posture & Exposure reports.

Usage:
  pe-reports REPORT_DATE OUTPUT_DIRECTORY [--log-level=LEVEL]

Options:
  -h --help                         Show this message.
  REPORT_DATE                       Date of the report, format YYYY-MM-DD
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
import fitz
import pandas as pd
from schema import And, Schema, SchemaError, Use
from xhtml2pdf import pisa

# cisagov Libraries
from pe_reports import CENTRAL_LOGGING_FILE

from ._version import __version__
from .data.db_query import connect, get_orgs
from .pages import init

LOGGER = logging.getLogger(__name__)


def embed(
    output_directory,
    org_code,
    datestring,
    file,
    cred_xlsx,
    da_xlsx,
    vuln_xlsx,
    mi_xlsx,
):
    """Embeds raw data into PDF and encrypts file."""
    doc = fitz.open(file)
    # Get the summary page of the PDF on page 4
    page = doc[3]
    output = (
        f"{output_directory}/{org_code}/Posture_and_Exposure_Report-{datestring}.pdf"
    )

    # Open CSV data as binary
    cc = open(cred_xlsx, "rb").read()
    da = open(da_xlsx, "rb").read()
    ma = open(vuln_xlsx, "rb").read()
    mi = open(mi_xlsx, "rb").read()

    # Insert link to CSV data in summary page of PDF.
    # Use coordinates to position them on the bottom.
    p1 = fitz.Point(110, 695)
    p2 = fitz.Point(240, 695)
    p3 = fitz.Point(375, 695)
    p5 = fitz.Point(500, 695)

    # Embed and add push-pin graphic
    page.add_file_annot(
        p1, cc, "compromised_credentials.xlsx", desc="Open up CSV", icon="PushPin"
    )
    page.add_file_annot(
        p2, da, "domain_alerts.xlsx", desc="Open up CSV", icon="PushPin"
    )
    page.add_file_annot(p3, ma, "vuln_alerts.xlsx", desc="Open up xlsx", icon="PushPin")
    page.add_file_annot(
        p5, mi, "mention_incidents.xlsx", desc="Open up CSV", icon="PushPin"
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

    return filesize, tooLarge


def convert_html_to_pdf(source_html, output_filename):
    """Convert HTML to PDF."""
    # Open output file for writing (truncated binary)
    result_file = open(output_filename, "w+b")

    # Convert HTML to PDF
    pisa_status = pisa.CreatePDF(
        source_html, dest=result_file  # the HTML to convert
    )  # file handle to receive result

    # Close output file
    result_file.close()  # close output file

    # Return False on success and True on errors
    return pisa_status.err


def generate_reports(datestring, output_directory):
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

            LOGGER.info("Running on %s", org_code)

            # Create folders in output directory
            for dir_name in ("ppt", org_code):
                if not os.path.exists(f"{output_directory}/{dir_name}"):
                    os.mkdir(f"{output_directory}/{dir_name}")

            # Insert Charts and Metrics into PDF
            (
                source_html,
                creds_sum,
                masq_df,
                insecure_df,
                vulns_df,
                assets_df,
                dark_web_mentions,
                alerts,
                top_cves,
            ) = init(
                datestring,
                org_name,
                org_uid,
            )

            # Convert to HTML to PDF
            output_filename = f"{output_directory}/{org_code}-Posture_and_Exposure_Report-{datestring}.pdf"
            convert_html_to_pdf(source_html, output_filename)

            # Create Credential Exposure Excel file
            cred_xlsx = f"{output_directory}/{org_code}/compromised_credentials.xlsx"
            credWriter = pd.ExcelWriter(cred_xlsx, engine="xlsxwriter")
            creds_sum.to_excel(
                credWriter, sheet_name="Exposed_Credentials", index=False
            )
            credWriter.save()

            # Create Domain Masquerading Excel file
            da_xlsx = f"{output_directory}/{org_code}/domain_alerts.xlsx"
            domWriter = pd.ExcelWriter(da_xlsx, engine="xlsxwriter")
            masq_df.to_excel(domWriter, sheet_name="Suspected Domains", index=False)
            domWriter.save()

            # Create Suspected vulnerability Excel file
            vuln_xlsx = f"{output_directory}/{org_code}/vuln_alerts.xlsx"
            vulnWriter = pd.ExcelWriter(vuln_xlsx, engine="xlsxwriter")
            assets_df.to_excel(vulnWriter, sheet_name="Assets", index=False)
            insecure_df.to_excel(vulnWriter, sheet_name="Insecure", index=False)
            vulns_df.to_excel(vulnWriter, sheet_name="Verified Vulns", index=False)
            vulnWriter.save()

            # Create dark web Excel file
            mi_xlsx = f"{output_directory}/{org_code}/mention_incidents.xlsx"
            miWriter = pd.ExcelWriter(mi_xlsx, engine="xlsxwriter")
            dark_web_mentions.to_excel(
                miWriter, sheet_name="Dark Web Mentions", index=False
            )
            alerts.to_excel(miWriter, sheet_name="Dark Web Alerts", index=False)
            top_cves.to_excel(miWriter, sheet_name="Top CVEs", index=False)
            miWriter.save()

            # Grab the PDF
            pdf = f"{output_directory}/{org_code}-Posture_and_Exposure_Report-{datestring}.pdf"

            (filesize, tooLarge) = embed(
                output_directory,
                org_code,
                datestring,
                pdf,
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
        filename=CENTRAL_LOGGING_FILE,
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
    )

    # Stop logging and clean up
    logging.shutdown()
