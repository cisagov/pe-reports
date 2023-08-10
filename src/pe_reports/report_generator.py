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
  -sc --soc_med_included            Include social media posts from Cybersixgill in the report.
"""

# Standard Python Libraries
import logging
import os
import sys
from typing import Any, Dict

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError
import docopt
import fitz
import pandas as pd
from schema import And, Schema, SchemaError, Use

# cisagov Libraries
import pe_reports

from ._version import __version__
from .asm_generator import create_summary
from .data.db_query import connect, get_orgs, refresh_asset_counts_vw, set_from_cidr

# from .helpers.generate_score import get_pe_scores
from .pages import init
from .reportlab_core_generator import core_report_gen
from .reportlab_generator import report_gen

# from .scorecard_generator import create_scorecard

LOGGER = logging.getLogger(__name__)
ACCESSOR_AWS_PROFILE = os.getenv("ACCESSOR_PROFILE")


def upload_file_to_s3(file_name, datestring, bucket, excel_org):
    """Upload a file to an S3 bucket."""
    session = boto3.Session(profile_name=ACCESSOR_AWS_PROFILE)
    s3_client = session.client("s3")

    # If S3 object_name was not specified, use file_name
    object_name = f"{datestring}/{os.path.basename(file_name)}"

    if excel_org is not None:
        object_name = f"{datestring}/{excel_org}-raw-data/{os.path.basename(file_name)}"

    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
        if response is None:
            LOGGER.info("Success uploading to S3.")
        else:
            LOGGER.info(response)
    except ClientError as e:
        LOGGER.error(e)


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
    """Embeds raw data into PDF and encrypts file."""
    doc = fitz.open(file)
    # Get the summary page of the PDF on page 4
    page = doc[4]
    output = f"{output_directory}/{org_code}/Posture_and_Exposure_Report-{org_code}-{datestring}.pdf"

    # Open CSV data as binary
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

    # Embed and add push-pin graphic
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

    # Resfresh ASM counts view
    LOGGER.info("Refreshing ASM count view and IPs from cidrs")
    refresh_asset_counts_vw()
    # set_from_cidr()
    LOGGER.info("Finished refreshing ASM count view and IPs from Cidrs")

    # Iterate over organizations

    if pe_orgs:
        LOGGER.info("PE orgs count: %d", len(pe_orgs))
        # Generate PE scores for all stakeholders.
        LOGGER.info("Calculating P&E Scores")
        # pe_scores_df = get_pe_scores(datestring, 12)
        # go = 0
        # pe_orgs.reverse()
        for org in pe_orgs:
            # Assign organization values
            org_uid = org[0]
            org_name = org[1]
            org_code = org[2]
            premium = org[8]

            # if org_code not in ["FRB"]:
            #     continue

            # DOL, USDA

            # if org_code == "HHS_FDA":
            #     go = 1
            #     continue
            # if go != 1:
            #     continue
            # Rapidgator%20 DOI_BIA

            LOGGER.info("Running on %s", org_code)

            # Create folders in output directory
            for dir_name in ("ppt", org_code):
                if not os.path.exists(f"{output_directory}/{dir_name}"):
                    os.mkdir(f"{output_directory}/{dir_name}")

            pe_scores_df = pd.DataFrame()
            if not pe_scores_df.empty:
                score = pe_scores_df.loc[
                    pe_scores_df["cyhy_db_name"] == org_code, "PE_score"
                ].item()
                grade = pe_scores_df.loc[
                    pe_scores_df["cyhy_db_name"] == org_code, "letter_grade"
                ].item()
            else:
                score = "NA"
                grade = "NA"

            # Insert Charts and Metrics into PDF
            (
                chevron_dict,
                scorecard_dict,
                summary_dict,
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
                score,
                grade,
                output_directory,
                soc_med_included,
            )

            # Create ASM Summary
            LOGGER.info("Creating ASM Summary")
            summary_filename = f"{output_directory}/Posture-and-Exposure-ASM-Summary_{org_code}_{scorecard_dict['end_date'].strftime('%Y-%m-%d')}.pdf"
            final_summary_output = f"{output_directory}/{org_code}/Posture-and-Exposure-ASM-Summary_{org_code}_{scorecard_dict['end_date'].strftime('%Y-%m-%d')}.pdf"
            summary_json_filename = f"{output_directory}/{org_code}/ASM_Summary.json"
            summary_excel_filename = f"{output_directory}/{org_code}/ASM_Summary.xlsx"
            asm_xlsx = create_summary(
                org_uid,
                final_summary_output,
                summary_dict,
                summary_filename,
                summary_json_filename,
                summary_excel_filename,
            )
            LOGGER.info("Done")

            # Create scorecard
            LOGGER.info("Creating scorecard")
            # scorecard_filename = f"{output_directory}/{org_code}/Posture-and-Exposure-Scorecard_{org_code}_{scorecard_dict['end_date'].strftime('%Y-%m-%d')}.pdf"
            # create_scorecard(scorecard_dict, scorecard_filename)
            LOGGER.info("Done")

            # Convert to HTML to PDF
            output_filename = f"{output_directory}/Posture_and_Exposure_Report-{org_code}-{datestring}.pdf"
            # convert_html_to_pdf(source_html, output_filename)#TODO possibly generate report here
            chevron_dict["filename"] = output_filename
            if premium:
                report_gen(chevron_dict, soc_med_included)
            else:
                core_report_gen(chevron_dict)

            # Grab the PDF
            pdf = f"{output_directory}/Posture_and_Exposure_Report-{org_code}-{datestring}.pdf"

            # Embed Excel files
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

            bucket_name = "cisa-crossfeed-staging-reports"

            # Upload excel files
            upload_file_to_s3(cred_xlsx, datestring, bucket_name, org_code)
            upload_file_to_s3(da_xlsx, datestring, bucket_name, org_code)
            upload_file_to_s3(vuln_xlsx, datestring, bucket_name, org_code)
            if premium:
                upload_file_to_s3(mi_xlsx, datestring, bucket_name, org_code)
            upload_file_to_s3(asm_xlsx, datestring, bucket_name, org_code)

            # Upload report
            upload_file_to_s3(output, datestring, bucket_name, None)

            # Upload scorecard
            upload_file_to_s3(final_summary_output, datestring, bucket_name, None)

            # Upload ASM Summary
            # upload_file_to_s3(scorecard_filename, datestring, bucket_name, None)
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

    try:
        soc_med = validated_args["--soc_med_included"]
    except Exception as e:
        LOGGER.info(f"Social media should not included: {e}")
        soc_med = False
    # Generate reports
    generated_reports = generate_reports(
        validated_args["REPORT_DATE"],
        validated_args["OUTPUT_DIRECTORY"],
        soc_med,
    )

    LOGGER.info("%s reports generated", generated_reports)

    # Stop logging and clean up
    logging.shutdown()
