"""ciagov/pe-reports: A tool for creating Posture & Exposure reports.

Usage:
  pe-reports REPORT_DATE  DATA_DIRECTORY OUTPUT_DIRECTORY [--db-creds-file=FILENAME]

Options:
  -h --help                         Show this message.
  REPORT_DATE                       Date of the report, format YYYY-MM-DD
  DATA_DIRECTORY                    The directory where the excel data
                                    files are located. Organized by
                                    owner.
  OUTPUT_DIRECTORY                  The directory where the final PDF
                                    reports should be saved.
  -c --db-creds-file=FILENAME       A YAML file containing the Cyber
                                    Hygiene database credentials.
                                    [default: /secrets/database_creds.yml]
"""

# Standard Python Libraries
import logging
import os
import sys
from typing import Any, Dict

# Third-Party Libraries
from docopt import docopt
import fitz
import pandas as pd
from schema import And, Schema, SchemaError, Use
from xhtml2pdf import pisa

# cisagov Libraries
from pe_reports._version import __version__
from pe_reports.data.db_query import connect, get_orgs
from pe_reports.pages import init


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
    """Embeds raw data into pdf and encrypts file."""
    doc = fitz.open(file)
    page = doc[3]
    output = (
        f"{output_directory}/{org_code}/Posture_and_Exposure_Report-{datestring}.pdf"
    )

    # Open csv data as binary
    cc = open(cred_xlsx, "rb").read()
    da = open(da_xlsx, "rb").read()
    ma = open(vuln_xlsx, "rb").read()
    mi = open(mi_xlsx, "rb").read()

    # Insert link to csv data in summary page of pdf
    p1 = fitz.Point(110, 695)
    p2 = fitz.Point(240, 695)
    p3 = fitz.Point(375, 695)
    p5 = fitz.Point(500, 695)

    # Embedd and add push-pin graphic
    page.add_file_annot(
        p1, cc, "compromised_credentials.xlsx", desc="Open up csv", icon="PushPin"
    )
    page.add_file_annot(
        p2, da, "domain_alerts.xlsx", desc="Open up csv", icon="PushPin"
    )
    page.add_file_annot(p3, ma, "vuln_alerts.xlsx", desc="Open up xlsx", icon="PushPin")
    page.add_file_annot(
        p5, mi, "mention_incidents.xlsx", desc="Open up csv", icon="PushPin"
    )

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
    """Convert html to pdf."""
    # open output file for writing (truncated binary)
    result_file = open(output_filename, "w+b")

    # convert HTML to PDF
    pisa_status = pisa.CreatePDF(
        source_html, dest=result_file  # the HTML to convert
    )  # file handle to recieve result

    # close output file
    result_file.close()  # close output file

    # return False on success and True on errors
    return pisa_status.err


def generate_reports(datestring, data_directory, output_directory):
    """Process steps for generating report data."""
    # Get PE orgs from PE db
    conn = connect()
    pe_orgs = get_orgs(conn)
    logging.info(pe_orgs)
    generated_reports = 0

    # Iterate over organizations
    for org in pe_orgs:

        # Assign organization values
        org_uid = org[0]
        org_name = org[1]
        org_code = org[2]

        logging.info(f"Running on {org_code}...")

        # Create folders in output directory
        if not os.path.exists(f"{output_directory}/ppt"):
            os.mkdir(f"{output_directory}/ppt")

        if not os.path.exists(f"{output_directory}/{org_code}"):
            os.mkdir(f"{output_directory}/{org_code}")

        # Load source html
        file = open("template2.html")
        source_html = file.read().replace("\n", " ")

        # Insert Charts and Metrics into pdf
        (
            source_html,
            hibp_creds,
            cyber_creds,
            masq_df,
            insecure_df,
            vulns_df,
            assets_df,
            dark_web_mentions,
            alerts,
            top_cves,
        ) = init(
            source_html,
            datestring,
            org_name,
            org_uid,
        )

        # Close pdf
        file.close()

        # Convert to HTML to PDF
        output_filename = f"{output_directory}/{org_code}-Posture_and_Exposure_Report-{datestring}.pdf"
        convert_html_to_pdf(source_html, output_filename)

        # Create Crendential Exposure excel file
        cred_xlsx = f"{output_directory}/{org_code}/compromised_credentials.xlsx"
        credWriter = pd.ExcelWriter(cred_xlsx, engine="xlsxwriter")
        hibp_creds.to_excel(credWriter, sheet_name="HIBP_Credentials", index=False)
        cyber_creds.to_excel(credWriter, sheet_name="Cyber6_Credentials", index=False)
        credWriter.save()

        # Create Domain Masquerading excel file
        da_xlsx = f"{output_directory}/{org_code}/domain_alerts.xlsx"
        domWriter = pd.ExcelWriter(da_xlsx, engine="xlsxwriter")
        masq_df.to_excel(domWriter, sheet_name="Suspected Domains", index=False)
        domWriter.save()

        # Create Suspected vulnerability excel file
        vuln_xlsx = f"{output_directory}/{org_code}/vuln_alerts.xlsx"
        vulnWriter = pd.ExcelWriter(vuln_xlsx, engine="xlsxwriter")
        assets_df.to_excel(vulnWriter, sheet_name="Assets", index=False)
        insecure_df.to_excel(vulnWriter, sheet_name="Insecure", index=False)
        vulns_df.to_excel(vulnWriter, sheet_name="Verified Vulns", index=False)
        vulnWriter.save()

        # Create dark web excel file
        mi_xlsx = f"{output_directory}/{org_code}/mention_incidents.xlsx"
        miWriter = pd.ExcelWriter(mi_xlsx, engine="xlsxwriter")
        dark_web_mentions.to_excel(
            miWriter, sheet_name="Dark Web Mentions", index=False
        )
        alerts.to_excel(miWriter, sheet_name="Dark Web Alerts", index=False)
        top_cves.to_excel(miWriter, sheet_name="Top CVEs", index=False)
        miWriter.save()

        # grab the pdf
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
        # Need to make sure Cyhy Mailer doesn't send files that are too large
        if tooLarge:
            logging.info(f"{org_code} is too large. File size: {filesize} Limit: 20MB")

        generated_reports = generated_reports + 1

    logging.info(f"{generated_reports} reports generated")


def main():
    """Generate PDF reports."""
    args = docopt(__doc__, version=__version__)

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
        return 1

    # Assign validated arguments to variables
    log_level: str = validated_args["--log-level"]

    # Set up logging
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
    )

    # TODO: Add generate_reports func to handle cmd line arguments and function.
    # Issue #8: https://github.com/cisagov/pe-reports/issues/8
    # def generate_reports(db, datestring, data_directory, output_directory):

    logging.info(
        "Loading Posture & Exposure Report Template, Version : %s", __version__
    )
    logging.info("Generating Graphs")

    # Create output directory
    if not os.path.exists(args["OUTPUT_DIRECTORY"]):
        os.mkdir(args["OUTPUT_DIRECTORY"])

    # Generate reports
    generate_reports(
        args["REPORT_DATE"], args["DATA_DIRECTORY"], args["OUTPUT_DIRECTORY"]
    )

    # Stop logging and clean up
    logging.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
