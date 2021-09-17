"""A tool for creating Posture & Exposure reports.

Usage:
    pe-reports REPORT_DATE DATA_DIRECTORY OUTPUT_DIRECTORY [--db-creds-file=FILENAME] [--log-level=LEVEL]

Arguments:
  REPORT_DATE                   Date of the report, format YYYY-MM-DD.
  DATA_DIRECTORY                The directory where the excel data files are located.
                                Organized by owner.
  OUTPUT_DIRECTORY              The directory where the final PDF reports should be saved.
  -c --db-creds-file=FILENAME   A YAML file containing the Cyber
                                Hygiene database credentials.
                                [default: /secrets/database_creds.yml]

Options:
  -h --help                     Show this message.
  -v --version                  Show version information.
  --log-level=LEVEL             If specified, then the log level will be set to
                                the specified value.  Valid values are "debug", "info",
                                "warning", "error", and "critical". [default: info]
"""

# Standard Python Libraries
import glob
import json
import logging
import os
import re

# Bandit triggers B404 here, but we're using subprocess.run() safely.
# The action to import subprocess is safe as there is no function call here
# that would provide a way to inject an operation that would produce
# hazardous results.  For more details on B404 see here:
# https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess
import subprocess  # nosec
import sys
from typing import Any, Dict

# Third-Party Libraries
import docopt
import fitz
from mongo_db_from_config import db_from_config
import pandas as pd
import pkg_resources
from pptx import Presentation
import pymongo
from schema import And, Schema, SchemaError, Use
import yaml

from ._version import __version__
from .pages import init
from .report_metrics import generate_metrics

# Configuration
REPORT_SHELL = pkg_resources.resource_filename("pe_reports", "data/shell/pe_shell.pptx")
CUSTOMERS = pkg_resources.resource_filename("pe_reports", "data/org_names.json")


def load_template():
    """Load PowerPoint template into memory."""
    prs = Presentation(REPORT_SHELL)
    return prs


def load_customers():
    """Export PowerPoint report set to output directory."""
    try:

        if os.path.getsize(CUSTOMERS) != 0 and os.path.exists(CUSTOMERS):
            with open(CUSTOMERS) as customers_file:
                return json.load(customers_file)
    except FileNotFoundError as not_found:
        logging.error("%s : Missing input data. No report generated.", not_found)
        return dict()


def export_set(output_directory, _id, datestring, prs):
    """Export PowerPoint report set to output directory."""
    try:
        pptx_out = f"{output_directory}/ppt/{_id}-Posture_and_Exposure_Report-{datestring}.pptx"
        prs.save(pptx_out)
    except FileNotFoundError as not_found:
        logging.error("%s : Missing input data. No report generated.", not_found)
    return pptx_out


def convert_to(folder, source, timeout=None):
    """Convert pptx to pdf."""
    args = [
        libreoffice_exec(),
        "--headless",
        "--convert-to",
        "pdf",
        "--outdir",
        folder,
        source,
    ]

    # Bandit triggers B603 here, but we're using subprocess.run()
    # safely here, since the args input variable to subprocess.run is sanitized
    # and secure. Since that value is hard-coded, the risks mentioned by B603
    # are minimal For more details on B603 see here:
    # https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html

    process = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        shell=False,  # nosec
    )

    filename = re.search("-> (.*?) using filter", process.stdout.decode())
    return filename.group(1)


def libreoffice_exec():
    """Call to MacOS LibeOffice App."""
    if sys.platform == "darwin":
        return "/Applications/LibreOffice.app/Contents/MacOS/soffice"


def embed_and_encrypt(
    output_directory,
    _id,
    datestring,
    file,
    cc_csv,
    da_csv,
    ma_csv,
    iv_csv,
    mi_csv,
    password,
):
    """Embed raw data into pdf and encrypts file."""
    doc = fitz.open(file)
    page = doc[-1]
    output = f"{output_directory}/{_id}/Posture_and_Exposure_Report-{datestring}.pdf"

    # Open csv data as binary
    cc = open(cc_csv, "rb").read()
    da = open(da_csv, "rb").read()
    ma = open(ma_csv, "rb").read()
    iv = open(iv_csv, "rb").read()
    mi = open(mi_csv, "rb").read()

    # Insert link to csv data in last page of pdf
    p1 = fitz.Point(740, 280)
    p2 = fitz.Point(740, 305)
    p3 = fitz.Point(740, 330)
    p4 = fitz.Point(740, 355)
    p5 = fitz.Point(740, 380)

    # Embedd and add push-pin graphic
    page.add_file_annot(
        p1, cc, "compromised_credentials.csv", desc="Open up csv", icon="PushPin"
    )
    page.add_file_annot(p2, da, "domain_alerts.csv", desc="Open up csv", icon="PushPin")
    page.add_file_annot(
        p3, ma, "malware_associations.csv", desc="Open up csv", icon="PushPin"
    )
    page.add_file_annot(
        p4,
        iv,
        "inferred_vulnerability_associations.csv",
        desc="Open up csv",
        icon="PushPin",
    )
    page.add_file_annot(
        p5, mi, "mention_incidents.csv", desc="Open up csv", icon="PushPin"
    )
    # Add encryption
    perm = int(
        fitz.PDF_PERM_ACCESSIBILITY
        | fitz.PDF_PERM_PRINT  # permit printing
        | fitz.PDF_PERM_COPY  # permit copying
        | fitz.PDF_PERM_ANNOTATE  # permit annotations
    )
    encrypt_meth = fitz.PDF_ENCRYPT_AES_256
    doc.save(
        output,
        encryption=encrypt_meth,  # set the encryption method
        user_pw=password,  # set the user password
        permissions=perm,  # set permissions
        garbage=4,
        deflate=True,
    )
    tooLarge = False
    # Throw error if file size is greater than 20MB
    filesize = os.path.getsize(output)
    if filesize >= 20000000:
        tooLarge = True

    return filesize, tooLarge


def get_key_from_request(request):
    """Return the agency"s key for encryption.

    Given the request document, return the key to use for encrypting
    documents to send to  the agency.

    Parameters
    ----------
    request : dict
        The request documents for which the corresponding email
        address is desired.

    Returns
    -------
    str: A string value to use as the password to encrypt the PDF
    report before sending over email to the agency.

    """
    id = request["_id"]
    # Get the key value
    try:
        key = request["key"]
    except TypeError:
        logging.critical(f"No key found for ID {id}")

    return key


def get_requests_raw(db, query, batch_size=None):
    """Return a cursor for iterating over agencies" request documents.

    Parameters
    ----------
    db : MongoDatabase
        The Mongo database from which agency data can be retrieved.

    query : dict
        The query to perform.

    batch_size : int
        The batch size to use when retrieving results from the Mongo
        database.  If None then the default will be used.

    Returns
    -------
    pymongo.cursor.Cursor: A cursor that can be used to iterate over
    the request documents.

    Throws
    ------
    pymongo.errors.TypeError: If unable to connect to the requested
    server, or if batch_size is not an int or None.

    pymongo.errors.InvalidOperation: If the cursor has already been
    used.  The batch size cannot be set on a cursor that has already
    been used.

    """
    projection = {"_id": True, "key": True}

    try:
        requests = db.requests.find(query, projection)
        if batch_size is not None:
            requests.batch_size(batch_size)
    except TypeError:
        logging.critical(
            "There was an error with the MongoDB query that retrieves the request documents",
            exc_info=True,
        )
        raise

    return requests


def get_requests(db, agency_list, batch_size=None):
    """Return a cursor for iterating over agencies" request documents.

    Parameters
    ----------
    db : MongoDatabase
        The Mongo database from which agency data can be retrieved.

    agency_list : list(str)
        A list of agency IDs (e.g. DOE, DOJ, DHS). If None then no such
        restriction is placed on the query.

    batch_size : int
        The batch size to use when retrieving results from the Mongo
        database.  If None then the default will be used.

    Returns
    -------
    pymongo.cursor.Cursor: A cursor that can be used to iterate over
    the request documents.

    Throws
    ------
    pymongo.errors.TypeError: If unable to connect to the requested
    server, or if batch_size is not an int or None.

    ValueError: If batch_size is negative, or if there is no FEDERAL
    category in the database but federal_only is True.

    pymongo.errors.InvalidOperation: If the cursor has already been
    used.  The batch size cannot be set on a cursor that has already
    been used.

    """
    query = {"retired": {"$ne": True}, "_id": {"$in": agency_list}}

    return get_requests_raw(db, query, batch_size)


def read_excel(file):
    """Read in data from each sheet of xlsx file."""
    cred_df = pd.read_excel(
        file, sheet_name="Compromised Credentials", engine="openpyxl"
    )
    dom_df = pd.read_excel(file, sheet_name="Domain Alerts", engine="openpyxl")
    mal_df = pd.read_excel(file, sheet_name="Malware Associations", engine="openpyxl")
    inferred_df = pd.read_excel(
        file, sheet_name="Inferred Vuln Associations", engine="openpyxl"
    )
    men_df = pd.read_excel(file, sheet_name="Mention incidents", engine="openpyxl")

    return cred_df, dom_df, mal_df, inferred_df, men_df


def generate_reports(db, datestring, data_directory, output_directory):
    """Process steps for generating report data."""
    agencies = []
    contents = os.walk(data_directory)
    names_obj = load_customers()

    for root, folders, files in contents:
        for folder_name in folders:
            agencies.append(names_obj[folder_name][0])

    try:
        requests = get_requests(db, agency_list=agencies)
        request_data = list(requests)

    except TypeError:
        return 4
    try:
        cyhy_agencies = len(request_data)
        logging.debug(f"{cyhy_agencies} agencies found in CyHy")

    except pymongo.errors.OperationFailure:
        logging.critical(
            "Mongo database error while counting the number of request documents returned",
            exc_info=True,
        )

    generated_reports = 0
    print("\n [INFO] Reports for:\n  ", request_data)

    # Iterate over cyhy_requests, to check input agencies are
    # valid cyhy customers and return passwords
    for request in request_data:
        _id = request["_id"]
        # Get the full name of org from json file
        for lg_name in names_obj:
            if names_obj[lg_name][0] == _id:
                org_name = names_obj[lg_name][1]
                folder_name = lg_name
        password = get_key_from_request(request)

        # Find raw data file
        data_glob = f"{data_directory}/{folder_name}/raw_data.xlsx"
        filenames = sorted(glob.glob(data_glob))

        # At most one xlsx should match
        if len(filenames) > 1:
            logging.warn("More than one xlsx file found")
        elif not filenames:
            logging.error("No xlsx file found")

        if filenames:
            # We take the last filename since, if there happens to be more than
            # one, it should the latest.  (This is because we sorted the glob
            # results.)
            file = filenames[-1]

            # Create folders in output directory if folders dont exists. If the folders exists remove them and create new directory.
            try:
                if not os.path.exists(f"{output_directory}/ppt") or not os.path.exists(
                    f"{output_directory}/_id"
                ):
                    os.mkdir(f"{output_directory}/ppt")
                    os.mkdir(f"{output_directory}/_id")
                else:
                    os.remove(f"{output_directory}/ppt")
                    os.remove(f"{output_directory}/_id")
                    os.mkdir(f"{output_directory}/ppt")
                    os.mkdir(f"{output_directory}/_id")
            except FileExistsError as err:
                logging.error(
                    f"The output directory exists or there was a problem during directory creation. {err}",
                    exc_info=True,
                )
                return 1

            # Extract data from each sheet
            cred_df, dom_df, mal_df, inferred_df, men_df = read_excel(file)

            # Generate metrics
            (
                inc,
                creds,
                inc_src_df,
                inc_date_df,
                ce_inc_df,
                creds_attach,
                domains,
                utld,
                tld_df,
                dm_df,
                dm_samp,
                domains_attach,
                malware,
                uma,
                ma_act_df,
                ma_samp,
                ma_attach,
                vulns,
                iv_df,
                iv_act_df,
                iv_samp,
                iv_attach,
                vuln_ma_df,
                vuln_ma_df2,
                assets,
                web,
                dark,
                web_df,
                web_source_df,
                web_attach,
                dark_web_df,
                web_only_df,
            ) = generate_metrics(
                datestring, cred_df, dom_df, mal_df, inferred_df, men_df
            )

            # Load Templates
            prs = load_template()

            # Generate pages
            prs = init(
                datestring,
                org_name,
                inc,
                creds,
                inc_src_df,
                inc_date_df,
                ce_inc_df,
                domains,
                utld,
                tld_df,
                dm_df,
                dm_samp,
                malware,
                uma,
                ma_act_df,
                ma_samp,
                vulns,
                iv_df,
                iv_act_df,
                iv_samp,
                iv_attach,
                vuln_ma_df,
                vuln_ma_df2,
                assets,
                web,
                dark,
                web_df,
                web_source_df,
                web_attach,
                dark_web_df,
                web_only_df,
                prs,
            )

            # Export PPT
            export_set(output_directory, _id, datestring, prs)

            # Convert to PDF
            pdf = convert_to(
                output_directory,
                f"{output_directory}/ppt/{_id}-Posture_and_Exposure_Report-{datestring}.pptx",
            )

            # Embed csvdata and encrypt PDF
            cc_csv = f"{output_directory}/{_id}/compromised_credentials.csv"
            creds_attach.to_csv(cc_csv)
            da_csv = f"{output_directory}/{_id}/domain_alerts.csv"
            domains_attach.to_csv(da_csv)
            ma_csv = f"{output_directory}/{_id}/malware_alerts.csv"
            ma_attach.to_csv(ma_csv)
            iv_csv = f"{output_directory}/{_id}/inferred_vulnerability_associations.csv"
            iv_attach.to_csv(iv_csv)
            mi_csv = f"{output_directory}/{_id}/mention_incidents.csv"
            web_attach.to_csv(mi_csv)

            (filesize, tooLarge) = embed_and_encrypt(
                output_directory,
                _id,
                datestring,
                pdf,
                cc_csv,
                da_csv,
                ma_csv,
                iv_csv,
                mi_csv,
                password,
            )
            # Need to make sure Cyhy Mailer doesn't send files that are too large
            if tooLarge:
                print(f"{_id} is too large. File size: {filesize} Limit: 20MB")

            generated_reports = generated_reports + 1

    print(f"{generated_reports} reports generated")


def main():
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
        return 1

    # Assign validated arguments to variables
    log_level: str = validated_args["--log-level"]

    # Set up logging
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
    )
    logging.info(
        "Loading Posture & Exposure Report Template, Version : %s", __version__
    )
    logging.info("Generating Graphs")

    # Create output directory
    try:
        os.mkdir(f"{args['OUTPUT_DIRECTORY']}")
    except FileExistsError as err:
        logging.error(f"The output directory cannot be created. {err}")
        return 0

    # Connect to cyhy database
    db_creds_file = args["--db-creds-file"]
    try:
        db = db_from_config(db_creds_file)
    except FileNotFoundError as not_found:
        logging.error("%s : Missing input data. No report generated.", not_found)
        return 0

    except yaml.YAMLError:
        logging.critical(
            f"Database configuration file {db_creds_file} does not contain valid YAML",
            exc_info=True,
        )
        print("Database configuration file {db_creds_file} does not contain valid YAML")
        return 1
    except KeyError:
        logging.critical(
            f"Database configuration file {db_creds_file} does not contain the expected keys",
            exc_info=True,
        )
        print(
            "Database configuration file {db_creds_file} does not contain the expected keys"
        )
        return 1
    except pymongo.errors.ConnectionError:
        logging.critical(
            f"Unable to connect to the database server in {db_creds_file}",
            exc_info=True,
        )
        print("Unable to connect to the database server in {db_creds_file}")
        return 1
    except pymongo.errors.InvalidName:
        logging.critical(
            f"The database in {db_creds_file} does not exist", exc_info=True
        )
        print("The database in {db_creds_file} does not exist")
        return 1

    # Generate reports
    generate_reports(
        db, args["REPORT_DATE"], args["DATA_DIRECTORY"], args["OUTPUT_DIRECTORY"]
    )

    # Stop logging and clean up
    logging.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
