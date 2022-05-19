"""ciagov/pe-reports: A tool for creating Posture & Exposure reports.

Usage:
  pe-reports REPORT_DATE INPUT_DIRECTORY [--db-creds-file=FILENAME]

Options:
  -h --help                         Show this message.
  REPORT_DATE                       Date of the report, format YYYY-MM-DD
  INPUT_DIRECTORY                   The directory where the Finished reports are located. Organized by
                                    owner.
  -c --db-creds-file=FILENAME       A YAML file containing the Cyber
                                    Hygiene database credentials.
                                    [default: /secrets/database_creds.yml]
"""
# Standard Python Libraries
import json
import logging
import os
import sys

# Third-Party Libraries
from docopt import docopt
import fitz
from mongo_db_from_config import db_from_config
import pymongo

# from _version import __version__
import yaml


def embed_and_encrypt(
    input_directory,
    _id,
    datestring,
    file,
    password,
):
    """Embeds raw data into pdf and encrypts file."""
    doc = fitz.open(file)
    output = f"/output_05_15/{_id}/Posture_and_Exposure_Report-{datestring}.pdf"

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
    except Exception:
        # Print an error if there is no key value
        print(f"No key found for ID {id}")

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


def main():
    """Run main."""
    # Parse command line arguments
    args = docopt(__doc__)

    if not os.path.exists(args["INPUT_DIRECTORY"]):
        os.mkdir(args["INPUT_DIRECTORY"])

    # Connect to cyhy database
    db_creds_file = args["--db-creds-file"]
    try:
        db = db_from_config(db_creds_file)
    except OSError:
        logging.critical(
            f"Database configuration file {db_creds_file} does not exist", exc_info=True
        )
        print("")
        return 1
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

    print("Starting Encryption")

    agencies = []
    f = open("org_info.json")
    org_obj = json.load(f)

    for agency in org_obj:
        agencies.append(agency["cyhy_db_name"])

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
    # print(len(request_data))

    for request in request_data:
        _id = request["_id"]
        print(_id)
        password = get_key_from_request(request)
        pdf = f"{args['INPUT_DIRECTORY']}/{_id}/Posture_and_Exposure_Report-{args['REPORT_DATE']}.pdf"
        (filesize, tooLarge) = embed_and_encrypt(
            args["INPUT_DIRECTORY"],
            _id,
            args["REPORT_DATE"],
            pdf,
            password,
        )
        if tooLarge:
            print(f"{_id} is too large. File size: {filesize} Limit: 20MB")

        generated_reports = generated_reports + 1

    print(f"{generated_reports} reports encrypted")


if __name__ == "__main__":

    sys.exit(main())
