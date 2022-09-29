"""A module to send Posture and Exposure reports using AWS SES.

Usage:
    pe-mailer [--pe-report-dir=DIRECTORY] [--db-creds-file=FILENAME] [--log-level=LEVEL]

Arguments:
  -p --pe-report-dir=DIRECTORY      Directory containing the pe-reports output.
  -c --db-creds-file=FILENAME       A YAML file containing the Cyber
                                    Hygiene database credentials.
                                    [default: /secrets/database_creds.yml]

Options:
  -h --help                         Show this message.
  -v --version                      Show version information.
  -s --summary-to=EMAILS            A comma-separated list of email addresses
                                    to which the summary statistics should be
                                    sent at the end of the run.  If not
                                    specified then no summary will be sent.
  -t --test_emails=EMAILS           A comma-separated list of email addresses
                                    to which to test email send process. If not
                                    specified then no test will be sent.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
"""

# Standard Python Libraries
import datetime
import glob
import logging
import os
import re
import sys
from typing import Any, Dict

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError
import docopt
from mongo_db_from_config import db_from_config
import pymongo.errors
from schema import And, Schema, SchemaError, Use
import yaml

# cisagov Libraries
from pe_reports import CENTRAL_LOGGING_FILE

from ._version import __version__
from .pe_message import PEMessage
from .stats_message import StatsMessage

LOGGER = logging.getLogger(__name__)


def get_emails_from_request(request):
    """Return the agency's correspondence email address(es).

    Given the request document, return the proper email address or
    addresses to use for corresponding with the agency.

    Parameters
    ----------
    request : dict
        The request documents for which the corresponding email
        address is desired.

    Returns
    -------
    list of str: A list containing the proper email addresses to use
    for corresponding with the agency

    """
    id = request["_id"]
    # Drop any contacts that do not have a type and a non-empty email attribute
    contacts = [
        c
        for c in request["agency"]["contacts"]
        if "type" in c and "email" in c and c["email"].split()
    ]

    for c in request["agency"]["contacts"]:
        if "type" not in c or "email" not in c or not c["email"].split():
            LOGGER.warning(
                "Agency with ID %s has a contact that is missing an email and/or type attribute!",
                id,
            )

    distro_emails = [c["email"] for c in contacts if c["type"] == "DISTRO"]
    technical_emails = [c["email"] for c in contacts if c["type"] == "TECHNICAL"]

    # There should be zero or one distro email
    if len(distro_emails) > 1:
        LOGGER.warning("More than one DISTRO email address for agency with ID %s", id)

    # Send to the distro email, else send to the technical emails.
    to_emails = distro_emails
    if not to_emails:
        to_emails = technical_emails

    # At this point to_emails should contain at least one email
    if not to_emails:
        LOGGER.error("No emails found for ID %s", id)

    return to_emails


def get_all_descendants(db, parent):
    """Return all (non-retired) descendants of the parent.

    Parameters
    ----------
    db : MongoDatabase
        The Mongo database from which request document data can be
        retrieved.

    parent : str
        The parent for which all descendants are desired.

    Returns
    -------
    list(str): The descendants of the parent.

    Throws
    ------
    ValueError: If there is no request document corresponding to the
    specified parent.

    """
    current_request = db.requests.find_one({"_id": parent})
    if not current_request:
        raise ValueError(parent + " has no request document")

    descendants = []
    if current_request.get("children"):
        for child in current_request["children"]:
            if not db.requests.find_one({"_id": child}).get("retired"):
                descendants.append(child)
                descendants += get_all_descendants(db, child)

    # Remove duplicates
    return list(set(descendants))


def get_requests_raw(db, query):
    """Return a cursor for iterating over agencies' request documents.

    Parameters
    ----------
    db : MongoDatabase
        The Mongo database from which agency data can be retrieved.

    query : dict
        The query to perform.

    Returns
    -------
    pymongo.cursor.Cursor: A cursor that can be used to iterate over
    the request documents.

    Throws
    ------
    pymongo.errors.TypeError: If unable to connect to the requested
    server.

    pymongo.errors.InvalidOperation: If the cursor has already been
    used.

    """
    projection = {
        "_id": True,
        "agency.acronym": True,
        "agency.contacts.name": True,
        "agency.contacts.email": True,
        "agency.contacts.type": True,
    }

    try:
        requests = db.requests.find(query, projection)
    except TypeError:
        LOGGER.critical(
            "There was an error with the MongoDB query that retrieves the request documents",
            exc_info=True,
        )
        raise

    return requests


def get_requests(db, agency_list):
    """Return a cursor for iterating over agencies' request documents.

    Parameters
    ----------
    db : MongoDatabase
        The Mongo database from which agency data can be retrieved.

    agency_list : list(str)
        A list of agency IDs (e.g. DOE, DOJ, DHS). If None then no such
        restriction is placed on the query.

    Returns
    -------
    pymongo.cursor.Cursor: A cursor that can be used to iterate over
    the request documents.

    Throws
    ------
    pymongo.errors.TypeError: If unable to connect to the requested
    server.

    pymongo.errors.InvalidOperation: If the cursor has already been
    used.

    """
    query = {"retired": {"$ne": True}}
    query["_id"] = {"$in": agency_list}

    return get_requests_raw(db, query)


class UnableToSendError(Exception):
    """Raise when an error is encountered when sending an email.

    Attributes
    ----------
    response : dict
        The response returned by boto3.

    """

    def __init__(self, response):
        """Initialize."""
        self.response = response


def send_message(ses_client, message, counter=None):
    """Send a message.

    Parameters
    ----------
    ses_client : boto3.client
        The boto3 SES client via which the message is to be sent.

    message : email.message.Message
        The email message that is to be sent.

    counter : int
        A counter.

    Returns
    -------
    int: If counter was not None, then counter + 1 is returned if the
    message was sent sent successfully and counter is returned if not.
    If counter was None then None is returned.

    Throws
    ------
    ClientError: If an error is encountered when attempting to send
    the message.

    UnableToSendError: If the response from sending the message is
    anything other than 200.

    """
    # Send Email
    response = ses_client.send_raw_email(RawMessage={"Data": message.as_string()})

    # Check for errors
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code != 200:
        LOGGER.error("Unable to send message. Response from boto3 is: %s", response)
        raise UnableToSendError(response)

    if counter is not None:
        counter += 1

    return counter


def send_pe_reports(db, ses_client, pe_report_dir, to):
    """Send out Posture and Exposure reports.

    Parameters
    ----------
    db : MongoDatabase
        The Mongo database from which Cyber Hygiene agency data can
        be retrieved.

    ses_client : boto3.client
        The boto3 SES client via which the message is to be sent.

    pe_report_dir : str
        The directory where the Posture and Exposure reports can be found.
        If None then no Posture and Exposure reports will be sent.

    Returns
    -------
    tuple(str): A tuple of strings that summarizes what was sent.

    """
    agencies = []

    contents = os.walk(pe_report_dir)

    for folders in contents:
        for folder_name in folders:
            agencies.append(folder_name)

    try:
        pe_requests = get_requests(db, agency_list=agencies)
    except TypeError:
        return 4

    try:
        # The directory must containe one usable report
        cyhy_agencies = pe_requests.count()
        1 / cyhy_agencies
    except ZeroDivisionError:
        LOGGER.critical("No report data is found in %s", pe_report_dir)
        sys.exit(1)

    agencies_emailed_pe_reports = 0

    # Iterate over cyhy_requests, if necessary
    if pe_report_dir:
        for request in pe_requests:
            id = request["_id"]
            if to is not None:
                to_emails = to
            else:
                to_emails = get_emails_from_request(request)
            # to_emails should contain at least one email
            if not to_emails:
                continue

            # Find and mail the Posture and Exposure report, if necessary
            pe_report_glob = f"{pe_report_dir}/{id}/*.pdf"
            pe_report_filenames = sorted(glob.glob(pe_report_glob))

            # At most one Cybex report and CSV should match
            if len(pe_report_filenames) > 1:
                LOGGER.warning("More than one PDF report found")
            elif not pe_report_filenames:
                LOGGER.error("No PDF report found")

            if pe_report_filenames:
                # We take the last filename since, if there happens to be more than
                # one, it should the latest.  (This is because we sorted the glob
                # results.)
                pe_report_filename = pe_report_filenames[-1]

                # Extract the report date from the report filename
                match = re.search(
                    r"-(?P<date>\d{4}-[01]\d-[0-3]\d)",
                    pe_report_filename,
                )
                print(match)
                report_date = datetime.datetime.strptime(
                    match.group("date"), "%Y-%m-%d"
                ).strftime("%B %d, %Y")

                # Construct the Posture and Exposure message to send
                message = PEMessage(pe_report_filename, report_date, id, to_emails)

                print(to_emails)
                print(pe_report_filename)
                print(report_date)

                try:
                    agencies_emailed_pe_reports = send_message(
                        ses_client, message, agencies_emailed_pe_reports
                    )
                except (UnableToSendError, ClientError):
                    logging.error(
                        "Unable to send Posture and Exposure report for agency with ID %s",
                        id,
                        exc_info=True,
                        stack_info=True,
                    )

    # Print out and log some statistics
    pe_stats_string = f"Out of {cyhy_agencies} agencies with Posture and Exposure reports, {agencies_emailed_pe_reports} ({100.0 * agencies_emailed_pe_reports / cyhy_agencies:.2f}%) were emailed."
    LOGGER.info(pe_stats_string)

    return pe_stats_string


def send_reports(pe_report_dir, db_creds_file, summary_to=None, test_emails=None):
    """Send emails."""
    try:
        os.stat(pe_report_dir)
    except FileNotFoundError:
        LOGGER.critical("Directory to send reports does not exist")
        return 1

    try:
        db = db_from_config(db_creds_file)
    except OSError:
        LOGGER.critical("Database configuration file %s does not exist", db_creds_file)
        return 1

    except yaml.YAMLError:
        LOGGER.critical(
            "Database configuration file %s does not contain valid YAML",
            db_creds_file,
            exc_info=True,
        )
        return 1
    except KeyError:
        LOGGER.critical(
            "Database configuration file %s does not contain the expected keys",
            db_creds_file,
            exc_info=True,
        )
        return 1
    except pymongo.errors.ConnectionError:
        LOGGER.critical(
            "Unable to connect to the database server in %s",
            db_creds_file,
            exc_info=True,
        )
        return 1
    except pymongo.errors.InvalidName:
        LOGGER.critical(
            "The database in %s does not exist", db_creds_file, exc_info=True
        )
        return 1

    ses_client = boto3.client("ses", region_name="us-east-1")

    # Email the summary statistics, if necessary
    if test_emails is not None:
        to = test_emails.split(",")
    else:
        to = None

    # Send reports and gather summary statistics
    all_stats_strings = []

    stats = send_pe_reports(db, ses_client, pe_report_dir, to)
    all_stats_strings.extend(stats)

    # Email the summary statistics, if necessary
    if summary_to is not None and all_stats_strings:
        message = StatsMessage(summary_to.split(","), all_stats_strings)
        try:
            send_message(ses_client, message)
        except (UnableToSendError, ClientError):
            LOGGER.error(
                "Unable to send cyhy-mailer report summary",
                exc_info=True,
                stack_info=True,
            )
    else:
        LOGGER.warning("Nothing was emailed.")
        print("Nothing was emailed.")

    # Stop logging and clean up
    logging.shutdown()


def main():
    """Send emails."""
    # Parse command line arguments
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)

    # Validate and convert arguments
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

    LOGGER.info("Sending Posture & Exposure Reports, Version : %s", __version__)

    send_reports(
        # TODO: Improve use of schema to validate arguments.
        # Issue 19: https://github.com/cisagov/pe-reports/issues/19
        validated_args["--pe-report-dir"],
        validated_args["--db-creds-file"],
        summary_to=None,
        test_emails=None,
    )

    # Stop logging and clean up
    logging.shutdown()
