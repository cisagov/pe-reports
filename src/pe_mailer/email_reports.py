"""A module to send Posture and Exposure reports using AWS SES.

Usage:
    pe-mailer [--pe-report-dir=DIRECTORY] [--summary-to=EMAILS] [--test-emails=EMAILS] [--log-level=LEVEL]

Arguments:
  -p --pe-report-dir=DIRECTORY      Directory containing the pe-reports output.

Options:
  -h --help                         Show this message.
  -v --version                      Show version information.
  -s --summary-to=EMAILS            A comma-separated list of email addresses
                                    to which the summary statistics should be
                                    sent at the end of the run.  If not
                                    specified then no summary will be sent.
  -t --test-emails=EMAILS           A comma-separated list of email addresses
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
import pe_reports
from pe_reports.data.db_query import connect, get_orgs, get_orgs_contacts

from ._version import __version__
from .pe_message import PEMessage
from .stats_message import StatsMessage

LOGGER = logging.getLogger(__name__)
MAILER_AWS_PROFILE = "cool-dns-sessendemail-cyber.dhs.gov"
MAILER_ARN = os.environ.get("MAILER_ARN")


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


def send_pe_reports(ses_client, pe_report_dir, to):
    """Send out Posture and Exposure reports.

    Parameters
    ----------

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

    for root, folders, files in contents:
        for folder_name in folders:
            agencies.append(folder_name)

    try:
        print(agencies)
        staging_conn = connect()
        pe_orgs = get_orgs(staging_conn)
    except TypeError:
        return 4

    try:
        # The directory must contain one usable report
        cyhy_agencies = len(pe_orgs)
        LOGGER.info(f"{cyhy_agencies} agencies found in P&E.")
        1 / cyhy_agencies
    except ZeroDivisionError:
        LOGGER.critical("No report data is found in %s", pe_report_dir)
        sys.exit(1)

    staging_conn = connect()
    # org_contacts = get_orgs_contacts(staging_conn) # old tsql ver.
    org_contacts = get_orgs_contacts() # api ver.
    
    agencies_emailed_pe_reports = 0
    # Iterate over cyhy_requests, if necessary
    if pe_report_dir:
        for org in pe_orgs:
            id = org[2]
            if id == "GSEC":
                continue
            if to is not None:
                to_emails = to
            else:
                contact_dict = {"DISTRO": "", "TECHNICAL": []}
                for contact in org_contacts:
                    email = contact[0]
                    type = contact[1]
                    contact_org_id = contact[2]
                    if contact_org_id == id:
                        if type == "DISTRO":
                            contact_dict["DISTRO"] = [email]
                        elif type == "TECHNICAL":
                            contact_dict["TECHNICAL"].append(email)
                        else:
                            continue
                if contact_dict["DISTRO"] == "":
                    to_emails = contact_dict["TECHNICAL"]
                else:
                    to_emails = contact_dict["DISTRO"]

            # to_emails should contain at least one email
            if not to_emails:
                continue

            # Find and mail the Posture and Exposure report, if necessary
            pe_report_glob = f"{pe_report_dir}/{id}/*.pdf"
            pe_report_filenames = sorted(glob.glob(pe_report_glob))

            # At most one Cybex report and CSV should match
            if len(pe_report_filenames) > 2:
                LOGGER.warning("More than two PDF reports found")
            elif not pe_report_filenames:
                LOGGER.error("No PDF report found")
                continue

            if pe_report_filenames:
                # We take the last filename since, if there happens to be more than
                # one, it should the latest.  (This is because we sorted the glob
                # results.)
                for file in pe_report_filenames:
                    if "Posture-and-Exposure-ASM-Summary" in file:
                        pe_asm_filename = file
                    elif "Posture_and_Exposure_Report" in file:
                        pe_report_filename = file
                    else:
                        LOGGER.error("Extra PDF file or named incorrectly.")
                        continue

                # Extract the report date from the report filename
                match = re.search(
                    r"-(?P<date>\d{4}-[01]\d-[0-3]\d)",
                    pe_report_filename,
                )
                report_date = datetime.datetime.strptime(
                    match.group("date"), "%Y-%m-%d"
                ).strftime("%B %d, %Y")

                # Construct the Posture and Exposure message to send
                message = PEMessage(
                    pe_report_filename, pe_asm_filename, report_date, id, to_emails
                )

                print(to_emails)
                print(pe_report_filename)
                print(pe_asm_filename)
                print(report_date)

                try:
                    agencies_emailed_pe_reports = send_message(
                        ses_client, message, agencies_emailed_pe_reports
                    )
                except (UnableToSendError, ClientError):
                    LOGGER.error(
                        "Unable to send Posture and Exposure report for agency with ID %s",
                        id,
                        exc_info=True,
                        stack_info=True,
                    )

    # Print out and log some statistics
    pe_stats_string = f"Out of {cyhy_agencies} agencies with Posture and Exposure reports, {agencies_emailed_pe_reports} ({100.0 * agencies_emailed_pe_reports / cyhy_agencies:.2f}%) were emailed."
    LOGGER.info(pe_stats_string)

    return pe_stats_string


def send_reports(pe_report_dir, summary_to, test_emails):
    """Send emails."""
    try:
        os.stat(pe_report_dir)
    except FileNotFoundError:
        LOGGER.critical("Directory to send reports does not exist")
        return 1

    # Assume role to use mailer
    sts_client = boto3.client('sts')
    assumed_role_object=sts_client.assume_role(
        RoleArn=MAILER_ARN,
        RoleSessionName="AssumeRoleSession1"
    )
    credentials=assumed_role_object['Credentials']

    ses_client = boto3.client("ses", 
        region_name="us-east-1",
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    

    # Email the summary statistics, if necessary
    if test_emails is not None:
        to = test_emails.split(",")
    else:
        to = None

    # Send reports and gather summary statistics
    stats = send_pe_reports(ses_client, pe_report_dir, to)

    # Email the summary statistics, if necessary
    if summary_to is not None and stats:
        message = StatsMessage(summary_to.split(","), stats)
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
        filename=pe_reports.CENTRAL_LOGGING_FILE,
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
        validated_args["--summary-to"],
        validated_args["--test-emails"],
    )

    # Stop logging and clean up
    logging.shutdown()
