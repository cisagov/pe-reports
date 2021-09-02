"""This module contains functions for sending Posture and Exposure reports using AWS SES."""

# Standard Python Libraries
import datetime
import glob
import logging
import os
import re

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError
from mongo_db_from_config import db_from_config
import pymongo.errors

# TODO: mypy check: PyYAML is not supported with Python 3.9 -
# Added to mypy hook - additional_dependencies: [types-all]
# https://github.com/asottile/types-all
# Create Issue to confirm with Fusion Dev that this is acceptable.
import yaml

from .pe_message import PandEMessage


class Error(Exception):
    """A base class for exceptions used in this module."""

    pass


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
    # Drop any contacts that do not have both a type and a non-empty email
    # attribute...
    contacts = [
        c
        for c in request["agency"]["contacts"]
        if "type" in c and "email" in c and c["email"].split()
    ]
    # ...but let's log a warning about them.
    for c in request["agency"]["contacts"]:
        if "type" not in c or "email" not in c or not c["email"].split():
            logging.warn(
                f"Agency with ID {id} has a contact that is missing an email and/or type attribute!"
            )

    distro_emails = [c["email"] for c in contacts if c["type"] == "DISTRO"]
    technical_emails = [c["email"] for c in contacts if c["type"] == "TECHNICAL"]

    # There should be zero or one distro email, so log a warning if
    # there are multiple.
    if len(distro_emails) > 1:
        logging.warn(f"More than one DISTRO email address for agency with ID {id}")

    # Send to the distro email, if it exists.  Otherwise, send to the
    # technical emails.
    to_emails = distro_emails
    if not to_emails:
        to_emails = technical_emails

    # At this point to_emails should contain at least one email
    if not to_emails:
        logging.error(f"No emails found for ID {id}")

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
        logging.critical(
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
    # "Are you silly?  I'm still gonna send it!"
    #   -- Larry Enticer
    response = ses_client.send_raw_email(RawMessage={"Data": message.as_string()})

    # Check for errors
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code != 200:
        logging.error(f"Unable to send message. Response from boto3 is: {response}")
        raise UnableToSendError(response)

    if counter is not None:
        counter += 1

    return counter


def send_pande_reports(db, ses_client, pande_report_dir, to):
    """Send out Posture and Exposure reports.

    Parameters
    ----------
    db : MongoDatabase
        The Mongo database from which Cyber Hygiene agency data can
        be retrieved.

    ses_client : boto3.client
        The boto3 SES client via which the message is to be sent.

    pande_report_dir : str
        The directory where the Posture and Exposure reports can be found.
        If None then no Posture and Exposure reports will be sent.

    Returns
    -------
    tuple(str): A tuple of strings that summarizes what was sent.

    """
    agencies = []

    contents = os.walk(pande_report_dir)
    for root, folders, files in contents:
        for folder_name in folders:
            agencies.append(folder_name)

    try:
        pande_requests = get_requests(db, agency_list=agencies)
    except TypeError:
        return 4

    try:
        cyhy_agencies = pande_requests.count()
        logging.debug(f"{cyhy_agencies} agencies found in CyHy")
    except pymongo.errors.OperationFailure:
        logging.critical(
            "Mongo database error while counting the number of request documents returned",
            exc_info=True,
        )

    agencies_emailed_pande_reports = 0

    ###
    # Iterate over cyhy_requests, if necessary
    ###
    if pande_report_dir:
        for request in pande_requests:
            id = request["_id"]
            if to is not None:
                to_emails = to
            else:
                to_emails = get_emails_from_request(request)
            # to_emails should contain at least one email
            if not to_emails:
                continue

            ###
            # Find and mail the Posture and Exposure report, if necessary
            ###

            pande_report_glob = f"{pande_report_dir}/{id}/*.pdf"
            pande_report_filenames = sorted(glob.glob(pande_report_glob))

            # At most one Cybex report and CSV should match
            if len(pande_report_filenames) > 1:
                logging.warn("More than one PDF report found")
            elif not pande_report_filenames:
                logging.error("No PDF report found")

            if pande_report_filenames:
                # We take the last filename since, if there happens to be more than
                # one, it should the latest.  (This is because we sorted the glob
                # results.)
                pande_report_filename = pande_report_filenames[-1]

                # Extract the report date from the report filename
                match = re.search(
                    r"-(?P<date>\d{4}-[01]\d-[0-3]\d)",
                    pande_report_filename,
                )
                print(match)
                report_date = datetime.datetime.strptime(
                    match.group("date"), "%Y-%m-%d"
                ).strftime("%B %d, %Y")

                # Construct the Posture and Exposure message to send
                message = PandEMessage(pande_report_filename, report_date, to_emails)

                print(to_emails)
                print(pande_report_filename)
                print(report_date)

                try:
                    agencies_emailed_pande_reports = send_message(
                        ses_client, message, agencies_emailed_pande_reports
                    )
                except (UnableToSendError, ClientError):
                    logging.error(
                        f"Unable to send Posture and Exposure report for agency with ID {id}",
                        exc_info=True,
                        stack_info=True,
                    )

    # Print out and log some statistics
    pande_stats_string = f"Out of {cyhy_agencies} agencies with Posture and Exposure reports, {agencies_emailed_pande_reports} ({100.0 * agencies_emailed_pande_reports / cyhy_agencies:.2f}%) were emailed."
    logging.info(pande_stats_string)
    print(pande_stats_string)

    return pande_stats_string


def send_reports(
    pande_report_dir, db_creds_file, summary_to=None, test_emails=None, debug=None
):
    """Send emails."""
    # Set up logging
    log_level = logging.WARNING
    if debug is not None:
        log_level = logging.DEBUG
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s", level=log_level
    )

    try:
        db = db_from_config(db_creds_file)
    except OSError:
        logging.critical(
            f"Database configuration file {db_creds_file} does not exist", exc_info=True
        )
        return 1
    except yaml.YAMLError:
        logging.critical(
            f"Database configuration file {db_creds_file} does not contain valid YAML",
            exc_info=True,
        )
        return 1
    except KeyError:
        logging.critical(
            f"Database configuration file {db_creds_file} does not contain the expected keys",
            exc_info=True,
        )
        return 1
    except pymongo.errors.ConnectionError:
        logging.critical(
            f"Unable to connect to the database server in {db_creds_file}",
            exc_info=True,
        )
        return 1
    except pymongo.errors.InvalidName:
        logging.critical(
            f"The database in {db_creds_file} does not exist", exc_info=True
        )
        return 1
    ses_client = boto3.client("ses", region_name="us-east-1")

    ###
    # Email the summary statistics, if necessary
    ###
    if test_emails is not None:
        to = test_emails.split(",")
    else:
        to = None

    ###
    # Send reports and gather summary statistics
    ###
    all_stats_strings = []

    stats = send_pande_reports(db, ses_client, pande_report_dir, to)
    all_stats_strings.extend(stats)

    ###
    # Email the summary statistics, if necessary
    ###

    if summary_to is not None and all_stats_strings:
        # TODO: StatsMessage needs defined
        # Create Issue
        StatsMessage = "Needs Defined!!"
        message = StatsMessage(summary_to.split(","), all_stats_strings)
        try:
            send_message(ses_client, message)
        except (UnableToSendError, ClientError):
            logging.error(
                "Unable to send cyhy-mailer report summary",
                exc_info=True,
                stack_info=True,
            )
    else:
        logging.warn("Nothing was emailed.")
        print("Nothing was emailed.")

    # Stop logging and clean up
    logging.shutdown()


def main():
    """Run mailer."""
    # TODO: Reestablish arguments for pande_report_dir and db_creds_file
    # Create Issue
    pande_report_dir = "/input"
    db_creds_file = "/creds"
    send_reports(
        pande_report_dir, db_creds_file, summary_to=None, test_emails=None, debug=None
    )
