"""Script to email scorecard."""
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
from pe_mailer.stats_message import StatsMessage
from pe_mailer.pe_message import ScorecardMessage
from pe_mailer.email_reports import send_message, UnableToSendError

LOGGER = logging.getLogger(__name__)
MAILER_ARN = os.environ.get("MAILER_ARN")

def email_scorecard_report(org_id, scorecard_filename, month_num, year):
    """Email scorecard."""
    print("running email report")

    # Get month name form number
    datetime_object = datetime.datetime.strptime(month_num, "%m")
    month = datetime_object.strftime("%b")

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

    # Send reports and gather summary statistics
    # stats = send_scorecard(ses_client, pe_report_dir, to)
    # Construct the Posture and Exposure message to send
    to_emails = ["andrew.loftus@associates.cisa.dhs.gov"]
    message = ScorecardMessage(
        scorecard_filename, month, year, org_id, to_emails
    )
    agencies_emailed_scorecard = 0

    try:
        agencies_emailed_scorecard = send_message(
            ses_client, message, agencies_emailed_scorecard
        )
    except (UnableToSendError, ClientError):
        LOGGER.error(
            "Unable to send Scorecard report for agency with ID %s",
            org_id,
            exc_info=True,
            stack_info=True,
        )
    
    stats = "%d email sent.", agencies_emailed_scorecard
    LOGGER.info(stats)


    # Email the summary statistics, if necessary
    summary_to = "andrew.loftus@associates.cisa.dhs.gov"
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
