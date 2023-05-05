# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError

# cisagov Libraries
from pe_mailer.stats_message import StatsMessage
from pe_mailer.email_reports import send_message, UnableToSendError

def email_userWeeklyStatusReminder_report(user, scorecard_filename, month_num, year):
    """Email scorecard."""
    print("running email report")

    # Get month name form number
    datetime_object = datetime.datetime.strptime(month_num, "%m")
    month = datetime_object.strftime("%b")

    # Assume role to use mailer
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=MAILER_ARN,
        RoleSessionName="AssumeRoleSession1"
    )
    credentials = assumed_role_object['Credentials']

    ses_client = boto3.client("ses",
                              region_name="us-east-1",
                              aws_access_key_id=credentials['AccessKeyId'],
                              aws_secret_access_key=credentials[
                                  'SecretAccessKey'],
                              aws_session_token=credentials['SessionToken']
                              )

    # Send reports and gather summary statistics
    # stats = send_scorecard(ses_client, pe_report_dir, to)
    # Construct the Posture and Exposure message to send
    to_emails = [user]
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
            user,
            exc_info=True,
            stack_info=True,
        )

    stats = f"{agencies_emailed_scorecard} email sent."
    LOGGER.info(stats)

    # Email the summary statistics, if necessary
    summary_to = "craig.duhn@associates.cisa.dhs.gov"
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
