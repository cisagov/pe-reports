"""Run the database backup script and save to S3 bucket."""
# Standard Python Libraries
import datetime
import logging
import os

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError
from importlib_resources import files

BACKUP_SCRIPT = files("pe_reports").joinpath("data/pg_backup.sh")
BUCKET_NAME = "cisa-crossfeed-staging-pe-db-backups"
DATE = datetime.datetime.now().strftime("%Y-%m-%d")
LOGGER = logging.getLogger(__name__)


def run_backup():
    """Run database backup script."""
    failed = False
    try:
        LOGGER.info("Running database backup...")
        LOGGER.info(BACKUP_SCRIPT)
        cmd = f"bash {BACKUP_SCRIPT}"
        # High sev. B605 warning acknowledged
        os.system(cmd)  # nosec
        LOGGER.info("Success")
    except Exception as e:
        failed = True
        LOGGER.error(e)
        LOGGER.error("Failed running backup script.")
    return failed


def upload_file_to_s3(file_name, datestring, bucket):
    """Upload a file to an S3 bucket."""
    LOGGER.info("Running S3 upload script.")
    LOGGER.info(file_name)
    s3_client = boto3.client("s3")

    # If S3 object_name was not specified, use file_name
    object_name = f"{datestring}/{os.path.basename(file_name)}"
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
        if response is None:
            LOGGER.info("Success uploading to S3.")
        else:
            LOGGER.error(response)
    except ClientError as e:
        LOGGER.error(e)


def main():
    """Run the database backup script and save to S3 bucket."""
    # Run DB backup script
    failed = run_backup()

    if failed:
        LOGGER.error("Not uploading to S3.")
        return

    # Upload each DB backup file to the specified S3 bucket
    backup_files = ["pedb_dump.sql", "pedb_globals.sql", "stderr.txt"]
    for file in backup_files:
        base = f"/var/www/db_backups/backups_{DATE}"
        file_name = f"{base}/{file}"
        upload_file_to_s3(file_name, DATE, BUCKET_NAME)


if __name__ == "__main__":
    main()
