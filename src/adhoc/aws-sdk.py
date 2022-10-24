import logging
import os
import boto3
import pe_reports
from botocore.exceptions import ClientError

LOGGER = logging.getLogger(__name__)

# Set up AWS configurations
os.environ["AWS_PROFILE"] = "cool-dns-sessendemail-cyber.dhs.gov"

ses_client = boto3.client("ses", region_name="us-east-1")
print(ses_client)

# Retrieve the list of existing buckets
# s3 = boto3.client("s3")
# response = s3.list_buckets()
# print(response)

# Output the bucket names
# LOGGER.info("Existing buckets:")
# bucket_name = "cisa-crossfeed-pe-reports"
# LOGGER.info(response["Buckets"]["Name"])
# if bucket_name in response["Buckets"]["Name"]:
#     LOGGER.info(bucket_name)
# else:
#     LOGGER.info("Bucket, %s, does not exist.", bucket_name)


def upload_file_to_s3(file_name, bucket):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    object_name = os.path.basename(file_name)

    # Upload the file
    s3_client = boto3.client("s3")
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
        LOGGER.info(response)
    except ClientError as e:
        logging.error(e)
        return False
    return True


def download_file_from_s3(bucket_name, object_name, file_name):
    s3 = boto3.client("s3")
    s3.download_file(bucket_name, object_name, file_name)
