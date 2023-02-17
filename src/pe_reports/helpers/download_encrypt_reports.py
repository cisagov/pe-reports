"""cisagov/pe-reports: A tool for downloading and encrypting PE reports.

Usage:
  pe-reports REPORT_DATE OUTPUT_DIRECTORY [--ssh-rsa-file=FILENAME]

Options:
  -h --help                         Show this message.
  REPORT_DATE                       Last date of the report period, format YYYY-MM-DD
  OUTPUT_DIRECTORY                  The directory where the encrypted reports are downloaded
  -c --ssh-rsa-file=FILENAME        A YAML file containing the Cyber
                                    Hygiene database credentials.
"""
import fitz
import traceback
from docopt import docopt
import boto3
import os
import logging
from pe_reports.data.db_query import connect_to_staging, get_orgs, get_orgs_pass

LOGGER = logging.getLogger(__name__)
ACCESSOR_AWS_PROFILE = ""
BUCKET_NAME = ""
PASSWORD = ""


def encrypt(file, password, encrypted_file):
    """Encrypt files."""
    doc = fitz.open(file)
    # Add encryption
    perm = int(
        fitz.PDF_PERM_ACCESSIBILITY
        | fitz.PDF_PERM_PRINT  # permit printing
        | fitz.PDF_PERM_COPY  # permit copying
        | fitz.PDF_PERM_ANNOTATE  # permit annotations
    )
    encrypt_meth = fitz.PDF_ENCRYPT_AES_256
    doc.save(
        encrypted_file,
        encryption=encrypt_meth,  # set the encryption method
        user_pw=password,  # set the user password
        permissions=perm,  # set permissions
        garbage=4,
        deflate=True,
    )


def download_encrypt_reports(report_date, output_dir):
    """Fetch reports from S3 bucket."""
    # Connect to the database to get org names
    conn = connect_to_staging()
    pe_orgs = get_orgs(conn)

    # Fetch the correct AWS credentials and connect to S3
    session = boto3.Session(profile_name=ACCESSOR_AWS_PROFILE)
    s3 = session.client("s3")

    download_count = 0
    total = len(pe_orgs)
    print(total)
    for org in pe_orgs:
        org_code = org[2]
        if org_code == "FAA":
            continue

        print(f"Downloading {org_code}")
        # Download each report
        try:
            # P&E Report
            file_name = f"Posture_and_Exposure_Report-{org_code}-{report_date}.pdf"
            object_name = f"{report_date}/{file_name}"
            output_file = f"{output_dir}/{file_name}"

            # ASM Summary
            asm_file_name = f"Posture-and-Exposure-ASM-Summary_{org_code}_{report_date}.pdf"
            asm_object_name = f"{report_date}/{asm_file_name}"
            asm_output_file = f"{output_dir}/{asm_file_name}"

            # Download each
            s3.download_file(BUCKET_NAME, object_name, output_file)
            s3.download_file(BUCKET_NAME, asm_object_name, asm_output_file)
            download_count += 1
        except Exception as e:
            LOGGER.error(e)
            LOGGER.error("Report is not in S3 for %s", org_code)
            continue

    # Encrypt the reports
    conn = connect_to_staging()
    pe_org_pass = get_orgs_pass(conn, PASSWORD)
    conn.close()
    encrypted_count = 0
    for org_pass in pe_org_pass:
        print(org_pass)
        password = org_pass[1]
        if password == None:
            LOGGER.error("NO PASSWORD")
            continue
        # Check if file exists before encrypting
        current_file = (
            f"{output_dir}/Posture_and_Exposure_Report-{org_pass[0]}-{report_date}.pdf"
        )
        current_asm_file = f"{output_dir}/Posture-and-Exposure-ASM-Summary_{org_pass[0]}_{report_date}.pdf"
        if not os.path.isfile(current_file):
            LOGGER.error("%s report does not exist.", org_pass[0])
            continue
        if not os.path.isfile(current_asm_file):
            LOGGER.error("%s ASM summary does not exist.", org_pass[0])
            continue

        # Create encrypted path
        encrypt_dir = f"{output_dir}/encrypted_reports"
        if not os.path.exists(encrypt_dir):
            os.mkdir(encrypt_dir)
        encrypted_org_path = f"{output_dir}/encrypted_reports/{org_pass[0]}"
        if not os.path.exists(encrypted_org_path):
            os.mkdir(encrypted_org_path)
        encrypted_file = f"{encrypted_org_path}/Posture_and_Exposure_Report-{org_pass[0]}-{report_date}.pdf"
        asm_encrypted_file = f"{encrypted_org_path}/Posture-and-Exposure-ASM-Summary_{org_pass[0]}_{report_date}.pdf"


        # Encrypt the reports
        try:
            encrypt(current_file, password, encrypted_file)
            # Encrypt the summary
            encrypt(current_asm_file, password, asm_encrypted_file)
            encrypted_count += 1
        except Exception as e:
            LOGGER.error(e)
            print(traceback.format_exc())
            LOGGER.error("%s report failed to encrypt.", org_pass[0])
            continue

    LOGGER.info("%d/%d were downloaded.", download_count, total)
    LOGGER.info("%d/%d were encrypted.", encrypted_count, total)


def main():
    """Download reports from S3 and encrypt."""
    # Parse command line arguments
    args = docopt(__doc__)
    report_date = args["REPORT_DATE"]
    output_dir = args["OUTPUT_DIRECTORY"]
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    print(report_date)
    print(output_dir)

    # Download the reports from S3
    download_encrypt_reports(report_date, output_dir)


if __name__ == "__main__":
    main()
