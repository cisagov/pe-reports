"""Combine all excel data."""
# Standard Python Libraries
import logging
import os

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError
import pandas as pd

# cisagov Libraries
from pe_reports.data.db_query import connect, get_orgs

PATH = "/var/www/report_run_03-31"
LOGGER = logging.getLogger(__name__)
ACCESSOR_AWS_PROFILE = os.getenv("ACCESSOR_PROFILE")
DATE = "2023-03-31"


def upload_file_to_s3(file_name, datestring, bucket):
    """Upload a file to an S3 bucket."""
    session = boto3.Session(profile_name=ACCESSOR_AWS_PROFILE)
    s3_client = session.client("s3")

    # If S3 object_name was not specified, use file_name
    object_name = f"{datestring}/_combined-raw-data/{os.path.basename(file_name)}"

    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
        if response is None:
            LOGGER.info("Success uploading to S3.")
        else:
            LOGGER.info(response)
    except ClientError as e:
        LOGGER.error(e)


def main():
    """Define main function."""
    # Get PE orgs from PE db
    conn = connect()
    if conn:
        pe_orgs = get_orgs(conn)
    else:
        return 1
    # generated_reports = 0

    # Iterate over organizations
    if pe_orgs:
        # pe_orgs.reverse()
        cred_excel_merged = pd.DataFrame()
        domain_suspected_excel_merged = pd.DataFrame()
        domain_alerts_excel_merged = pd.DataFrame()
        vuln_assets_merged = pd.DataFrame()
        vuln_insecure_merged = pd.DataFrame()
        vuln_verified_merged = pd.DataFrame()
        dark_mentions_merged = pd.DataFrame()
        dark_alerts_merged = pd.DataFrame()

        asm_cidr_merged = pd.DataFrame()
        asm_extra_ips_merged = pd.DataFrame()
        asm_ports_protocols_merged = pd.DataFrame()
        asm_root_domains_merged = pd.DataFrame()
        asm_sub_domains_merged = pd.DataFrame()
        asm_software_merged = pd.DataFrame()
        asm_foreign_ips_merged = pd.DataFrame()
        for org in pe_orgs:
            # Assign organization values
            # org_uid = org[0]
            # org_name = org[1]
            org_code = org[2]

            try:
                # Credentials
                cred_df = pd.read_excel(
                    f"{PATH}/{org_code}/compromised_credentials.xlsx",
                    sheet_name="Credentials",
                    engine="openpyxl",
                )
                cred_df["stakeholder"] = org_code
            except Exception:
                print(f"{org_code}doesn't exist.")
                continue

            try:
                # Domains
                domain_suspected_df = pd.read_excel(
                    f"{PATH}/{org_code}/domain_alerts.xlsx",
                    sheet_name="Suspected Domains",
                    engine="openpyxl",
                )
                domain_alerts_df = pd.read_excel(
                    f"{PATH}/{org_code}/domain_alerts.xlsx",
                    sheet_name="Domain Alerts",
                    engine="openpyxl",
                )
                domain_suspected_df["stakeholder"] = org_code
                domain_alerts_df["stakeholder"] = org_code
            except Exception:
                print(f"{org_code} doesn't exist.")
                continue

            try:
                # Vulns
                vuln_assets_df = pd.read_excel(
                    f"{PATH}/{org_code}/vuln_alerts.xlsx",
                    sheet_name="Assets",
                    engine="openpyxl",
                )
                vuln_assets_df["stakeholder"] = org_code

                vuln_insecure_df = pd.read_excel(
                    f"{PATH}/{org_code}/vuln_alerts.xlsx",
                    sheet_name="Insecure",
                    engine="openpyxl",
                )
                vuln_insecure_df["stakeholder"] = org_code

                vuln_verified_df = pd.read_excel(
                    f"{PATH}/{org_code}/vuln_alerts.xlsx",
                    sheet_name="Verified Vulns",
                    engine="openpyxl",
                )
                vuln_verified_df["stakeholder"] = org_code

            except Exception:
                print(f"{org_code} doesn't exist.")
                continue

            try:
                # Dark Web
                dark_mentions_df = pd.read_excel(
                    f"{PATH}/{org_code}/mention_incidents.xlsx",
                    sheet_name="Dark Web Mentions",
                    engine="openpyxl",
                )
                dark_mentions_df["stakeholder"] = org_code

                dark_alerts_df = pd.read_excel(
                    f"{PATH}/{org_code}/mention_incidents.xlsx",
                    sheet_name="Dark Web Alerts",
                    engine="openpyxl",
                )
                dark_alerts_df["stakeholder"] = org_code

                dark_cves_merged = pd.read_excel(
                    f"{PATH}/{org_code}/mention_incidents.xlsx",
                    sheet_name="Top CVEs",
                    engine="openpyxl",
                )

            except Exception:
                print(f"{org_code} doesn't exist.")
                continue

            try:
                # ASM
                asm_cidr_df = pd.read_excel(
                    f"{PATH}/{org_code}/ASM_Summary.xlsx",
                    sheet_name="CIDRs",
                    engine="openpyxl",
                )
                asm_cidr_df["stakeholder"] = org_code

                asm_extra_ips_df = pd.read_excel(
                    f"{PATH}/{org_code}/ASM_Summary.xlsx",
                    sheet_name="Extra IPs",
                    engine="openpyxl",
                )
                asm_extra_ips_df["stakeholder"] = org_code

                asm_ports_protocols_df = pd.read_excel(
                    f"{PATH}/{org_code}/ASM_Summary.xlsx",
                    sheet_name="Ports_Protocols",
                    engine="openpyxl",
                )
                asm_ports_protocols_df["stakeholder"] = org_code

                asm_root_domains_df = pd.read_excel(
                    f"{PATH}/{org_code}/ASM_Summary.xlsx",
                    sheet_name="Root Domains",
                    engine="openpyxl",
                )
                asm_root_domains_df["stakeholder"] = org_code

                asm_sub_domains_df = pd.read_excel(
                    f"{PATH}/{org_code}/ASM_Summary.xlsx",
                    sheet_name="Sub-domains",
                    engine="openpyxl",
                )
                asm_sub_domains_df["stakeholder"] = org_code

                asm_software_df = pd.read_excel(
                    f"{PATH}/{org_code}/ASM_Summary.xlsx",
                    sheet_name="Software",
                    engine="openpyxl",
                )
                asm_software_df["stakeholder"] = org_code

                asm_foreign_ips_df = pd.read_excel(
                    f"{PATH}/{org_code}/ASM_Summary.xlsx",
                    sheet_name="Foreign IPs",
                    engine="openpyxl",
                )
                asm_foreign_ips_df["stakeholder"] = org_code

            except Exception:
                print(f"{org_code} doesn't exist.")
                continue

            # Append to merged excel
            cred_excel_merged = cred_excel_merged.append(cred_df, ignore_index=True)
            domain_suspected_excel_merged = domain_suspected_excel_merged.append(
                domain_suspected_df, ignore_index=True
            )
            domain_alerts_excel_merged = domain_alerts_excel_merged.append(
                domain_alerts_df, ignore_index=True
            )
            vuln_assets_merged = vuln_assets_merged.append(
                vuln_assets_df, ignore_index=True
            )
            vuln_insecure_merged = vuln_insecure_merged.append(
                vuln_insecure_df, ignore_index=True
            )
            vuln_verified_merged = vuln_verified_merged.append(
                vuln_verified_df, ignore_index=True
            )
            dark_mentions_merged = dark_mentions_merged.append(
                dark_mentions_df, ignore_index=True
            )
            dark_alerts_merged = dark_alerts_merged.append(
                dark_alerts_df, ignore_index=True
            )

            asm_cidr_merged = asm_cidr_merged.append(asm_cidr_df, ignore_index=True)
            asm_extra_ips_merged = asm_extra_ips_merged.append(
                asm_extra_ips_df, ignore_index=True
            )
            asm_ports_protocols_merged = asm_ports_protocols_merged.append(
                asm_ports_protocols_df, ignore_index=True
            )
            asm_root_domains_merged = asm_root_domains_merged.append(
                asm_root_domains_df, ignore_index=True
            )
            asm_sub_domains_merged = asm_sub_domains_merged.append(
                asm_sub_domains_df, ignore_index=True
            )
            asm_software_merged = asm_software_merged.append(
                asm_software_df, ignore_index=True
            )
            asm_foreign_ips_merged = asm_foreign_ips_merged.append(
                asm_foreign_ips_df, ignore_index=True
            )

        # Create output directory
        if not os.path.exists(f"{PATH}/_combined_raw_data"):
            os.mkdir(f"{PATH}/_combined_raw_data")

        # Create total creds
        credWriter = pd.ExcelWriter(
            f"{PATH}/_combined_raw_data/total_compromised_credentials.xlsx",
            engine="xlsxwriter",
        )
        cred_excel_merged.to_excel(
            credWriter,
            sheet_name="Credentials",
            index=False,
        )
        credWriter.save()

        # Create total Domain Alerts
        domWriter = pd.ExcelWriter(
            f"{PATH}/_combined_raw_data/total_domain_alerts.xlsx",
            engine="xlsxwriter",
        )
        domain_suspected_excel_merged.to_excel(
            domWriter,
            sheet_name="Suspected Domains",
            index=False,
        )
        domain_alerts_excel_merged.to_excel(
            domWriter,
            sheet_name="Domain Alerts",
            index=False,
        )
        domWriter.save()

        # Create total Vuln Alerts
        vulnWriter = pd.ExcelWriter(
            f"{PATH}/_combined_raw_data/total_vuln_alerts.xlsx",
            engine="xlsxwriter",
        )
        vuln_assets_merged.to_excel(
            vulnWriter,
            sheet_name="Assets",
            index=False,
        )
        vuln_insecure_merged.to_excel(
            vulnWriter,
            sheet_name="Insecure",
            index=False,
        )
        vuln_verified_merged.to_excel(
            vulnWriter,
            sheet_name="Verified Vulns",
            index=False,
        )
        vulnWriter.save()

        # Create total Vuln Alerts
        darkWriter = pd.ExcelWriter(
            f"{PATH}/_combined_raw_data/total_mention_incidents.xlsx",
            engine="xlsxwriter",
        )
        dark_mentions_merged.to_excel(
            darkWriter,
            sheet_name="Dark Web Mentions",
            index=False,
        )
        dark_alerts_merged.to_excel(
            darkWriter,
            sheet_name="Dark Web Alerts",
            index=False,
        )
        dark_cves_merged.to_excel(
            darkWriter,
            sheet_name="Top CVEs",
            index=False,
        )
        darkWriter.save()

        # Create total ASM Summary
        asmWriter = pd.ExcelWriter(
            f"{PATH}/_combined_raw_data/total_asm_summary.xlsx",
            engine="xlsxwriter",
        )
        asm_cidr_merged.to_excel(
            asmWriter,
            sheet_name="CIDRs",
            index=False,
        )
        asm_extra_ips_merged.to_excel(
            asmWriter,
            sheet_name="Extra IPs",
            index=False,
        )
        asm_ports_protocols_merged.to_excel(
            asmWriter,
            sheet_name="Ports_Protocols",
            index=False,
        )
        asm_root_domains_merged.to_excel(
            asmWriter,
            sheet_name="Root Domains",
            index=False,
        )
        asm_sub_domains_merged.to_excel(
            asmWriter,
            sheet_name="Sub-domains",
            index=False,
        )
        asm_software_merged.to_excel(
            asmWriter,
            sheet_name="Software",
            index=False,
        )
        asm_foreign_ips_merged.to_excel(
            asmWriter,
            sheet_name="Foreign IPs",
            index=False,
        )
        asmWriter.save()

    bucket = "cisa-crossfeed-staging-reports"
    upload_file_to_s3(f"{PATH}/_combined_raw_data/total_asm_summary.xlsx", DATE, bucket)
    upload_file_to_s3(
        f"{PATH}/_combined_raw_data/total_mention_incidents.xlsx", DATE, bucket
    )
    upload_file_to_s3(f"{PATH}/_combined_raw_data/total_vuln_alerts.xlsx", DATE, bucket)
    upload_file_to_s3(
        f"{PATH}/_combined_raw_data/total_domain_alerts.xlsx", DATE, bucket
    )
    upload_file_to_s3(
        f"{PATH}/_combined_raw_data/total_compromised_credentials.xlsx", DATE, bucket
    )


if __name__ == "__main__":
    main()
