"""Combine all excel data."""


import pandas as pd
import glob
from pe_reports.data.db_query import connect, get_orgs
import logging
import os
import json
import boto3

PATH = "/var/www/current_report_run"
LOGGER = logging.getLogger(__name__)
ACCESSOR_AWS_PROFILE = os.getenv("ACCESSOR_PROFILE")
DATE = '2023-03-31'


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
    # Get PE orgs from PE db
    conn = connect()
    if conn:
        pe_orgs = get_orgs(conn)
    else:
        return 1
    generated_reports = 0

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
            org_uid = org[0]
            org_name = org[1]
            org_code = org[2]

            try:
                # Credentials
                cred_df = pd.read_excel(
                    f"{PATH}/{org_code}/compromised_credentials.xlsx",
                    sheet_name="Credentials",
                    engine="openpyxl",
                )
                cred_df["stakeholder"] = org_code
            except:
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
            except:
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

            except:
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

            except:
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

            except:
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

            asm_cidr_merged = asm_cidr_merged.append(
                asm_cidr_df, ignore_index=True
            )
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
        cred_json = f"{PATH}/_combined_raw_data/total_compromised_credentials.json"
        cred_dict = cred_excel_merged.to_dict(orient="records")
        final_dict = {"credentials": cred_dict}
        with open(cred_json, "w") as outfile:
            json.dump(final_dict, outfile, default=str)

        # Create total Domain Alerts
        da_json = f"{PATH}/_combined_raw_data/total_domain_alerts.json"
        susp_domains_dict = domain_suspected_excel_merged.to_dict(orient="records")
        dom_alerts_dict = domain_alerts_excel_merged.to_dict(orient="records")
        final_dict = {
            "suspected_domains": susp_domains_dict,
            "domain_alerts": dom_alerts_dict,
        }
        with open(da_json, "w") as outfile:
            json.dump(final_dict, outfile, default=str)


        # Create total Vuln Alerts
        vuln_json = f"{PATH}/_combined_raw_data/total_vuln_alerts.json"
        assets_dict = vuln_assets_merged.to_dict(orient="records")
        insecure_dict = vuln_insecure_merged.to_dict(orient="records")
        vulns_dict = vuln_verified_merged.to_dict(orient="records")
        final_dict = {
            "assets": assets_dict,
            "insecure": insecure_dict,
            "verified_vulns": vulns_dict,
        }
        with open(vuln_json, "w") as outfile:
            json.dump(final_dict, outfile, default=str)


        # Create total Dark Web JSON
        mi_json = f"{PATH}/_combined_raw_data/total_mention_incidents.json"
        mentions_dict = dark_mentions_merged.to_dict(orient="records")
        alerts_dict = dark_alerts_merged.to_dict(orient="records")
        cve_dict = dark_cves_merged.to_dict(orient="records")
        final_dict = {
            "dark_web_mentions": mentions_dict,
            "dark_web_alerts": alerts_dict,
            "top_cves": cve_dict,
        }
        with open(mi_json, "w") as outfile:
            json.dump(final_dict, outfile, default=str)


        # Create total ASM Summary
        asmWriter = pd.ExcelWriter(
            f"{PATH}/_combined_raw_data/total_asm_summary.xlsx",
            engine="xlsxwriter",
        )

        cidr_df = asm_cidr_merged[["network"]]
        cidr_dict = cidr_df["network"].to_list()

        
        ips_dict = asm_extra_ips_merged["ip"].to_list()

        ports_protocols_dict = asm_ports_protocols_merged.to_dict(orient="records")

        rd_df = asm_root_domains_merged[["root_domain"]]
        rd_dict = rd_df["root_domain"].to_list()

        sd_df = asm_sub_domains_merged[["sub_domain"]]
        sd_dict = sd_df["sub_domain"].to_list()

        soft_dict = asm_software_merged["product"].to_list()

        for_ips_dict = asm_foreign_ips_merged.to_dict(orient="records")

        # Write to a JSON file
        final_dict = {
            "cidrs": cidr_dict,
            "extra_ips": ips_dict,
            "ports_protocols": ports_protocols_dict,
            "root_domains": rd_dict,
            "sub_domains": sd_dict,
            "software": soft_dict,
            "foreign_ips": for_ips_dict,
        }
        asm_json = f"{PATH}/_combined_raw_data/total_asm_summary.json"
        with open(asm_json, "w") as outfile:
            json.dump(final_dict, outfile, default=str)

    bucket = "cisa-crossfeed-staging-reports"
    upload_file_to_s3(f"{PATH}/_combined_raw_data/total_asm_summary.json", DATE, bucket)
    upload_file_to_s3(f"{PATH}/_combined_raw_data/total_mention_incidents.json", DATE, bucket)
    upload_file_to_s3(f"{PATH}/_combined_raw_data/total_vuln_alerts.json", DATE, bucket)
    upload_file_to_s3(f"{PATH}/_combined_raw_data/total_domain_alerts.json", DATE, bucket)
    upload_file_to_s3(f"{PATH}/_combined_raw_data/total_compromised_credentials.json", DATE, bucket)

if __name__ == "__main__":
    main()
