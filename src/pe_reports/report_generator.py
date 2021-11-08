"""ciagov/pe-reports: A tool for creating Posture & Exposure reports.

Usage:
  pe-reports REPORT_DATE  DATA_DIRECTORY OUTPUT_DIRECTORY [--db-creds-file=FILENAME]

Options:
  -h --help                         Show this message.
  REPORT_DATE                       Date of the report, format YYYY-MM-DD
  DATA_DIRECTORY                    The directory where the excel data
                                    files are located. Organized by
                                    owner.
  OUTPUT_DIRECTORY                  The directory where the final PDF
                                    reports should be saved.
  -c --db-creds-file=FILENAME       A YAML file containing the Cyber
                                    Hygiene database credentials.
                                    [default: /secrets/database_creds.yml]
"""

# Standard Python Libraries
import os
import sys

# Third-Party Libraries
from _version import __version__
from docopt import docopt
import fitz
from pages import init
import pandas as pd
from pe_db.query import connect, get_orgs
from report_metrics import generate_metrics
from xhtml2pdf import pisa


def embed_and_encrypt(
    output_directory,
    org_code,
    datestring,
    file,
    cred_xlsx,
    da_xlsx,
    vuln_xlsx,
    mi_xlsx,
):
    """Embeds raw data into pdf and encrypts file."""
    doc = fitz.open(file)
    page = doc[3]
    output = (
        f"{output_directory}/{org_code}/Posture_and_Exposure_Report-{datestring}.pdf"
    )

    # Open csv data as binary
    cc = open(cred_xlsx, "rb").read()
    da = open(da_xlsx, "rb").read()
    ma = open(vuln_xlsx, "rb").read()
    mi = open(mi_xlsx, "rb").read()

    # Insert link to csv data in last page of pdf
    p1 = fitz.Point(110, 695)
    p2 = fitz.Point(240, 695)
    p3 = fitz.Point(375, 695)
    p5 = fitz.Point(500, 695)

    # Embedd and add push-pin graphic
    page.add_file_annot(
        p1, cc, "compromised_credentials.xlsx", desc="Open up csv", icon="PushPin"
    )
    page.add_file_annot(
        p2, da, "domain_alerts.xlsx", desc="Open up csv", icon="PushPin"
    )
    page.add_file_annot(p3, ma, "vuln_alerts.xlsx", desc="Open up xlsx", icon="PushPin")
    page.add_file_annot(
        p5, mi, "mention_incidents.xlsx", desc="Open up csv", icon="PushPin"
    )
    # Add encryption
    # perm = int(
    #     fitz.PDF_PERM_ACCESSIBILITY
    #     | fitz.PDF_PERM_PRINT  # permit printing
    #     | fitz.PDF_PERM_COPY  # permit copying
    #     | fitz.PDF_PERM_ANNOTATE  # permit annotations
    # )
    # encrypt_meth = fitz.PDF_ENCRYPT_AES_256
    # doc.save(
    #     output,
    #     encryption=encrypt_meth,  # set the encryption method
    #     user_pw=password,  # set the user password
    #     permissions=perm,  # set permissions
    #     garbage=4,
    #     deflate=True,
    # )
    doc.save(
        output,
        garbage=4,
        deflate=True,
    )
    tooLarge = False
    # Throw error if file size is greater than 20MB
    filesize = os.path.getsize(output)
    if filesize >= 20000000:
        tooLarge = True

    return filesize, tooLarge


def convert_html_to_pdf(source_html, output_filename):
    """Convert html to pdf."""
    # open output file for writing (truncated binary)
    result_file = open(output_filename, "w+b")

    # convert HTML to PDF
    pisa_status = pisa.CreatePDF(
        source_html, dest=result_file  # the HTML to convert
    )  # file handle to recieve result

    # close output file
    result_file.close()  # close output file

    # return False on success and True on errors
    return pisa_status.err


def generate_reports(datestring, data_directory, output_directory):
    """Process steps for generating report data."""
    # Get PE orgs from PE db
    conn = connect()
    pe_orgs = get_orgs(conn)
    print(pe_orgs)

    generated_reports = 0

    # Iterate over organizations
    for org in pe_orgs:

        # Assign organization values
        org_uid = org[0]
        org_name = org[1]
        org_code = org[2]
        folder_name = org_code

        print(f"Running on {org_code}...")

        # Create folders in output directory
        if not os.path.exists(f"{output_directory}/ppt"):
            os.mkdir(f"{output_directory}/ppt")

        if not os.path.exists(f"{output_directory}/{org_code}"):
            os.mkdir(f"{output_directory}/{org_code}")

        # Generate metrics
        (
            creds,
            breach,
            pw_creds,
            ce_date_df,
            breach_det_df,
            creds_attach,
            creds_attach2,
            breach_appendix,
            domain_masq,
            domain_sum,
            domain_count,
            utlds,
            insecure_df,
            vulns_df,
            output_df,
            pro_count,
            unverif_df,
            risky_assets,
            verif_vulns,
            verif_vulns_summary,
            riskyPortsCount,
            verifVulns,
            unverifVulnAssets,
            dark_web_mentions,
            alerts,
            darkWeb,
            dark_web_date,
            dark_web_sites,
            alerts_threats,
            dark_web_bad_actors,
            dark_web_tags,
            dark_web_content,
            alerts_exec,
            dark_web_most_act,
            top_cves,
            top_cve_table,
        ) = generate_metrics(datestring, org_uid)

        # Load source html
        file = open("template2.html")
        source_html = file.read().replace("\n", " ")

        # Insert Charts and Metrics into pdf
        source_html = init(
            source_html,
            datestring,
            org_name,
            folder_name,
            creds,
            breach,
            pw_creds,
            ce_date_df,
            breach_det_df,
            creds_attach,
            creds_attach2,
            breach_appendix,
            domain_sum,
            domain_count,
            utlds,
            pro_count,
            unverif_df,
            risky_assets,
            verif_vulns,
            verif_vulns_summary,
            riskyPortsCount,
            verifVulns,
            unverifVulnAssets,
            darkWeb,
            dark_web_date,
            dark_web_sites,
            alerts_threats,
            dark_web_bad_actors,
            dark_web_tags,
            dark_web_content,
            alerts_exec,
            dark_web_most_act,
            top_cve_table,
        )

        # Close pdf
        file.close()

        # Convert to HTML to PDF
        output_filename = f"{output_directory}/{org_code}-Posture_and_Exposure_Report-{datestring}.pdf"
        convert_html_to_pdf(source_html, output_filename)

        # Create Crendential Exposure excel file
        cred_xlsx = f"{output_directory}/{org_code}/compromised_credentials.xlsx"
        credWriter = pd.ExcelWriter(cred_xlsx, engine="xlsxwriter")
        creds_attach.to_excel(credWriter, sheet_name="HIBP_Credentials", index=False)
        creds_attach2.to_excel(credWriter, sheet_name="Cyber6_Credentials", index=False)
        credWriter.save()

        # Create Domain Masquerading excel file
        da_xlsx = f"{output_directory}/{org_code}/domain_alerts.xlsx"
        domWriter = pd.ExcelWriter(da_xlsx, engine="xlsxwriter")
        domain_masq.to_excel(domWriter, sheet_name="Suspected Domains", index=False)
        domWriter.save()

        # Create Suspected vulnerability excel file
        vuln_xlsx = f"{output_directory}/{org_code}/vuln_alerts.xlsx"
        vulnWriter = pd.ExcelWriter(vuln_xlsx, engine="xlsxwriter")
        output_df.to_excel(vulnWriter, sheet_name="Assets", index=False)
        insecure_df.to_excel(vulnWriter, sheet_name="Insecure", index=False)
        vulns_df.to_excel(vulnWriter, sheet_name="Verified Vulns", index=False)
        vulnWriter.save()

        # Create dark web excel file
        mi_xlsx = f"{output_directory}/{org_code}/mention_incidents.xlsx"
        miWriter = pd.ExcelWriter(mi_xlsx, engine="xlsxwriter")
        dark_web_mentions.to_excel(
            miWriter, sheet_name="Dark Web Mentions", index=False
        )
        alerts.to_excel(miWriter, sheet_name="Dark Web Alerts", index=False)
        top_cves.to_excel(miWriter, sheet_name="Top CVEs", index=False)
        miWriter.save()

        # grab the pdf
        pdf = f"{output_directory}/{org_code}-Posture_and_Exposure_Report-{datestring}.pdf"

        (filesize, tooLarge) = embed_and_encrypt(
            output_directory,
            org_code,
            datestring,
            pdf,
            cred_xlsx,
            da_xlsx,
            vuln_xlsx,
            mi_xlsx,
        )
        # Need to make sure Cyhy Mailer doesn't send files that are too large
        if tooLarge:
            print(f"{org_code} is too large. File size: {filesize} Limit: 20MB")

        generated_reports = generated_reports + 1

    print(f"{generated_reports} reports generated")


def main():
    """Generate PDF reports."""
    # Parse command line arguments
    args = docopt(__doc__, version=__version__)

    # Create output directory
    if not os.path.exists(args["OUTPUT_DIRECTORY"]):
        os.mkdir(args["OUTPUT_DIRECTORY"])

    # Generate reports
    generate_reports(
        args["REPORT_DATE"], args["DATA_DIRECTORY"], args["OUTPUT_DIRECTORY"]
    )


if __name__ == "__main__":
    sys.exit(main())
