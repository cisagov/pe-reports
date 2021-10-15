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
from pe_db.query import connect, get_orgs
from report_metrics import generate_metrics
from xhtml2pdf import pisa


def embed_and_encrypt(
    output_directory,
    _id,
    datestring,
    file,
    cc_csv,
    da_csv,
    ma_csv,
    # iv_csv,
    mi_csv,
    password,
):
    """Embeds raw data into pdf and encrypts file."""
    doc = fitz.open(file)
    page = doc[-1]
    output = f"{output_directory}/{_id}/Posture_and_Exposure_Report-{datestring}.pdf"

    # Open csv data as binary
    cc = open(cc_csv, "rb").read()
    da = open(da_csv, "rb").read()
    ma = open(ma_csv, "rb").read()
    # iv = open(iv_csv, "rb").read()
    mi = open(mi_csv, "rb").read()

    # Insert link to csv data in last page of pdf
    p1 = fitz.Point(100, 280)
    p2 = fitz.Point(100, 305)
    p3 = fitz.Point(100, 330)
    # p4 = fitz.Point(100, 355)
    p5 = fitz.Point(100, 380)

    # Embedd and add push-pin graphic
    page.add_file_annot(
        p1, cc, "compromised_credentials.csv", desc="Open up csv", icon="PushPin"
    )
    page.add_file_annot(p2, da, "domain_alerts.csv", desc="Open up csv", icon="PushPin")
    page.add_file_annot(
        p3, ma, "malware_associations.csv", desc="Open up csv", icon="PushPin"
    )
    # page.add_file_annot(
    #     p4,
    #     iv,
    #     "inferred_vulnerability_associations.csv",
    #     desc="Open up csv",
    #     icon="PushPin",
    # )
    page.add_file_annot(
        p5, mi, "mention_incidents.csv", desc="Open up csv", icon="PushPin"
    )
    # Add encryption
    perm = int(
        fitz.PDF_PERM_ACCESSIBILITY
        | fitz.PDF_PERM_PRINT  # permit printing
        | fitz.PDF_PERM_COPY  # permit copying
        | fitz.PDF_PERM_ANNOTATE  # permit annotations
    )
    encrypt_meth = fitz.PDF_ENCRYPT_AES_256
    doc.save(
        output,
        encryption=encrypt_meth,  # set the encryption method
        user_pw=password,  # set the user password
        permissions=perm,  # set permissions
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
            top_cves,
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
            top_cves,
        )

        # Close pdf
        file.close()

        # Convert to HTML to PDF
        output_filename = f"{output_directory}/{org_code}-Posture_and_Exposure_Report-{datestring}.pdf"
        convert_html_to_pdf(source_html, output_filename)

        # Embed csvdata and encrypt PDF
        # cc_csv = f"{output_directory}/{_id}/compromised_credentials.csv"
        # creds_attach.to_csv(cc_csv)
        # da_csv = f"{output_directory}/{_id}/domain_alerts.csv"
        # domain_masq.to_csv(da_csv)
        # ma_csv = f"{output_directory}/{_id}/malware_alerts.csv"
        # output_df.to_csv(ma_csv)
        # iv_csv = f"{output_directory}/{_id}/inferred_vulnerability_associations.csv"
        # iv_attach.to_csv(iv_csv)
        # mi_csv = f"{output_directory}/{_id}/mention_incidents.csv"
        # dark_web_mentions.to_csv(mi_csv)

        # grab the pdf
        # pdf = f"{output_directory}/{org_code}-Posture_and_Exposure_Report-{datestring}.pdf"

        # (filesize, tooLarge) = embed_and_encrypt(
        #     output_directory,
        #     org_code,
        #     datestring,
        #     pdf,
        #     cc_csv,
        #     da_csv,
        #     ma_csv,
        #     # iv_csv,
        #     mi_csv,
        #     password,
        # )
        # Need to make sure Cyhy Mailer doesn't send files that are too large
        # if tooLarge:
        #     print(f"{_id} is too large. File size: {filesize} Limit: 20MB")

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
