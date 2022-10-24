"""
Bulletin/bulletin_generator: A tool for creating Posture & Exposure Bulletins.

Usage:
  bulletin_generator INTEL_ITEM_ID

Options:
  -h --help                         Show this message.
  INTEL_ITEM_ID                     Cyber Sixgill intel item id
"""

# Standard Python Libraries
import datetime
import logging
import os

# Third-Party Libraries
from docopt import docopt
import jinja2
import pandas as pd
import pdfkit

# cisagov Libraries
from pe_reports.data.db_query import connect
from pe_source.data.pe_db.config import cybersix_token
from pe_source.data.sixgill.api import intel_post

LOGGER = logging.getLogger(__name__)


def get_post(id):
    """Retrieve a cybersix post based on the intel item id."""
    query = f"_id:{id}"
    token = cybersix_token()
    resp = intel_post(token, query, frm=0, scroll=False, result_size=1)
    return resp


def date_format(value, format="%m/%d/%Y"):
    """Format a date field."""
    val = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    return val.strftime(format)


def html_builder(text):
    """Build out an html string for command line usage."""
    input_type = input(
        "Which of the following would you like to insert:\n [P]aragraph\n [B]ulleted List \n [N]umbered List\n Please provide a selection:"
    )
    if input_type == "P":
        LOGGER.info("Paragraph Selected")
        paragraph = input("Please enter paragraph text:")
        paragraph = f"<p> {paragraph} </p>"
        text = text + f"\n {paragraph}"

    elif input_type == "B":
        LOGGER.info("Bulleted List Selected. Enter [D] when done.")
        bullets = "<ul>\n"
        while True:
            item = input("Enter line item: ")
            if item == "D":
                bullets = bullets + "</ul>"
                break
            bullets = bullets + f"<li>{item}</li>\n"
        text = text + f"\n {bullets}"

    elif input_type == "N":
        LOGGER.info("Numbered List Selected")
        bullets = "<ol>\n"
        while True:
            item = input("Enter line item: ")
            if item == "D":
                bullets = bullets + "</ol>"
                break
            bullets = bullets + f"<li>{item}</li>\n"
        text = text + f"\n {bullets}"
    else:
        LOGGER.info("Invalid Selection")

    cont = input("Would you like to add more content (Y/N): ")
    if cont == "Y":
        text = html_builder(text)

    return text


bulletin_path = os.path.dirname(os.path.realpath(__file__))


def generate_cybersix_bulletin(
    id,
    user_text="",
    output_directory="/var/www/cybersix_bulletins",
    filename="_Bulletin.pdf",
):
    """Generate a bulletin based on a provided cybersix id."""
    if not filename.endswith(".pdf"):
        filename = filename + ".pdf"

    template_loader = jinja2.FileSystemLoader(searchpath=bulletin_path)
    template_env = jinja2.Environment(loader=template_loader, autoescape=True)
    template_env.filters["date_format"] = date_format
    TEMPLATE_FILE = "bulletin_template.html"
    template = template_env.get_template(TEMPLATE_FILE)
    resp = get_post(id)

    for post in resp["intel_items"]:

        outputText = template.render(
            post,
            user_provided_content=user_text,
            Stakeholder_Name="Posture and Exposure",
        )
        html_file = open(bulletin_path + "/bulletin_template_filled.html", "w")
        html_file.write(outputText)
        html_file.close()

        options = {
            "page-size": "Letter",
            "margin-top": "1.3in",
            "margin-right": "0in",
            "margin-bottom": "1.1in",
            "margin-left": "0in",
            "dpi": 96,
            "encoding": "UTF-8",
            "custom-header": [("Accept-Encoding", "gzip")],
            "cookie": [
                ("cookie-empty-value", '""'),
                ("cookie-name1", "cookie-value1"),
                ("cookie-name2", "cookie-value2"),
            ],
            "no-outline": None,
            "header-html": bulletin_path + "/header.html",
            "header-spacing": -5,
            "footer-right": "[page] of [topage]       \t\t\t\t",
            "footer-left": "       \t\t\tPosture & Exposure",
            "footer-spacing": 8,
            "footer-html": bulletin_path + "/footer.html",
            "enable-local-file-access": True,
            "disable-smart-shrinking": True,
        }
        out_path = output_directory + "/" + filename

        pdfkit.from_file(
            [bulletin_path + "/bulletin_template_filled.html"],
            out_path,
            options=options,
            verbose=True,
        )


def generate_creds_bulletin(
    breach,
    org_name,
    user_text,
    output_directory="/var/www/cred_bulletins",
    filename="_Bulletin.pdf",
):
    """Generate a credential breach bulletin."""
    LOGGER.info("generating creds bulletin")
    template_loader = jinja2.FileSystemLoader(searchpath=bulletin_path)
    template_env = jinja2.Environment(loader=template_loader, autoescape=True)
    template_env.filters["date_format"] = date_format
    TEMPLATE_FILE = "creds_bulletin_template.html"
    template = template_env.get_template(TEMPLATE_FILE)

    conn = connect()
    cur = conn.cursor()
    cur.callproc("query_breach", [breach])

    breaches = cur.fetchall()
    column_names = [desc[0] for desc in cur.description]

    cur.callproc("query_emails", [breach, org_name])
    emails = cur.fetchall()
    cols = [desc[0] for desc in cur.description]
    cur.close()
    conn.close()
    emails_df = pd.DataFrame(emails, columns=cols)

    emails_df = emails_df.rename(
        columns={
            "email": "Email",
            "name": "Name",
            "login_id": "Login ID",
            "phone": "Phone",
            "password": "Password",
            "hash_type": "Hash Type",
        }
    )

    # Replace Blank values with DataFrame.replace() methods.
    emails_df = emails_df.replace(r"^\s*$", "-", regex=True)
    df_table = emails_df[
        ["Email", "Name", "Login ID", "Phone", "Password", "Hash Type"]
    ].to_html(index=False, classes="table table-striped")
    emails_list = emails_df["Email"].values.tolist()

    emails_list.sort()
    email_count = len(emails_list)
    n = 2
    hibp_rows = [
        emails_list[i * n : (i + 1) * n] for i in range((len(emails_list) + n - 1) // n)
    ]

    results = []
    for row in breaches:
        row_dict = {}
        for i, col in enumerate(column_names):
            row_dict[col] = row[i]
        results.append(row_dict)

        output_text = template.render(
            row_dict,
            user_provided_content=user_text,
            email_count=email_count,
            df_table=df_table,
            hibp_rows=hibp_rows,
        )
        html_file = open(bulletin_path + "/creds_bulletin_template_filled.html", "w")
        html_file.write(output_text)
        html_file.close()

        options = {
            "page-size": "Letter",
            "margin-top": "1.3in",
            "margin-right": "0in",
            "margin-bottom": "1.2in",
            "margin-left": "0in",
            "encoding": "UTF-8",
            "custom-header": [("Accept-Encoding", "gzip")],
            "cookie": [
                ("cookie-empty-value", '""'),
                ("cookie-name1", "cookie-value1"),
                ("cookie-name2", "cookie-value2"),
            ],
            "no-outline": None,
            "header-html": bulletin_path + "/header.html",
            "header-spacing": -5,
            "footer-right": "[page] of [topage]       \t\t\t\t",
            "footer-left": "       \t\t\tPosture & Exposure",
            "footer-spacing": 8,
            "footer-html": bulletin_path + "/footer.html",
            "enable-local-file-access": True,
            "disable-smart-shrinking": True,
        }
        out_path = output_directory + "/" + filename

        pdfkit.from_file(
            [bulletin_path + "/creds_bulletin_template_filled.html"],
            out_path,
            options=options,
            verbose=True,
        )


def main():
    """Generate a bulletin for a cybersixgill post."""
    args = docopt(__doc__)

    id = args["INTEL_ITEM_ID"]

    user_text = html_builder("")

    LOGGER.info("Running on %s", id)

    generate_cybersix_bulletin(
        id,
        user_text,
    )


if __name__ == "__main__":
    main()
