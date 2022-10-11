#!/usr/bin/env python
"""Classes and associated functions that render the UI app pages."""

# Standard Python Libraries
import logging
import os
import re
import traceback

# Third-Party Libraries
from bs4 import BeautifulSoup
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
import pandas as pd
import requests
import spacy
from werkzeug.utils import secure_filename

# cisagov Libraries
from pe_reports.data.db_query import (
    get_cidrs_and_ips,
    insert_roots,
    set_org_to_demo,
    set_org_to_report_on,
)
from pe_reports.helpers.enumerate_subs_from_root import (
    enumerate_and_save_subs,
    query_roots,
)
from pe_reports.helpers.fill_cidrs_from_cyhy_assets import fill_cidrs
from pe_reports.helpers.fill_ips_from_cidrs import fill_ips_from_cidrs
from pe_reports.helpers.link_subs_and_ips_from_ips import connect_subs_from_ips
from pe_reports.helpers.link_subs_and_ips_from_subs import connect_ips_from_subs
from pe_reports.helpers.shodan_dedupe import dedupe
from pe_source.data.sixgill.api import setNewCSGOrg

# If you are getting errors saying that a "en_core_web_lg" is loaded. Run the command " python -m spacy download en_core_web_trf" but might have to chagne the name fo the spacy model
nlp = spacy.load("en_core_web_lg")

LOGGER = logging.getLogger(__name__)


stakeholder_bulk_upload_blueprint = Blueprint(
    "stakeholder_bulk_upload",
    __name__,
    template_folder="templates/stakeholder_bulk_upload",
)


def allowed_file(filename):
    """Filter allowed file extensions to upload."""
    ALLOWED_EXTENSIONS = current_app.config["ALLOWED_EXTENSIONS"]
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def theExecs(URL):
    """Fetch executives from about page."""
    # Scrape the page with Beautiful Soup
    page = requests.get(URL).text
    soup = BeautifulSoup(page, "lxml")
    body = soup.body.text
    body = body.replace("\n", " ")
    body = body.replace("\t", " ")
    body = body.replace("\r", " ")
    body = body.replace("\xa0", " ")

    # Use NLP to locate the executive names and append to list
    exec_list = []
    doc = nlp(body)
    for ent in doc.ents:
        exec_list.append((ent.label_, ent.text))

    # Clean up exec list
    final_exec_list = []
    regex_pattern = re.compile(r"[@_'’!#\-$%^&*()<>?/\|}{~:]")
    for hy in exec_list:
        if ("PERSON" in hy) and (hy[1] not in final_exec_list) and (len(hy[1]) < 50):
            if not regex_pattern.search(hy[1]) and len(hy[1].split()) > 1:
                person = hy[1].split("  ")
                if len(person) <= 1:
                    final_exec_list.append(hy[1])
    return final_exec_list


def add_stakeholders(orgs_df):
    """Add each stakeholder to P&E infrastructure."""
    count = 0
    for org_index, org_row in orgs_df.iterrows():
        try:
            logging.info(f"Beginning to add {org_row['org_code']}")

            premium = org_row["premium"]
            # Set new org to report on
            if org_row["demo"] is True:
                new_org_df = set_org_to_demo(org_row["org_code"], premium)
            else:
                new_org_df = set_org_to_report_on(org_row["org_code"], premium)

            # Insert root domains
            logging.info("Getting root domains:")
            insert_roots(new_org_df, org_row["root_domain"].split(","))
            logging.info(org_row["root_domain"].split(","))

            # Enumerate and save subdomains
            roots = query_roots(new_org_df["organizations_uid"].iloc[0])
            for root_index, root in roots.iterrows():
                enumerate_and_save_subs(root["root_domain_uid"], root["root_domain"])
            logging.info("Subdomains have been successfully added to the database.")

            # Fill the cidrs from cyhy assets
            logging.info("Filling all cidrs:")
            fill_cidrs(new_org_df)
            logging.info("Finished filling all cidrs.")

            # Connect to subs and IPs from subs table (only new orgs)
            connect_ips_from_subs(new_org_df)
            logging.info("Finished connecting subs/ips from subs.")

            # Connect subs and IPs from IPs table (only new orgs)
            connect_subs_from_ips(new_org_df)
            logging.info("Finished connecting subs/ips from IPs.")

            # Check if the org should be added to Cybersixgill
            if org_row["premium"] is True:
                # Get executives list by passing the about page URL
                logging.info("Getting executives:")
                allExecutives = list(theExecs(org_row["exec_url"]))
                logging.info(allExecutives)

                # Insert org and all assets into Cybersixgill
                allValidIP = get_cidrs_and_ips(new_org_df["organizations_uid"].iloc[0])
                aliases = org_row["aliases"].split(",")
                logging.info("Addind these assets to Cybersixgill:")
                logging.info(org_row["org_code"])
                logging.info(aliases)
                logging.info(org_row["root_domain"].split(","))
                logging.info(allValidIP)
                logging.info(allExecutives)

                setNewCSGOrg(
                    org_row["org_code"],
                    aliases,
                    org_row["root_domain"].split(","),
                    allValidIP,
                    allExecutives,
                )

            # Fill IPs table by enumerating CIDRs (all orgs)
            fill_ips_from_cidrs()

            # Run Shodan dedupe script
            logging.info("Running Shodan dedupe:")
            dedupe(new_org_df)

            logging.info(f"Completely done with {org_row['org_code']}")
            count += 1
        except Exception as e:
            logging.info(e)
            logging.error(f"{org_row['org_code']} failed.")
            logging.error(traceback.format_exc())
    logging.info(f"Finished {count} orgs.")
    return count


@stakeholder_bulk_upload_blueprint.route(
    "/stakeholder_bulk_upload", methods=["GET", "POST"]
)
def stakeholder_bulk_upload():
    """Stakeholder bulk upload."""
    # Directory where bulk stakeholder files to be uploaded
    UPLOAD_FOLDER = current_app.config["UPLOAD_FOLDER"]

    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        logging.info("There was a directory created for upload")
    except FileExistsError:
        logging.info("The upload folder already exists")

    if request.method == "POST":
        # check if the post request has the file part
        if "file" not in request.files:
            flash("No file part", "warning")
            return redirect(request.url)
        file = request.files["file"]
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == "":
            flash("No selected file", "warning")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filePath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filePath)
            flash("The file was saved", "success")

            # Parse CSV data into a pandas DataFrame
            df = pd.read_csv(filePath)
            logging.info(df)

            # Add each stakeholder to P&E infrastructure
            success_count = add_stakeholders(df)

            flash(f"{success_count} org(s) succeeded.", "success")

        else:
            flash("The file that was chosen cannot be uploaded", "warning")
            logging.info("The file that was chosen cannot be uploaded")

            return redirect(
                url_for(
                    "stakeholder_bulk_upload.stakeholder_bulk_upload", name=filename
                )
            )
        return redirect(url_for("stakeholder_bulk_upload.stakeholder_bulk_upload"))
    return render_template("home_stakeholder_bulk_upload.html")
