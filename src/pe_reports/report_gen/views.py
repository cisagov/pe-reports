"""Classes and associated functions that render the UI app pages."""

# Standard Python Libraries
import datetime
from datetime import date
import logging
import os

# Third-Party Libraries
from flask import Blueprint, flash, redirect, render_template, url_for
import spacy

# cisagov Libraries
from adhoc.Bulletin.bulletin_generator import (
    generate_creds_bulletin,
    generate_cybersix_bulletin,
)
from pe_reports.data.db_query import get_orgs_df
from pe_reports.report_gen.forms import (
    BulletinFormExternal,
    CredsFormExternal,
    InfoFormExternal,
)
from pe_reports.report_generator import generate_reports

# If you are getting errors saying that a "en_core_web_lg" is loaded. Run the command " python -m spacy download en_core_web_trf" but might have to chagne the name fo the spacy model
nlp = spacy.load("en_core_web_lg")

logging.basicConfig(
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=logging.INFO,
)

conn = None
cursor = None
thedateToday = date.today().strftime("%Y-%m-%d")


report_gen_blueprint = Blueprint(
    "report_gen", __name__, template_folder="templates/report_gen_UI"
)


@report_gen_blueprint.route("/report_gen", methods=["GET", "POST"])
def report_gen():
    """Process form information, instantiate form and render page template."""
    report_date = False
    output_directory = False

    formExternal = InfoFormExternal()

    if formExternal.validate_on_submit() and formExternal.submit.data:
        logging.info("Got to the submit validate")
        report_date = formExternal.report_date.data
        output_directory = formExternal.output_directory.data
        formExternal.report_date.data = ""
        formExternal.output_directory.data = ""

        try:
            datetime.datetime.strptime(report_date, "%Y-%m-%d")
        except ValueError:
            flash("Incorrect data format, should be YYYY-MM-DD", "warning")
            return redirect(url_for("report_gen.report_gen  "))

        if not os.path.exists(output_directory):
            os.mkdir(output_directory)

        # Generate reports
        generate_reports(report_date, output_directory)

    bulletinForm = BulletinFormExternal()

    if bulletinForm.validate_on_submit() and bulletinForm.submit1.data:
        logging.info("Submitted Bulletin Form")
        print("Submitted Bulletin Form")

        id = bulletinForm.cybersix_id.data
        user_input = bulletinForm.user_input.data
        output_dir = bulletinForm.output_directory1.data
        file_name = bulletinForm.file_name.data
        bulletinForm.cybersix_id.data = ""
        bulletinForm.user_input.data = ""
        bulletinForm.output_directory1.data = ""
        bulletinForm.file_name.data = ""

        file_name = file_name.replace(" ", "")
        if any(ele in file_name for ele in ["#","%","&","{","}","<",">","!","`","$","+","*","'",'"',"?","=","/",":"," ","@"]):
            flash(
                "Invalid filename entered, please enter a different filename",
                "warning",
            )
            return redirect(url_for("report_gen.report_gen"))

        if not os.path.exists(output_dir):
            flash(
                "Invalid output directory provided, please enter an existing directory",
                "warning",
            )
            return redirect(url_for("report_gen.report_gen"))

        generate_cybersix_bulletin(id, user_input, output_dir, file_name)

    credsForm = CredsFormExternal()
    if credsForm.validate_on_submit() and credsForm.submit2.data:
        breach_name = credsForm.breach_name.data
        org_id = credsForm.org_id.data
        credsForm.breach_name.data = ""
        credsForm.org_id.data = ""
        all_orgs = get_orgs_df()
        all_orgs = all_orgs[all_orgs["report_on"] == True]

        if org_id != "":
            org_id = org_id.upper()
            print(all_orgs)
            all_orgs = all_orgs[all_orgs["cyhy_db_name"].str.upper() == org_id]

        if len(all_orgs) < 1:
            flash(
                "The provided org_id does not exist in the database, try another.",
                "warning",
            )
            return redirect(url_for("report_gen.report_gen"))

        for org_index, org in all_orgs.iterrows():
            print(f"Running on {org['name']}")
            generate_creds_bulletin(
                breach_name,
                org_id,
                "user_text",
                output_directory="/var/www/Bulletins",
                filename=org_id + "_" + breach_name.replace(" ", "") + "_Bulletin.pdf",
            )

        print(breach_name)

    return render_template(
        "home_report_gen.html",
        formExternal=formExternal,
        bulletinForm=bulletinForm,
        credsForm=credsForm,
    )
