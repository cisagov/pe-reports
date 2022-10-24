"""Classes and associated functions that render the UI app pages."""

# Standard Python Libraries
import datetime
import logging
import os

# Third-Party Libraries
from flask import Blueprint, flash, redirect, render_template, url_for

# cisagov Libraries
from pe_reports.data.db_query import get_orgs_df
from pe_reports.helpers.bulletin.bulletin_generator import (
    generate_creds_bulletin,
    generate_cybersix_bulletin,
)
from pe_reports.report_gen.forms import (
    BulletinFormExternal,
    CredsFormExternal,
    InfoFormExternal,
)
from pe_reports.report_generator import generate_reports

LOGGER = logging.getLogger(__name__)

conn = None
cursor = None
thedateToday = datetime.date.today().strftime("%Y-%m-%d")


report_gen_blueprint = Blueprint(
    "report_gen", __name__, template_folder="templates/report_gen_UI"
)


def validate_filename(filename):
    """Verify that a filename is the correct format."""
    if filename == "":
        return False
    if any(
        char in filename
        for char in [
            "#",
            "%",
            "&",
            "{",
            "}",
            "<",
            ">",
            "!",
            "`",
            "$",
            "+",
            "*",
            "'",
            '"',
            "?",
            "=",
            "/",
            ":",
            " ",
            "@",
        ]
    ):
        return False
    else:
        return True


def validate_date(date_string):
    """Validate that a provided string matches the right format and is a report date."""
    try:
        date = datetime.datetime.strptime(date_string, "%Y-%m-%d")
    except ValueError:
        return False
    if date.day == 15:
        return True
    if date.month in [4, 6, 9, 11] and date.day != 30:
        return False
    elif date.month in [1, 3, 5, 7, 8, 12] and date.day != 31:
        return False
    elif date.month == 2 and date.day not in [28, 29]:
        return False
    return True


@report_gen_blueprint.route("/report_gen", methods=["GET", "POST"])
def report_gen():
    """Process form information, instantiate form and render page template."""
    report_date = False
    output_directory = False

    formExternal = InfoFormExternal()

    if formExternal.validate_on_submit() and formExternal.submit.data:
        LOGGER.info("Got to the submit validate")
        report_date = formExternal.report_date.data
        output_directory = formExternal.output_directory.data
        formExternal.report_date.data = ""
        formExternal.output_directory.data = ""

        if not validate_date(report_date):
            flash(
                "Incorrect data format, should be YYYY-MM-DD or not correct report date",
                "warning",
            )
            return redirect(url_for("report_gen.report_gen  "))

        if not os.path.exists(output_directory):
            os.mkdir(output_directory)

        # Generate reports
        generate_reports(report_date, output_directory)

    bulletinForm = BulletinFormExternal()

    if bulletinForm.validate_on_submit() and bulletinForm.submit1.data:
        LOGGER.info("Submitted Bulletin Form")

        id = bulletinForm.cybersix_id.data
        user_input = bulletinForm.user_input.data
        output_dir = bulletinForm.output_directory1.data
        file_name = bulletinForm.file_name.data
        bulletinForm.cybersix_id.data = ""
        bulletinForm.user_input.data = ""
        bulletinForm.output_directory1.data = ""
        bulletinForm.file_name.data = ""

        file_name = file_name.replace(" ", "")
        if not validate_filename(file_name):
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
            all_orgs = all_orgs[all_orgs["cyhy_db_name"].str.upper() == org_id]

        if len(all_orgs) < 1:
            flash(
                "The provided org_id does not exist in the database, try another.",
                "warning",
            )
            return redirect(url_for("report_gen.report_gen"))

        for org_index, org in all_orgs.iterrows():
            LOGGER.info("Running on %s", org['name'])
            generate_creds_bulletin(
                breach_name,
                org_id,
                "user_text",
                output_directory="/var/www/cred_bulletins",
                filename=org_id + "_" + breach_name.replace(" ", "") + "_Bulletin.pdf",
            )

    return render_template(
        "home_report_gen.html",
        formExternal=formExternal,
        bulletinForm=bulletinForm,
        credsForm=credsForm,
    )
