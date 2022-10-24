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
    # If the day after a date is the first day of a month, then
    # that date is the last day of a month
    if date.day == 15 or (date + datetime.timedelta(days=1)).day == 1:
        return True


@report_gen_blueprint.route("/report_gen", methods=["GET", "POST"])
def report_gen():
    """Process form information, instantiate form and render page template."""
    report_date = False
    output_directory = False

    form_external = InfoFormExternal()

    if form_external.validate_on_submit() and form_external.submit.data:
        report_date = form_external.report_date.data
        output_directory = form_external.output_directory.data
        form_external.report_date.data = ""
        form_external.output_directory.data = ""

        if not validate_date(report_date):
            flash(
                "Incorrect data format, should be YYYY-MM-DD or not correct report date",
                "warning",
            )
            return redirect(url_for("report_gen.report_gen"))

        if not os.path.exists(output_directory):
            os.mkdir(output_directory)

        # Generate reports
        generate_reports(report_date, output_directory)

    bulletin_form = BulletinFormExternal()

    if bulletin_form.validate_on_submit() and bulletin_form.submit1.data:
        LOGGER.info("Submitted Bulletin Form")

        id = bulletin_form.cybersix_id.data
        user_input = bulletin_form.user_input.data
        output_dir = bulletin_form.output_directory1.data
        file_name = bulletin_form.file_name.data
        bulletin_form.cybersix_id.data = ""
        bulletin_form.user_input.data = ""
        bulletin_form.output_directory1.data = ""
        bulletin_form.file_name.data = ""

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

    creds_form = CredsFormExternal()
    if creds_form.validate_on_submit() and creds_form.submit2.data:
        breach_name = creds_form.breach_name.data
        org_id = creds_form.org_id.data
        creds_form.breach_name.data = ""
        creds_form.org_id.data = ""
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
            LOGGER.info("Running on %s", org["name"])
            generate_creds_bulletin(
                breach_name,
                org_id,
                "user_text",
                output_directory="/var/www/cred_bulletins",
                filename=org_id + "_" + breach_name.replace(" ", "") + "_Bulletin.pdf",
            )

    return render_template(
        "home_report_gen.html",
        form_external=form_external,
        bulletin_form=bulletin_form,
        creds_form=creds_form,
    )
