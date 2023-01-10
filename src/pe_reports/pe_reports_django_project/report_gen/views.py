"""Classes and associated functions that render the UI app pages."""
import logging
import os
import datetime

# Third party packages
from django.shortcuts import render, redirect
from django.http import HttpResponseNotFound
from django.contrib import messages
from .forms import InfoFormExternal, BulletinFormExternal, CredsFormExternal
#
# # cisagov Libraries
from pe_reports.data.db_query import get_orgs_df
from pe_reports.helpers.bulletin.bulletin_generator import (
    generate_creds_bulletin,
    generate_cybersix_bulletin,
)
from .forms import (
    BulletinFormExternal,
    CredsFormExternal,
    InfoFormExternal,
)
from pe_reports.report_generator import generate_reports


# from .models import Usersapi, Organizations
# from .forms import GatherStakeholderForm
# import psycopg2
# import psycopg2.extras.   .
# import requests

# cisagov Libraries

LOGGER = logging.getLogger(__name__)

conn = None
cursor = None

# Create your views here.


def report_gen(request):
    try:
        return render(request=request,
                      template_name="report_gen/report_gen.html")
    except:
        return HttpResponseNotFound('Nothing found')



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
    else:
        return False


def report_gen(request):
    """Process form information, instantiate form and render page template."""
    report_date = False
    output_directory = False

    form_external = InfoFormExternal()

    if form_external.is_valid() and request.method == 'POST':
        report_date = form_external.cleaned_data["report_date"].data
        output_directory = form_external.output_directory.data


        if not validate_date(report_date):
            messages.error(request,
                           "Incorrect date format, should be YYYY-MM-DD"
            )
            return redirect("/report_gen/")

        if not os.path.exists(output_directory):
            os.mkdir(output_directory)

        # Generate reports
        generate_reports(report_date, output_directory)

    bulletin_form = BulletinFormExternal(request.POST)

    if bulletin_form.is_valid() and bulletin_form:
        LOGGER.info("Submitted Bulletin Form")

        id = bulletin_form.cleaned_data["id"]
        user_input = bulletin_form.cleaned_data["user_input"]
        output_dir = bulletin_form.cleaned_data["output_directory1"]
        file_name = bulletin_form.cleaned_data["file_name"]


        file_name = file_name.replace(" ", "")
        if not validate_filename(file_name):
            messages.warning(request,
                "Invalid filename entered, please enter a different filename")
            return redirect("/report_gen/")

        if not os.path.exists(output_dir):
            messages.warning(
                "Invalid output directory provided, please enter an existing directory"
            )
            return redirect("/report_gen/")

        generate_cybersix_bulletin(id, user_input, output_dir, file_name)

    creds_form = CredsFormExternal(request.POST)
    if creds_form.is_valid():
        breach_name = creds_form.cleaned_data['breach_name']
        org_id = creds_form.cleaned_data['org_id']
        all_orgs = get_orgs_df()
        # Pandas does not support "cond is True" syntax for dataframe filters,
        # so we must disable flake8 E712 here
        all_orgs = all_orgs[all_orgs["report_on"] == True]  # noqa: E712

        if org_id != "":
            org_id = org_id.upper()
            all_orgs = all_orgs[all_orgs["cyhy_db_name"].str.upper() == org_id]

        if len(all_orgs) < 1:
            messages.warning(request,
                "The provided org_id does not exist in the database, try another."
            )
            return redirect("/report_gen/")

        for org_index, org in all_orgs.iterrows():
            LOGGER.info("Running on %s", org["name"])
            generate_creds_bulletin(
                breach_name,
                org_id,
                "user_text",
                output_directory="/var/www/cred_bulletins",
                filename=org_id + "_" + breach_name.replace(" ", "") + "_Bulletin.pdf",
            )

    return render(request,
        "report_gen/report_gen.html",
                  {'form_external': form_external,
                   'bulletin_form': bulletin_form,
                   'creds_form': creds_form
                   }
    )