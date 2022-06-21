"""Classes and associated functions that render the UI app pages."""

# Standard Python Libraries
from datetime import date
import logging
import os
import time

# Third-Party Libraries
from flask import Blueprint, redirect, render_template, url_for

# cisagov Libraries
from adhoc.fill_cidrs_from_cyhy_assets import fill_cidrs
from adhoc.fill_ips_from_cidrs import fill_ips_from_cidrs
from adhoc.link_subs_and_ips_from_ips import connect_subs_from_ips
from adhoc.link_subs_and_ips_from_subs import connect_ips_from_subs
from adhoc.shodan_dedupe import dedupe
from pe_reports.data.db_query import get_new_orgs
from pe_reports.stakeholder_lite.forms import InfoFormExternal

logging.basicConfig(
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=logging.INFO,
)

# CSG credentials
API_Client_ID = os.getenv("CSGUSER")
API_Client_secret = os.environ.get("CSGSECRET")
API_WHOIS = os.environ.get("WHOIS_VAR")

conn = None
cursor = None
thedateToday = date.today().strftime("%Y-%m-%d")


def getAgenciesByCount(orgCount):
    """Get all agency names from P&E database."""
    all_orgs_df = get_new_orgs()
    print(all_orgs_df)
    new_orgs_df = all_orgs_df.sample(n=orgCount)
    # TODO: Update new orgs to report_on
    # TODO: Maybe add assets_collected column so we don't need to collect cidrs everytime
    print(new_orgs_df)
    return new_orgs_df


stakeholder_lite_blueprint = Blueprint(
    "stakeholder_lite", __name__, template_folder="templates/stakeholder_lite_UI"
)


@stakeholder_lite_blueprint.route("/stakeholder_lite", methods=["GET", "POST"])
def stakeholder_lite():
    """Process form information, instantiate form and render page template."""
    orgCount = False

    formExternal = InfoFormExternal()

    if formExternal.validate_on_submit():
        start_time = time.time()

        logging.info("Got to the submit validate")
        orgCount = int(formExternal.orgCount.data.upper())
        orgs = getAgenciesByCount(orgCount)

        # Fill cidrs table (only new orgs)
        fill_cidrs(orgs)
        print("Filled all cidrs")

        # Fill IPs table by enumerating CIDRs (all orgs)
        fill_ips_from_cidrs()

        # Connect to subs from IPs table (only new orgs)
        connect_subs_from_ips(orgs)
        print("Filled all IPs")

        # Connect to IPs from subs table (only new orgs)
        connect_ips_from_subs(orgs)

        # Run pe_dedupe
        print("Running dedupe:")
        dedupe(orgs)

        print("--- %s seconds ---" % (time.time() - start_time))

        return redirect(url_for("stakeholder_lite.stakeholder_lite"))
    return render_template(
        "home_stakeholder_lite.html",
        formExternal=formExternal,
        orgCount=orgCount,
    )
