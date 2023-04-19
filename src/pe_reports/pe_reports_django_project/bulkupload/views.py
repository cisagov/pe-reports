# Third party imports
from django.http import HttpResponseRedirect
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from django.urls import reverse_lazy
from django.core.validators import FileExtensionValidator, ValidationError
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import DataError
from bs4 import BeautifulSoup
import spacy

# Standard Python
import logging
import csv
import traceback
from io import TextIOWrapper
import re
import requests
from datetime import datetime


# CISA Imports
from .forms import CSVUploadForm
from home.models import WasTrackerCustomerdata
from pe_reports.data.db_query import (
    get_cidrs_and_ips,
    insert_roots,
    set_org_to_demo,
    set_org_to_report_on,
)

from pe_asm.helpers.enumerate_subs_from_root import (
    enumerate_roots,
    insert_sub_domains,
)
from pe_asm.data.cyhy_db_query import (
    pe_db_connect,
    query_roots,
)

from pe_asm.helpers.fill_cidrs_from_cyhy_assets import fill_cidrs
from pe_asm.helpers.fill_ips_from_cidrs import fill_ips_from_cidrs
from pe_asm.helpers.link_subs_and_ips_from_ips import connect_subs_from_ips
from pe_asm.helpers.link_subs_and_ips_from_subs import connect_ips_from_subs
from pe_asm.helpers.shodan_dedupe import dedupe
from pe_source.data.sixgill.api import setNewCSGOrg

LOGGER = logging.getLogger(__name__)

# nlp = spacy.load("en_core_web_lg")


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
        conn = pe_db_connect()
        try:
            logging.info("Beginning to add %s", org_row["org_code"])

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
                subs = enumerate_roots(root["root_domain_uid"], root["root_domain"])
                # Create DataFrame
                subs_df = pd.DataFrame(subs)

                # Insert into P&E database
                insert_sub_domains(conn, subs_df)
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

            logging.info("Completely done with %s", org_row["org_code"])
            count += 1
        except Exception as e:
            logging.info(e)
            logging.error("%s failed.", org_row["org_code"])
            logging.error(traceback.format_exc())
        conn.close()
    logging.info("Finished %s orgs.", count)
    return count


class CustomCSVView(TemplateView):
    """CBV route to bulk upload page"""

    template_name = "bulk_upload/upload.html"
    form_class = CSVUploadForm


class CustomCSVForm(LoginRequiredMixin, FormView):
    """CBV form bulk upload csv file with file extension and header validation"""

    form_class = CSVUploadForm
    template_name = "bulk_upload/upload.html"

    success_url = reverse_lazy("bulkupload")

    def form_valid(self, form):
        """Validate form data"""

        csv_file = form.cleaned_data["file"]

        f = TextIOWrapper(csv_file.file)

        # LOGGER.info(allInfo)
        dict_reader = csv.DictReader(f)
        dict_reader1 = dict_reader.fieldnames
        dict_reader2 = set(dict_reader1)

        required_columns = [
            "tag",
            "customer_name",
            "testing_sector",
            "ci_type",
            "jira_ticket",
            "ticket",
            "next_scheduled",
            "last_scanned",
            "frequency",
            "comments_notes",
            "was_report_poc",
            "was_report_email",
            "onboarding_date",
            "no_of_web_apps",
            "no_web_apps_last_updated",
            "elections",
            "fceb",
            "special_report",
            "report_password",
            "child_tags",
        ]

        # Check needed columns exist
        req_col = ""

        incorrect_col = []
        testtheList = [i for i in required_columns if i in dict_reader2]
        # LOGGER.info(testtheList)

        if len(testtheList) == len(dict_reader2):

            messages.success(self.request, "The file was uploaded successfully.")

            self.process_item(dict_reader)

            return super().form_valid(form)
        else:
            for col in required_columns:
                if col in dict_reader2:
                    pass
                else:
                    incorrect_col.append(col)

            messages.warning(
                self.request,
                "A required column is missing"
                " from the uploaded CSV: %s " % incorrect_col,
            )
            return super().form_invalid(form)

    def process_item(self, dict):
        """Delete all data and replace with the data from the file that is getting uploaded."""

        if WasTrackerCustomerdata.objects.exists():
            LOGGER.info("There was data that was deleted from the WAS table.")
            WasTrackerCustomerdata.objects.all().delete()

        for row in dict:
            wasCustomer = WasTrackerCustomerdata(
                tag=row["tag"],
                customer_name=row["customer_name"],
                testing_sector=row["testing_sector"],
                ci_type=row["ci_type"],
                jira_ticket=row["jira_ticket"],
                ticket=row["ticket"],
                next_scheduled=row["next_scheduled"],
                last_scanned=row["last_scanned"],
                frequency=row["frequency"],
                comments_notes=row["comments_notes"],
                was_report_poc=row["was_report_poc"],
                was_report_email=row["was_report_email"],
                onboarding_date=row["onboarding_date"],
                no_of_web_apps=row["no_of_web_apps"],
                no_web_apps_last_updated=row["no_web_apps_last_updated"],
                elections=row["elections"],
                fceb=row["fceb"],
                special_report=row["special_report"],
                report_password=row["report_password"],
                child_tags=row["child_tags"],
            )
            try:
                wasCustomer.save()

            except DataError as e:
                LOGGER.error("There is an issue with the data type %s", e)
