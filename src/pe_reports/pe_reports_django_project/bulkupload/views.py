# Third party imports
from django.http import HttpResponseRedirect
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from django.urls import reverse_lazy
from django.core.validators import FileExtensionValidator, ValidationError
from django.contrib import messages
from bs4 import BeautifulSoup
import spacy

# Standard Python
import logging
import csv
import traceback
from io import TextIOWrapper
import re
import requests

# CISA Imports
from .forms import CSVUploadForm
from pe_reports.data.db_query import (
    get_cidrs_and_ips,
    insert_roots,
    set_org_to_demo,
    set_org_to_report_on,
)

from pe_asm.helpers.enumerate_subs_from_root import (
    enumerate_and_save_subs,
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

            logging.info("Completely done with %s", org_row["org_code"])
            count += 1
        except Exception as e:
            logging.info(e)
            logging.error("%s failed.", org_row["org_code"])
            logging.error(traceback.format_exc())
    logging.info("Finished %s orgs.", count)
    return count


class CustomCSVView(TemplateView):
    """CBV route to bulk upload page"""

    template_name = "bulk_upload/upload.html"
    form_class = CSVUploadForm


class CustomCSVForm(FormView):
    """CBV form bulk upload csv file with file extension and header validation"""

    form_class = CSVUploadForm
    template_name = "bulk_upload/upload.html"

    success_url = reverse_lazy("bulkupload")

    def form_valid(self, form):
        """Validate form data"""

        csv_file = form.cleaned_data["file"]

        f = TextIOWrapper(csv_file.file)

        dict_reader = csv.DictReader(f)
        dict_reader = dict_reader.fieldnames
        dict_reader = set(dict_reader)

        required_columns = [
            "org",
            "org_code",
            "root_domain",
            "exec_url",
            "aliases",
            "premium",
            "demo",
        ]
        # Check needed columns exist
        req_col = ""

        # print(dict_reader)
        # print(required_columns)
        incorrect_col = []
        testtheList = [i for i in required_columns if i in dict_reader]
        # print(testtheList)

        if len(testtheList) == len(dict_reader):

            messages.success(self.request, "The file was uploaded successfully.")

            for row, item in enumerate(dict_reader, start=1):
                self.process_item(item)
            #
            return super().form_valid(form)
        else:
            for col in required_columns:
                if col in dict_reader:
                    pass
                else:
                    incorrect_col.append(col)

            messages.warning(
                self.request,
                "A required column is missing"
                " from the uploaded CSV: %s " % incorrect_col,
            )
            return super().form_invalid(form)

    def process_item(self, item):
        #     # TODO: Replace with the code for what you wish to do with the row of data in the CSV.
        LOGGER.info("The item is %s" % item)
