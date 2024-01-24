# Standard Python Libraries
import logging

# Third-Party Libraries
from django.urls import reverse_lazy
from django.views.generic import TemplateView
from django.views.generic.edit import FormView

# cisagov Libraries
from pe_reports.data.db_query import get_new_orgs
from pe_reports.helpers.fill_cidrs_from_cyhy_assets import fill_cidrs
from pe_reports.helpers.fill_ips_from_cidrs import fill_ips_from_cidrs
from pe_reports.helpers.link_subs_and_ips_from_ips import connect_subs_from_ips
from pe_reports.helpers.link_subs_and_ips_from_subs import connect_ips_from_subs
from pe_reports.helpers.shodan_dedupe import dedupe

from .forms import GatherStakeholderLiteForm

# Create your views here.

# Setup logging
LOGGER = logging.getLogger(__name__)


def getAgenciesByCount(orgCount):
    """Get all agency names from P&E database."""
    all_orgs_df = get_new_orgs()
    logging.info(all_orgs_df)
    new_orgs_df = all_orgs_df.sample(n=orgCount)
    # TODO: Update new orgs to report_on
    # TODO: Maybe add assets_collected column so we don't need to collect cidrs everytime
    logging.info(new_orgs_df)
    return new_orgs_df


class StakeholderLiteView(TemplateView):
    """Stakeholder lite template"""

    template_name = "stakeholder_lite/stakeholder_lite.html"
    LOGGER.info("Got to Stakeholder")


class StakeholderLiteForm(FormView):
    """Stahkeholder lite from"""

    form_class = GatherStakeholderLiteForm
    template_name = "stakeholder_lite/stakeholder_lite.html"

    success_url = reverse_lazy("stakeholder_lite")

    def form_valid(self, form):

        theorgCount = form.cleaned_data["orgCount"].upper()
        LOGGER.info(f"The org count was {theorgCount}")

        orgs = getAgenciesByCount(theorgCount)

        # Fill cidrs table (only new orgs)
        fill_cidrs(orgs)
        LOGGER.info("Filled all cidrs")

        # Fill IPs table by enumerating CIDRs (all orgs)
        fill_ips_from_cidrs()

        # Connect to subs from IPs table (only new orgs)
        connect_subs_from_ips(orgs)
        LOGGER.info("Filled all IPs")

        # Connect to IPs from subs table (only new orgs)
        connect_ips_from_subs(orgs)

        # Run pe_dedupe
        LOGGER.info("Running dedupe:")
        dedupe(orgs)
        return super().form_valid(form)
