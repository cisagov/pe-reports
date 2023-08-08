"""API tasks."""
# Standard Python Libraries
import ast
import json
from typing import List

# Third-Party Libraries
from celery import shared_task
from django.core import serializers
from home.models import MatVwOrgsAllIps, VwPshttDomainsToRun


@shared_task(bind=True)
def get_vs_info(self, cyhy_db_names: List[str]):
    """Get the Vulnerability Scanning information from the database."""
    vs_data_orm = list(MatVwOrgsAllIps.objects.filter(cyhy_db_name__in=cyhy_db_names))

    vs_data = serializers.serialize("json", vs_data_orm)

    vs_data = json.loads(vs_data)

    # Convert the string representation of a list into an actual list
    for item in vs_data:
        item["fields"]["ip_addresses"] = ast.literal_eval(
            item["fields"]["ip_addresses"]
        )

    return [item["fields"] for item in vs_data]


@shared_task
def get_ve_info(ip_address: List[str]):
    """Get the VE information from the database."""
    ve_data = MatVwOrgsAllIps.objects.filter(ip_addresses__contains=ip_address)

    print(ve_data)  # temporary print for debugging

    # To get cyhy_db_name values:
    cyhy_db_name_values = ve_data.values_list("cyhy_db_name", flat=True)

    # Return the result as a list of dictionaries for JSON serialization
    result = [{"cyhy_db_name": value} for value in cyhy_db_name_values]

    return result


@shared_task(bind=True)
def get_vw_pshtt_domains_to_run_info(self):
    """Get subdomains to run through the PSHTT scan."""
    # Make database query, then convert to list of dictionaries
    endpoint_data = list(VwPshttDomainsToRun.objects.all().values())

    # Convert UUID data to string (UUIDs cause issues with formatting)
    for row in endpoint_data:
        row["sub_domain_uid"] = str(row["sub_domain_uid"])
        row["organizations_uid"] = str(row["organizations_uid"])
    # Return results
    return endpoint_data
