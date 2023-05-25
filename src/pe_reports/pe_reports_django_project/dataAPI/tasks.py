from typing import List
from celery import shared_task

from home.models import MatVwOrgsAllIps


@shared_task
def get_vs_info(cyhy_db_names: List[str]):
    vs_data = list(MatVwOrgsAllIps.objects.filter(cyhy_db_name__in=cyhy_db_names))
    return vs_data


@shared_task
def get_ve_info(ip_address: List[str]):
    vs_data = list(MatVwOrgsAllIps.objects.filter(
        ip_addresses__contains=[ip_address]))
    return vs_data
