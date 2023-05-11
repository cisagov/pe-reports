from typing import List
from celery import shared_task
from home.models import MatVwOrgsAllIps


@shared_task(bind=True)
def get_vs_info(self, cyhy_db_names: List[str]):
    vs_data = list(MatVwOrgsAllIps.objects.filter(cyhy_db_name__in=cyhy_db_names))
    return vs_data