"""pe_reports_django module celery_config.py."""
# Standard Python Libraries
import os

# Third-Party Libraries
from celery import Celery
from decouple import config

# from django_celery_beat.models import PeriodicTask, CrontabSchedule
# from django.conf import settings
from django.apps import apps

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pe_reports_django.settings")

app = Celery(
    "pe_reports_django",
    broker=f"amqp://"
    f'{config("RABBITMQ_USER")}:'
    f'{config("RABBITMQ_PASS")}@localhost:5672/',
    backend="redis://localhost:6379/1",
)


app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks(lambda: [n.name for n in apps.get_app_configs()])

app.conf.result_expires = 86400
