import os
from celery import Celery
from django.conf import settings
from decouple import config

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pe_reports_django.settings')

app = Celery('pe_reports_django',
             broker=f'amqp://'
                    f'{config("RABBITMQ_USER")}:'
                    f'{config("RABBITMQ_PASS")}@localhost:5672/')

app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
