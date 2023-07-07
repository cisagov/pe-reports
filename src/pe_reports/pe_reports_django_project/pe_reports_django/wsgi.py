"""
WSGI config for pe_reports_django project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/howto/deployment/wsgi/
"""
# Standard Python Libraries
# from  import router as main_router
import os

# Third-Party Libraries
from django.core.wsgi import get_wsgi_application

##Third party packages
from fastapi import FastAPI

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pe_reports_django.settings")

application = get_wsgi_application()

# Below this line is comment
