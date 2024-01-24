"""
ASGI config for pe_reports_django project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/howto/deployment/asgi/
"""
# Standard Python Libraries
import os

# Third-Party Libraries
from django.core.wsgi import get_wsgi_application
# Following 2 lines custom code
from django.apps import apps
from django.conf import settings
from fastapi import FastAPI
from fastapi.middleware.wsgi import WSGIMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware

# cisagov Libraries
from dataAPI.views import api_router

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pe_reports_django.settings")

application = get_wsgi_application()

#Below this comment is custom code
apps.populate(settings.INSTALLED_APPS)


def get_application() -> FastAPI:
    app1 = FastAPI(title=settings.PROJECT_NAME, debug=settings.DEBUG)
    app1.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_HOSTS or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app1.include_router(api_router, prefix="/apiv1")
    app1.mount("/", WSGIMiddleware(get_wsgi_application()))
    app1.mount("/static/", StaticFiles(directory="static"), name="static")

    return app1


app1 = get_application()
