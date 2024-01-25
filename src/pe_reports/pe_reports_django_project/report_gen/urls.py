"""report_gen module urls.py."""
# Third-Party Libraries
from django.urls import path

from . import views

urlpatterns = [
    path("", views.report_gen, name="report_gen"),
]
