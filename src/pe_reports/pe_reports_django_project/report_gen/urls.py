# Third-Party Libraries
from django.contrib.auth.decorators import login_required
from django.urls import path

from . import views

urlpatterns = [
    path("", login_required(views.report_gen), name="report_gen"),
]
