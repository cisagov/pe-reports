"""stakeholder_lite module urls.py."""
# Third-Party Libraries
from django.contrib.auth.decorators import login_required
from django.urls import path

from .views import StakeholderLiteForm

# app_name = 'stakeholder_lite'

urlpatterns = [
    path("", login_required(StakeholderLiteForm.as_view()), name="stakeholder_lite"),
]
