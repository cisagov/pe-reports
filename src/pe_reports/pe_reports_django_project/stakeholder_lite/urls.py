from django.urls import path
from django.contrib.auth.decorators import login_required
from .views import StakeholderLiteForm

# app_name = 'stakeholder_lite'

urlpatterns = [


    path('', login_required(StakeholderLiteForm.as_view()),
         name='stakeholder_lite'),
]
