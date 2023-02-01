from django.urls import path
from . import views
from django.contrib.auth.decorators import login_required

urlpatterns = [


    path('', login_required(views.report_gen), name='report_gen'),
]