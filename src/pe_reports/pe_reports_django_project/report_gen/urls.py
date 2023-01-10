from django.urls import path
from . import views

urlpatterns = [


    path('', views.report_gen, name='report_gen'),
]