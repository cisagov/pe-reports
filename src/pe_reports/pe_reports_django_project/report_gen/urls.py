# Third-Party Libraries
from django.urls import path

# cisagov Libraries
from . import views

urlpatterns = [
    path('', views.report_gen, name='report_gen'),
]