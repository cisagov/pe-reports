from django.urls import path
from django.contrib.auth.decorators import login_required
from .views import CustomCSVForm




urlpatterns = [


    path('', login_required(CustomCSVForm.as_view()), name='bulkupload'),
]
