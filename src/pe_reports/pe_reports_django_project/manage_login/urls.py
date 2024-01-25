"""manage_login module urls.py."""
# Third-Party Libraries
from django.urls import path

from . import views

urlpatterns = [
    path("", views.login_request, name="login"),
    path("register/", views.register_request, name="register"),
    path("logout/", views.logout_view, name="logout"),
]
