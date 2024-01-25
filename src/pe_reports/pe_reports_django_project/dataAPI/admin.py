"""dataAPI module admin.py."""
# Third-Party Libraries
# Register your models here.
# Third-Party Libraries
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User

from .models import apiUser


# Define an inline admin descriptor for User model
# which acts a bit like a singleton
class ApiUserInline(admin.StackedInline):
    """ApiUserInline class."""

    model = apiUser
    can_delete = False


# Define a new User admin
class UserAdmin(BaseUserAdmin):
    """UserAdmin class."""

    inlines = (ApiUserInline,)


# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

admin.site.site_header = "P&E Admin"
