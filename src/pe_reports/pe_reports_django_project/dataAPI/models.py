"""dataAPI module models.py."""
# Third-Party Libraries
from django.contrib.auth.models import User
from django.db import models

# Create your models here.


class apiUser(models.Model):
    """apiUser class."""

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    apiKey = models.CharField(max_length=200, null=True)
    refresh_token = models.CharField(max_length=200, null=True)
