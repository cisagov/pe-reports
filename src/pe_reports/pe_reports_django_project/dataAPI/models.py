from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class apiUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    apiKey = models.CharField(max_length=200, null=True)
    refresh_token = models.CharField(max_length=200, null=True)


