# Generated by Django 4.1.5 on 2023-01-04 14:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dataAPI', '0002_apiuser_refresh_token'),
    ]

    operations = [
        migrations.AlterField(
            model_name='apiuser',
            name='apiKey',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='apiuser',
            name='refresh_token',
            field=models.CharField(max_length=200, null=True),
        ),
    ]