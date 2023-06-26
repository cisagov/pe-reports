#!/bin/bash

#docker run --name filebeat -d -v /var/www/pe-reports/src/pe_reports/pe_reports_django_project/pe_reportsLogFile.log:/logs1 -v /var/log/celery/celeryDjango.service.log:/logs2 --env-file .env my-filebeat

docker stop filebeat
docker rm filebeat

