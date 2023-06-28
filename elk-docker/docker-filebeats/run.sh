#!/bin/bash


docker stop filebeat
docker rm filebeat

#docker run --name filebeat -d -v /var/www/pe-reports/src/pe_reports/pe_reports_django_project/pe_reportsLogFile.log:/logs1 -v /var/log/celery/celeryDjango.service.log:/logs2 --env-file .env my-filebeat

#docker run -d --name=filebeat --user=root --volume="$(pwd)/filebeat.yml:/etc/filebeat/filebeat.yml:ro" --volume="/var/lib/docker/containers:/var/lib/docker/containers:ro" --volume="/var/run/docker.sock:/var/run/docker.sock:ro" --volume="/var/log:/var/log:ro" docker.elastic.co/beats/filebeat:8.6.0 filebeat -e -strict.perms=false -E output.logstash.hosts=["${ELASTICSEARCH_URL}:5044"]
