FROM debian:sid-20230612-slim

# Install Filebeat
RUN apt-get update && apt-get install -y wget
RUN wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.6.0-amd64.deb
RUN dpkg -i filebeat-8.6.0-amd64.deb

# Copy over Filebeat configuration
COPY filebeat.yml /etc/filebeat/filebeat.yml
RUN chmod go-w /etc/filebeat/filebeat.yml

# Command to run
CMD ["filebeat", "-e"]