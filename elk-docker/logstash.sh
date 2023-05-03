#!/bin/bash

# Copy the Elasticsearch certificates from the 'es01' container to the local 'logs/' directory.
docker cp es01:/usr/share/elasticsearch/config/certs/es01/ logs/

# Create a 'ssl' directory inside the 'logstash' container.
docker exec -it logstash /bin/bash -c "mkdir -p /usr/share/logstash/ssl"

# Copy the Elasticsearch certificates from the local 'logs/' directory to the 'logstash' container's 'ssl' directory.
docker cp logs/es01/es01.crt logstash:/usr/share/logstash/ssl/

# Update the package lists for upgrades and package installations in the 'logstash' container.
docker exec -u 0 -it logstash bash -c "apt-get update"

# Install the OpenJDK 11 JDK headless package in the 'logstash' container. Use options 2 and 106 
docker exec -u 0 -it logstash bash -c "apt-get install -y openjdk-11-jdk-headless"
#docker exec -u 0 -it logstash bash -c 'read -p "Enter 2 and 106: " num1 num2 && apt-get install -y openjdk-11-jdk-headless "$num1" "$num2"'  #Need to test this command

# Import the Elasticsearch certificate into the Java keystore in the 'logstash' container.
docker exec -u 0 -it logstash bash -c "keytool -import -trustcacerts -alias es01_cert -file /usr/share/logstash/ssl/es01.crt -keystore $JAVA_HOME/usr/lib/jvm/java-11-openjdk-amd64/lib/security/cacerts -storepass changeit"
