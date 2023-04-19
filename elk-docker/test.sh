#!/bin/bash

#This is a test script to set up the ELK Stack

# Configure AWS credentials
aws configure

# Run shell to pull env variables
source ./env.sh

# Pull a single env variable for testing and adds to end of .env file
#STACK_VERSION=$(aws ssm get-parameter --name /ELK-Test/STACK-VERSION --query 'Parameter.Value' --output text)
#echo "STACK_VERSION=${STACK_VERSION}" >> .env

# Run the Elastic Stack containers
sudo docker-compose up -d

# Copy files from Docker container to local host
sudo docker cp es01:/usr/share/elasticsearch/config/certs/ca ./certs

# Reboot Docker Compose
sudo docker-compose restart