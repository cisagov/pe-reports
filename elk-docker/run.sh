#!/bin/bash

#This is the master run file. It is, as of Apr 19 2023, Not fully usable with other scripts

# Load environment variables from .env file
source .env

# Clone the git repository
git clone $GIT_REPO

# Install Docker and Docker Compose
sudo apt-get update
sudo apt-get install -y docker.io docker-compose

# Install AWS CLI
sudo apt-get install awscli

# Change directory to the cloned repository
cd $GIT_FOLDER

# Run the Docker Compose file
sudo docker-compose up -d

# Copy files from Docker container to local host
sudo docker cp :docker cp elastic:/usr/share/elasticsearch/config/certs/ca ./certs

# Reboot Docker Compose
sudo docker-compose restart