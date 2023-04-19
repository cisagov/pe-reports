#!/bin/bash
# This is a Bash script to stop all running Docker containers, and clean up Docker resources.

# Stop all running Docker containers.
# `docker ps -q` lists the IDs of all running containers.
sudo docker stop $(docker ps -q)

# Remove all stopped containers.
# The `-f` flag is used to force the removal without prompting for confirmation.
sudo docker container prune -f

# Remove all unused images.
sudo docker image prune -f

# Remove all unused volumes.
sudo docker volume prune -f

# Remove all unused networks.
sudo docker network prune -f