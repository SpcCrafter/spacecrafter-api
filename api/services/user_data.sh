#!/bin/bash
# Update the package listings
apt-get update

# Install Docker
apt-get install -y docker.io

# Start and enable Docker service
systemctl start docker
systemctl enable docker

# Add the ubuntu user to the docker group so you can execute Docker commands without using sudo
usermod -aG docker ubuntu
