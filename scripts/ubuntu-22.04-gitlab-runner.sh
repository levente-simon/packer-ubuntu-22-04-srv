#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -yq upgrade
apt-get -yq install git

curl -LJO 'https://gitlab-runner-downloads.s3.amazonaws.com/latest/deb/gitlab-runner_amd64.deb'
dpkg -i gitlab-runner_amd64.deb
usermod -aG docker gitlab-runner
