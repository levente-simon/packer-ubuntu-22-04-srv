#!/bin/bash

# TODO: enable fw
systemctl stop ufw
systemctl disable ufw
systemctl stop firewalld
systemctl disable firewalld
iptables -t filter -F
iptables -t filter -X

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -yq upgrade

apt-get -yq install ca-certificates curl gnupg lsb-release

mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get -yq install docker-ce docker-ce-cli containerd.io docker-compose-plugin

mv /var/lib/docker /data/docker
ln -s /data/docker /var/lib/docker

systemctl enable docker.service containerd.service cloud-config cloud-init cloud-init-local cloud-final

usermod -aG docker iac
grep -Elrs '^\s*groups:\s*\[.*\]\s*$' /etc/cloud | while read cfg; do sed -ri 's/(^\s*groups:\s*\[.*)].*$/\1, docker]/' $cfg; done

systemctl daemon-reload
systemctl restart docker containerd
