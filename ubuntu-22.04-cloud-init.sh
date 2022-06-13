#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
apt -yq purge cloud-init
rm -rf /etc/cloud
rm -rf /var/lib/cloud
rm -rf /etc/netplan/*
apt -yq install cloud-init

touch /etc/growroot-disabled

cat <<EOF > /etc/cloud/cloud.cfg.d/99-packer-setup.cfg
# preserve_hostname: false
# manage_etc_hosts: true
growpart:
  mode: auto
  devices: [/dev/sda3]
  ignore_growroot_disabled: true
runcmd:
  - [pvresize, /dev/sda3]
  - [lvextend, -l, +100%FREE, /dev/vg_root/lv_data]
  - [xfs_growfs, /dev/vg_root/lv_data]
EOF

