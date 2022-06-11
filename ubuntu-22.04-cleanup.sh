#!/bin/bash

while [ ! -f /var/lib/cloud/instance/boot-finished ]; do
  echo 'Waiting for boot-finished...'
  sleep 5
done

shred -u /etc/ssh/*_key /etc/ssh/*_key.pub
sudo mkdir -m og-rxw /etc/skel/.ssh

truncate -s 0 /var/log/lastlog /var/log/wtmp /var/log/btmp /etc/resolv.conf
unset HISTFILE; rm -rf /home/*/.*history /root/.*history /var/run/utmp /tmp/* /var/tmp/* /root/*ks

cloud-init clean -l

