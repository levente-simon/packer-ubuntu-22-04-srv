#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -yq upgrade                             # 1.9 Ensure updates, patches, and additional security software are installed

apt-get -yq install aide aide-common            # 1.3.1 Ensure AIDE is installed 
apt-get -yq install apparmor                    # 1.6.1.1 Ensure AppArmor is installed
apt-get -yq install ufw                         # 3.5.1.1 Ensure ufw is installed 
apt-get -yq install auditd audispd-plugins      # 4.1.1.1 Ensure auditd is installed
apt-get -yq install rsyslog                     # 4.2.1.1 Ensure rsyslog is installed
apt-get -yq install sudo                        # 5.2.1 Ensure sudo is installed
apt-get -yq install libpam-pwquality            # 5.4.1 Ensure password creation requirements are configured

apt-get -yq purge autofs                        # 1.1.23 Disable Automounting 
apt-get -yq purge prelink                       # 1.5.3 Ensure prelink is not installed
apt-get -yq purge gdm3                          # 1.8.1 Ensure GNOME Display Manager is removed
apt-get -yq purge ntp                           # 2.1.1.2 Ensure systemd-timesyncd is configured
apt-get -yq purge chrony                        # 2.1.1.2 Ensure systemd-timesyncd is configured
apt-get -yq purge xserver-xorg*                 # 2.1.2 Ensure X Window System is not installed
apt-get -yq purge avahi-daemon                  # 2.1.3 Ensure Avahi Server is not installed 
apt-get -yq purge cups                          # 2.1.4 Ensure CUPS is not installed
apt-get -yq purge isc-dhcp-server               # 2.1.5 Ensure DHCP Server is not installed 
apt-get -yq purge slapd                         # 2.1.6 Ensure LDAP server is not installed
apt-get -yq purge nfs-kernel-server             # 2.1.7 Ensure NFS is not installed
apt-get -yq purge bind9                         # 2.1.8 Ensure DNS Server is not installed
apt-get -yq purge vsftpd                        # 2.1.9 Ensure FTP Server is not installed
apt-get -yq purge apache2                       # 2.1.10 Ensure HTTP server is not installed
apt-get -yq purge dovecot-imapd dovecot-pop3d   # 2.1.11 Ensure IMAP and POP3 server are not installed
apt-get -yq purge samba                         # 2.1.12 Ensure Samba is not installed
apt-get -yq purge squid                         # 2.1.13 Ensure HTTP Proxy Server is not installed 
apt-get -yq purge snmpd                         # 2.1.14 Ensure SNMP Server is not installed
apt-get -yq purge rsync                         # 2.1.16 Ensure rsync service is not installed
apt-get -yq purge nis                           # 2.1.17 Ensure NIS Server is not installed
apt-get -yq purge nis                           # 2.2.1 Ensure NIS Client is not installed
apt-get -yq purge rsh-client                    # 2.2.2 Ensure rsh client is not installed
apt-get -yq purge talk                          # 2.2.3 Ensure talk client is not installed
apt-get -yq purge telnet                        # 2.2.4 Ensure telnet client is not installed
apt-get -yq purge ldap-utils                    # 2.2.5 Ensure LDAP client is not installed
apt-get -yq purge rpcbind                       # 2.2.6 Ensure RPC is not installed
apt-get -yq purge iptables-persistent           # 3.5.1.2 Ensure iptables-persistent is not installed with ufw


cat <<EOF > /etc/modprobe.d/cis.conf
install cramfs /bin/true      #
install freevxfs /bin/true
install jffs2 /bin/true       # 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled
install hfs /bin/true         # 1.1.1.4 Ensure mounting of hfs filesystems is disabled
install hfsplus /bin/true     # 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled
install squashfs /bin/true    # 1.1.1.6 Ensure mounting of squashfs filesystems is disabled
install udf /bin/true         # 1.1.1.7 Ensure mounting of udf filesystems is disabled

install usb-storage /bin/true # 1.1.24 Disable USB Storage

install dccp /bin/true       # 3.4.1 Ensure DCCP is disabled
install sctp /bin/true       # 3.4.2 Ensure SCTP is disabled
install rds /bin/true        # 3.4.3 Ensure RDS is disabled
install tipc /bin/true       # 3.4.4 Ensure TIPC is disabled
EOF


# 1.1.6 Ensure /dev/shm is configured 
# 1.1.7 Ensure nodev option set on /dev/shm partition
# 1.1.8 Ensure nosuid option set on /dev/shm partition
# 1.1.9 Ensure noexec option set on /dev/shm partition
#TODO: fix to replece too  
echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0" >> /etc/fstab

# 1.1.22 Ensure sticky bit is set on all world-writable directories
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'

# 1.1.23 Disable Automounting 
systemctl --now disable autofs

# 1.3.1 Ensure AIDE is installed 
aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 1.3.2 Ensure filesystem integrity is regularly checked
cat <<EOF > /etc/systemd/system/aidecheck.service
[Unit]
Description=Aide Check
[Service]
Type=simple
ExecStart=/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check
[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/systemd/system/aidecheck.timer
[Unit]
Description=Aide check every day at 5AM
[Timer]
OnCalendar=*-*-* 05:00:00
Unit=aidecheck.service
[Install]
WantedBy=multi-user.target
EOF

chown root:root /etc/systemd/system/aidecheck.*
chmod 0644 /etc/systemd/system/aidecheck.*
systemctl enable aidecheck.service
systemctl --now enable aidecheck.timer

# 1.4.1 Ensure permissions on bootloader config are not overridden
sed -ri 's/chmod\s+[0-7][0-7][0-7]\s+\$\{grub_cfg\}\.new/chmod 400 ${grub_cfg}.new/' /usr/sbin/grub-mkconfig
sed -ri 's/ && ! grep "\^password" \$\{grub_cfg\}.new >\/dev\/null//' /usr/sbin/grub-mkconfig
if [ "x${grub_cfg}" != "x" ] && ! grep "^password" ${grub_cfg}.new >/dev/null; then
  chmod 444 ${grub_cfg}.new || true
fi

# Ensure bootloader password is set
#BL_PASS="lEW993Fxf33SfDaaq3v?wwer.wepq!11&uuh=3F0da12;sdppCdmap"
#BL_HASH=$(echo -e "${BL_PASS}\n${BL_PASS}" | grub-mkpasswd-pbkdf2 |  awk '/PBKDF2/ {print $7}')
#
#cat <<EOF > /etc/grub.d/99_cis_bl_pass
#set superusers="iac"
#password_pbkdf2 iac ${BL_HASH} EOF
#update-grub

# 1.4.3 Ensure permissions on bootloader config are configured
chown root:root /boot/grub/grub.cfg
chmod u-wx,go-rwx /boot/grub/grub.cfg

# 1.4.4 Ensure authentication required for single user mode


# 1.5.1 Ensure XD/NX support is enabled

# 1.5.2 Ensure address space layout randomization (ASLR) is enabled
echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/99-cis-addr-space-lo-rand.conf

for file in /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /run/sysctl.d/*.conf; do
  if [ -f "$file" ]; then
    grep -Esq "^\s*kernel\.randomize_va_space\s*=\s*([0-1]|[3-9]|[1-9][0-9]+)" "$file" && sed -ri 's/^\s*kernel\.randomize_va_space\s*=\s*([0-1]|[3-9]|[1-9][0-9]+)/# &/gi' "$file"
  fi
done


# 1.5.4 Ensure core dumps are restricted
echo "* hard core 0" > /etc/security/limits.d/99-cis-core-dump-disable.conf
echo "fs.suid_dumpable = 0" > /etc/sysctl.d/99-cis-core-dump-disable.conf

cat <<EOF > /etc/systemd/coredump.conf
Storage=none
ProcessSizeMax=0
EOF

# 1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration
# 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled
# 4.1.1.4 Ensure audit_backlog_limit is sufficient
sed -ri 's/^GRUB_CMDLINE_LINUX=.*$/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"/' /etc/default/grub
update-grub

# 1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
aa-complain /etc/apparmor.d/*

# 1.6.1.4 Ensure all AppArmor Profiles are enforcing
# aa-enforce /etc/apparmor.d/*

# 1.7.1 Ensure message of the day is configured properly 
# 1.7.4 Ensure permissions on /etc/motd are configured
rm /etc/motd

# 1.7.2 Ensure local login warning banner is configured properly
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

# 1.7.3 Ensure remote login warning banner is configured properly
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

# 1.7.5 Ensure permissions on /etc/issue are configured
chown root:root $(readlink -e /etc/issue) 
chmod u-x,go-wx $(readlink -e /etc/issue)

# 1.7.6 Ensure permissions on /etc/issue.net are configured
chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)

# 2.1.1.2 Ensure systemd-timesyncd is configured
cat <<EOF > /etc/systemd/timesyncd.conf
NTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org #Servers listed should be In Accordence With Local Policy
FallbackNTP=2.debian.pool.ntp.org 3.debian.pool.ntp.org #Servers listed should be In Accordence With Local Policy
RootDistanceMax=1 #should be In Accordence With Local Policy
EOF

systemctl start systemd-timesyncd.service
systemctl enable systemd-timesyncd.service
timedatectl set-ntp true


# 3.1.2 Ensure wireless interfaces are disabled
if command -v nmcli >/dev/null 2>&1 ; then
  nmcli radio all off
else
  if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
    mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
    for dm in $mname; do
      echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
    done
  fi
fi

cat <<EOF > /etc/sysctl.d/99-cis-network-params.conf
# net.ipv6.conf.all.disable_ipv6 = 1               # 3.1.1 Disable IPv6
# net.ipv6.conf.default.disable_ipv6 = 1           # 3.1.1 Disable IPv6
net.ipv4.conf.all.send_redirects = 0             # 3.2 Network Parameters
net.ipv4.conf.default.send_redirects = 0         # 3.2 Network Parameters
net.ipv4.conf.all.accept_source_route = 0        # 3.3.1 Ensure source routed packets are not accepted
net.ipv4.conf.default.accept_source_route = 0    # 3.3.1 Ensure source routed packets are not accepted
net.ipv6.conf.all.accept_source_route = 0        # 3.3.1 Ensure source routed packets are not accepted
net.ipv6.conf.default.accept_source_route = 0    # 3.3.1 Ensure source routed packets are not accepted
net.ipv4.conf.all.accept_redirects = 0           # 3.3.2 Ensure ICMP redirects are not accepted
net.ipv4.conf.default.accept_redirects = 0       # 3.3.2 Ensure ICMP redirects are not accepted
net.ipv6.conf.all.accept_redirects = 0           # 3.3.2 Ensure ICMP redirects are not accepted
net.ipv6.conf.default.accept_redirects = 0       # 3.3.2 Ensure ICMP redirects are not accepted
net.ipv4.conf.all.secure_redirects = 0           # 3.3.3 Ensure secure ICMP redirects are not accepted
net.ipv4.conf.default.secure_redirects = 0       # 3.3.3 Ensure secure ICMP redirects are not accepted
net.ipv4.conf.all.log_martians = 1               # 3.3.4 Ensure suspicious packets are logged
net.ipv4.conf.default.log_martians = 1           # 3.3.4 Ensure suspicious packets are logged
net.ipv4.icmp_echo_ignore_broadcasts = 1         # 3.3.5 Ensure broadcast ICMP requests are ignored
net.ipv4.icmp_ignore_bogus_error_responses = 1   # 3.3.6 Ensure bogus ICMP responses are ignored
net.ipv4.conf.all.rp_filter = 1                  # 3.3.7 Ensure Reverse Path Filtering is enabled
net.ipv4.conf.default.rp_filter = 1              # 3.3.7 Ensure Reverse Path Filtering is enabled
net.ipv4.tcp_syncookies = 1                      # 3.3.8 Ensure TCP SYN Cookies is enabled
net.ipv6.conf.all.accept_ra = 0                  # 3.3.9 Ensure IPv6 router advertisements are not accepted
net.ipv6.conf.default.accept_ra = 0              # 3.3.9 Ensure IPv6 router advertisements are not accepted
EOF

# 3.2.2 Ensure IP forwarding is disabled
grep -Els "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv4\.ip_forward\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done
grep -Els "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv6\.conf\.all\.forwarding\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done



# 3.5.1.3 Ensure ufw service is enabled
ufw allow proto tcp from any to any port 22
echo -e "y\n" | ufw enable

# 3.5.1.4 Ensure ufw loopback traffic is configured
ufw allow in on lo
ufw allow out on lo
ufw deny in from 127.0.0.0/8
ufw deny in from ::1

# 3.5.1.5 Ensure ufw outbound connections are configured
ufw allow out on all

# 3.5.1.7 Ensure ufw default deny firewall policy 
ufw allow git
ufw allow in http
ufw allow in https
ufw allow out 53
ufw logging on
ufw default deny incoming
ufw default deny outgoing
ufw default deny routed

# 4.1.1.2 Ensure auditd service is enabled
systemctl --now enable auditd

# 4.1.3 Ensure events that modify date and time information are collected
cat <<EOF > /etc/audit/rules.d/50-time-change.rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
EOF

# 4.1.4 Ensure events that modify user/group information are collected
cat <<EOF > /etc/audit/rules.d/50-identity.rules
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
EOF

# 4.1.5 Ensure events that modify the system's network environment are collected
cat <<EOF > /etc/audit/rules.d/50-system-locale.rules
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale -w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
EOF

# 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected
cat <<EOF > /etc/audit/rules.d/50-MAC-policy.rules
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
EOF

# 4.1.7 Ensure login and logout events are collected
cat <<EOF > /etc/audit/rules.d/50-logins.rules
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
EOF

# 4.1.8 Ensure session initiation information is collected
cat <<EOF > /etc/audit/rules.d/50-session.rules
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
EOF

# 4.1.9 Ensure discretionary access control permission modification events are collected
cat <<EOF > /etc/audit/rules.d/50-perm_mod.rules
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF

# 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected
cat <<EOF > /etc/audit/rules.d/50-access.rules
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
EOF

# 4.1.11 Ensure use of privileged commands is collected
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/50-privileged.rules

# 4.1.12 Ensure successful file system mounts are collected
cat <<EOF > /etc/audit/rules.d/50-mounts.rules
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
EOF

# 4.1.13 Ensure file deletion events by users are collected
cat <<EOF > /etc/audit/rules.d/50-delete.rules
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
EOF

# 4.1.14 Ensure changes to system administration scope (sudoers) is collected
cat <<EOF > /etc/audit/rules.d/50-scope.rules
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF

# 4.1.15 Ensure system administrator command executions (sudo) are collected 
cat <<EOF > /etc/audit/rules.d/50-actions.rules
-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions
-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions
EOF

# 4.1.16 Ensure kernel module loading and unloading is collected
cat <<EOF > /etc/audit/rules.d/50-modules.rules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF

# 4.1.17 Ensure the audit configuration is immutable
echo "-e 2" > /etc/audit/rules.d/99-finalize.rules 

# 4.2.1.2 Ensure rsyslog Service is enabled
systemctl --now enable rsyslog

# 4.2.1.3 Ensure logging is configured
cat <<EOF > /etc/rsyslog.d/99-cis-loggin.conf
*.emerg                   :omusrmsg:*
auth,authpriv.*           /var/log/auth.log
mail.*                    -/var/log/mail
mail.info                 -/var/log/mail.info
mail.warning              -/var/log/mail.warn
mail.err                  /var/log/mail.err
news.crit                 -/var/log/news/news.crit
news.err                  -/var/log/news/news.err
news.notice               -/var/log/news/news.notice
*.=warning;*.=err         -/var/log/warn
*.crit                    /var/log/warn
*.*;mail.none;news.none   -/var/log/messages
local0,local1.*           -/var/log/localmessages
local2,local3.*           -/var/log/localmessages
local4,local5.*           -/var/log/localmessages
local6,local7.*           -/var/log/localmessages
EOF

# 4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host
# TODO

# 4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts.
# TODO

systemctl reload rsyslog

# 4.2.2.1 Ensure journald is configured to send logs to rsyslog
sed -ri 's/.*ForwardToSyslog=.*$/ForwardToSyslog=yes/' /etc/systemd/journald.conf

# 4.2.2.2 Ensure journald is configured to compress large log files
sed -ri 's/.*Compress=.*$/Compress=yes/' /etc/systemd/journald.conf

# 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk
sed -ri 's/.*Storage=.*$/Storage=persistent/' /etc/systemd/journald.conf

# 4.2.3 Ensure permissions on all logfiles are configured
find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +

# 4.4 Ensure logrotate assigns appropriate permissions
sed -ri 's/create.*$/create 0640 root utmp/' /etc/logrotate.conf

# 5.1.1 Ensure cron daemon is enabled and running
systemctl --now enable cron

# 5.1.2 Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab

# 5.1.3 Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/

# 5.1.4 Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/

# 5.1.5 Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/

# 5.1.6 Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly/
chmod og-rwx /etc/cron.monthly/

# 5.1.7 Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/

# 5.1.8 Ensure cron is restricted to authorized users
rm /etc/cron.deny
touch /etc/cron.allow
chmod g-wx,o-rwx /etc/cron.allow
chown root:root /etc/cron.allow

# 5.1.9 Ensure at is restricted to authorized users
rm /etc/at.deny
touch /etc/at.allow
chmod g-wx,o-rwx /etc/at.allow
chown root:root /etc/at.allow

# 5.2.2 Ensure sudo commands use pty

# 5.2.3 Ensure sudo log file exists
echo 'Defaults logfile="/var/log/sudo.log"' > /etc/sudoers.d/cis-sudoers

# 5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

# 5.3.2 Ensure permissions on SSH private host key files are configured
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;

# 5.3.3 Ensure permissions on SSH public host key files are configured
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;

# 5.3.4 Ensure SSH access is limited
# TODO

cat <<EOF > /etc/ssh/sshd_config.d/cis.conf
LogLevel INFO              # 5.3.5 Ensure SSH LogLevel is appropriate
X11Forwarding no           # 5.3.6 Ensure SSH X11 forwarding is disabled
MaxAuthTries 4             # 5.3.7 Ensure SSH MaxAuthTries is set to 4 or less
IgnoreRhosts yes           # 5.3.8 Ensure SSH IgnoreRhosts is enabled
HostbasedAuthentication no # 5.3.9 Ensure SSH HostbasedAuthentication is disabled
PermitRootLogin no         # 5.3.10 Ensure SSH root login is disabled
PermitEmptyPasswords no    # 5.3.11 Ensure SSH PermitEmptyPasswords is disabled
PermitUserEnvironment no   # 5.3.12 Ensure SSH PermitUserEnvironment is disabled
HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa,ssh-dss
PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-rsa-cert-v01@openssh.com
# Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr # 5.3.13 Ensure only strong Ciphers are used
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr # 5.3.13 Ensure only strong Ciphers are used
# MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256 # 5.3.14 Ensure only strong MAC algorithms are used
# MACs hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-sha2-512,umac-64@openssh.com,umac-128@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com
# KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256 # 5.3.15 Ensure only strong Key Exchange algorithms are used
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521
ClientAliveInterval 300    # 5.3.16 Ensure SSH Idle Timeout Interval is configured
ClientAliveCountMax 3      # 5.3.16 Ensure SSH Idle Timeout Interval is configured
LoginGraceTime 60          # 5.3.17 Ensure SSH LoginGraceTime is set to one minute or less
Banner /etc/issue.net      # 5.3.18 Ensure SSH warning banner is configured
UsePAM yes                 # 5.3.19 Ensure SSH PAM is enabled
AllowTcpForwarding no      # 5.3.20 Ensure SSH AllowTcpForwarding is disabled
MaxStartups 10:30:60       # 5.3.21 Ensure SSH MaxStartups is configured
MaxSessions 10             # 5.3.22 Ensure SSH MaxSessions is limited
EOF

# 5.4.1 Ensure password creation requirements are configured
cat <<EOF > /etc/security/pwquality.conf
minlen = 14
minclass = 4
EOF

# TODO:
# 5.4.2 Ensure lockout for failed password attempts is configured
# 5.4.3 Ensure password reuse is limited
# 5.4.4 Ensure password hashing algorithm is SHA-512
# 5.5.1.1 Ensure minimum days between password changes is configured
# 5.5.1.2 Ensure password expiration is 365 days or less
# 5.5.1.3 Ensure password expiration warning days is 7 or more
# 5.5.1.4 Ensure inactive password lock is 30 days or less
# 5.5.1.5 Ensure all users last password change date is in the past

# 5.5.2 Ensure system accounts are secured
awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print $1}' /etc/passwd | while read -r user; do usermod -s "$(which nologin)" "$user"; done
awk -F: '($1!~/(root|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}' | while read -r user; do usermod -L "$user"; done

# 5.5.3 Ensure default group for the root account is GID 0
usermod -g 0 root

# 5.5.4 Ensure default user umask is 027 or more restrictive
grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bash.bashrc*
sed -ri 's/^UMASK.*$/UMASK 027/' /etc/login.defs
sed -ri 's/^USERGROUPS_ENAB.*$/USERGROUPS_ENAB no/' /etc/login.defs

# 5.5.5 Ensure default user shell timeout is 900 seconds or less
cat <<EOF > /etc/profile.d/99-cis.sh
TMOUT=900
readonly TMOUT
export TMOUT
EOF

# 6.1.3 Ensure permissions on /etc/passwd- are configured
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

# 6.1.4 Ensure permissions on /etc/group are configured
chown root:root /etc/group
chmod u-x,go-wx /etc/group

# 6.1.5 Ensure permissions on /etc/group- are configured
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-

# 6.1.6 Ensure permissions on /etc/shadow are configured
chown root:root /etc/shadow
chown root:shadow /etc/shadow

# 6.1.7 Ensure permissions on /etc/shadow- are configured
chown root:root /etc/shadow-
chown root:shadow /etc/shadow-

# 6.1.8 Ensure permissions on /etc/gshadow are configured 
chown root:root /etc/gshadow
chown root:shadow /etc/gshadow

# 6.1.9 Ensure permissions on /etc/gshadow- are configured
chown root:root /etc/gshadow-
chown root:shadow /etc/gshadow-

systemctl daemon-reload

