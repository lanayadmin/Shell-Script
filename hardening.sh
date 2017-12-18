#!/bin/bash
# hardening script RedHat 7
#############################################
#check to see if script is being run as root
if [ `whoami` != 'root' ]
  then
    echo "You must be root to do this."
    exit
fi
#############################################

progress () {
echo ''
echo '############################################'
echo -ne "$1.       \r"
sleep 1
echo -ne "$1..      \r"
sleep 1
echo -ne "$1...     \r"
sleep 1
echo -ne "$1....    \r"
sleep 1
echo -ne '\n'
echo '############################################'
echo ''
}

progress "1.0 Remove legacy services"
#remove telnet-server
yum -y erase telnet-server
#Remove telnet clients
yum -y erase telnet
#Remove rsh-server
yum -y erase rsh-server
#Remove rsh
yum -y erase rsh
#Remove NIS Client
yum -y erase ypbind
#Remove NIS Server
yum -y erase ypserv
#Remove tftp
yum -y erase tftp
#Remove tftp-server
yum -y erase tftp-server
#Remove talk
yum -y erase talk
#Remove talk-server
yum -y erase talk-server
#Remove xinetd
yum -y erase xinetd
#Remove DHCP Server
yum -y erase dhcp

#Disable chargen-dgram
chkconfig chargen-dgram off
#Disable chargen-stream
chkconfig chargen-stream off
#Disable daytime-dgram
chkconfig daytime-dgram off
#Disable daytime-stream
chkconfig daytime-stream off
#Disable echo-dgram
chkconfig echo-dgram off
#Disable echo-stream
chkconfig echo-stream off
#Disable tcpmux-server
chkconfig tcpmux-server off
#Disable Avahi Server
chkconfig avahi-daemon off
#Disable Print Server 
chkconfig cups off

progress "2.0 Modify Network Parameters (Host Only)"
#Disable IP Forwarding
#Disable Send Packet Redirects
#Modify Network Parameters ( Host and Router)
#Disable Source Routed Packet Acceptance
#Disable ICMP Redirect Acceptance
#Disable Secure ICMP Redirect Acceptance
#Log suspicious Packets
#Enable Ignore Broadcast Request
#Enable Bad Error Message Protection
#Enable RFC-recommended Source Route Validation
#Enable TCP SYN cookies
# /etc/sysctl.conf

string="net.ipv4.conf.all.log_martians=1"

if grep -Fxq "$string" /etc/sysctl.conf
then
	echo "Nothing to do"
else
cat << 'EOM' >> /etc/sysctl.conf
#Benchmark Adjustments
kernel.randomize_va_space=2
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.default.disable_ipv6=0
net.ipv6.conf.all.disable_ipv6=0
EOM

#run the following commands to set the active kernel parameters
sysctl -w kernel.randomize_va_space=2
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv6.conf.default.disable_ipv6=0
sysctl -w net.ipv6.conf.all.disable_ipv6=0
sysctl -w net.ipv4.route.flush=1
fi

progress "3.0 Ensure permission on /etc/hosts.* (root / 644)"

chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny
ls -l /etc/hosts.*

progress "4.0 Configure System Accounting (/etc/audit/auditd.conf)"

#Ensure audit log storage size is configured
echo "---Change max_log_file to 100MB---"
sed -i 's/max_log_file = 8/max_log_file = 100/' /etc/audit/auditd.conf
grep -i 'max_log_file = 100' /etc/audit/auditd.conf
echo ''

#Ensure system is disabled when audit logs are full
echo "---Ensure system is disabled when audit logs are full---"
sed -i 's/admin_space_left_action = SUSPEND/admin_space_left_action = halt/' /etc/audit/auditd.conf
grep -i 'admin_space_left_action = halt' /etc/audit/auditd.conf
echo ''

#Ensure audit logs are not automatically deleted
echo "---Ensure audit logs are not automatically deleted---"
sed -i 's/max_log_file_action = ROTATE/max_log_file_action = keep_logs/'  /etc/audit/auditd.conf
grep -i 'max_log_file_action = keep_logs' /etc/audit/auditd.conf
echo ''

#Enable auditd service
echo "---Enable auditd service---"
chkconfig auditd on
echo ''

#Enable Auditing for process that start prior to auditd
echo "---Enable auditing for process that start prior to auditd---"
if grep -q audit=1 "/etc/default/grub";
	then 
		echo "audit=1 configured. Nothing to do." 
	else
		sed -i 's/GRUB_CMDLINE_LINUX=\"/& audit=1 /g' /etc/default/grub;
		grub2-mkconfig > /boot/grub2/grub.cfg;
fi
grep -i 'GRUB_CMDLINE_LINUX' /etc/default/grub
echo ''


#Logging services should be configured to prevent information leaks and to aggregate logs on a remote server 
#so that they can be reviewed in the event of a system compromise and ease log analysis.
progress "5.0 Configure Logging"

#Ensure rsyslog service is enabled
echo "---Ensure rsyslog service is enable---"
systemctl enable rsyslog
systemctl status rsyslog | grep -i 'active'
echo ''

#Ensure rsyslog default file permission configured
#This setting controls what permission will be applied to these newly created files
#It is important to ensure that log files have the correct permission to ensure that sensitive data is archived and protected.
echo "---Ensure rsyslog default file permission configured---"
if grep -q "\$FileCreateMode" "/etc/rsyslog.conf";
	then
		echo "\$FileCreateMode configured. Nothing to do."
	else
		sed -i '/$IMJournalStateFile/a $FileCreateMode 0640' /etc/rsyslog.conf
fi
grep -i "\$FileCreateMode" /etc/rsyslog.conf
echo ''


#the system does have maintenance jobs that may include security monitoring that have to run and cron is used to execute them
progress "6.0 Configure cron"
echo "---Ensure cron daemon is enabled---"
systemctl enable crond
systemctl status crond | grep -i 'active'
echo ''

#Ensure permission on /etc/crontab are configured
echo "---Ensure permissions on /etc/crontab are configured---"
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
stat /etc/crontab | grep -i uid
echo ''

#Ensure permissions on /etc/cron.hourly are configured
echo "---Ensure permissions on /etc/cron.hourly are configured---"
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
stat /etc/cron.hourly | grep -i uid
echo ''

#Ensure permission on /etc/cron.daily are configured
echo "---Ensure permission on /etc/cron.daily are configured---"
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
stat /etc/cron.daily | grep -i uid
echo ''

#Ensure permission on /etc/cron.weekly are configured
echo "---Ensure permission on /etc/cron.weekly are configured---"
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
stat /etc/cron.daily | grep -i uid
echo ''

#Ensure permission on /etc/cron.monthly are configured
echo "---Ensure permission on /etc/cron.monthly are configured ---"
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
stat /etc/cron.monthly | grep -i uid
echo ''

#Ensure permission on /etc/cron.d are configured 
echo "---Ensure permission on /etc/cron.d are configured---"
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
stat /etc/cron.d | grep -i uid
echo ''

#The cron.allow file only control administrative access to the crontab command for scheduling and modifying cron jobs
echo "---Ensure cron is restricted to authorized users---"
if [ -e /etc/cron.deny ]
	then 
		rm -f /etc/cron.deny
		echo "removed /etc/cron.deny"
	else
		echo "/etc/cron.deny not exist. Nothing to do."
fi
echo ''

echo "---Configure cron.allow---"
if [ -e /etc/cron.allow ]; then
		chmod og-rwx /etc/cron.allow
		chown root:root /etc/cron.allow
		if grep -q "root" "/etc/cron.allow"
			then
				echo "Only root allowed to use cron configured. Nothing to do."
			else 
				sed -i '1 a root' /etc/cron.allow
		fi
else
		touch /etc/cron.allow
		echo "root" > /etc/cron.allow
		chmod og-rwx /etc/cron.allow
		chown root:root /etc/cron.allow
fi

stat /etc/cron.allow | grep -i uid
cat /etc/cron.allow
echo ''

progress "7.0 SSH Server Configuration"
echo "--Ensure permission on /etc/ssh/sshd_config are configured--"
if [ -e /etc/ssh/sshd_config ]; then
	chown root:root /etc/ssh/sshd_config
	chmod og-rwx /etc/ssh/sshd_config
	stat /etc/ssh/sshd_config | grep -i uid
	
else
	echo "/etc/ssh/sshd_config file not found"
fi
echo ''


echo "--Ensure SSH LogLevel is set to INFO--"
if [ -e /etc/ssh/sshd_config ]; then
	sed -i '/LogLevel/s/^#//g' /etc/ssh/sshd_config
else
	echo "/etc/ssh/sshd_config file not found"
fi
grep "LogLevel" /etc/ssh/sshd_config
echo ''

echo "--Ensure SSH X11 forwarding is disabled--"
if [ -e /etc/ssh/sshd_config ]; then
	 sed -i "s/X11Forwarding yes/X11Forwarding no/" /etc/ssh/sshd_config
else
	echo "/etc/ssh/sshd_config file not found"
fi
grep "X11Forwarding" /etc/ssh/sshd_config
echo ''

echo "--Ensure SSH MaxAuthTries is set to 4 or less--"
if [ -e /etc/ssh/sshd_config ]; then
	sed -i '/MaxAuthTries/s/^#//g' /etc/ssh/sshd_config
	sed -i 's/MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
else
	echo "/etc/ssh/sshd_config file not found"
fi
grep "MaxAuthTries" /etc/ssh/sshd_config
echo ''

#Setting this parameter forces users to enter a password when authenticating with ssh
echo "--Ensure SSH IgnoreRhosts is enabled--"
if [ -e /etc/ssh/sshd_config ]; then
	sed -i '/IgnoreRhosts/s/^#//g' /etc/ssh/sshd_config
else
	echo "/etc/ssh/sshd_config file not found"
fi
grep "IgnoreRhosts" /etc/ssh/sshd_config
echo ''


echo "--Ensure SSH HostbasedAuthentication is disabled--"
if [ -e /etc/ssh/sshd_config ]; then
	sed -i '/HostbasedAuthentication no/s/^#//g' /etc/ssh/sshd_config
else
	echo "/etc/ssh/sshd_config file not found"
fi
grep "HostbasedAuthentication no" /etc/ssh/sshd_config
echo ''

#The PermitEmptyPassword parameter specifies if the SSH server allows login to accounts with empty password strings
echo "--Ensure SSH PermitEmptyPasswords is disabled--"
if [ -e /etc/ssh/sshd_config ]; then
	sed -i '/PermitEmptyPasswords/s/^#//g' /etc/ssh/sshd_config
else
	echo "/etc/ssh/sshd_config file not found"
fi
grep "PermitEmptyPasswords" /etc/ssh/sshd_config
echo ''

#The PermitUserEnvironment option allows users to present environment options to the ssh daemon
echo "--Ensure SSH PermitUserEnvironment is disabled--"
if [ -e /etc/ssh/sshd_config ]; then
	sed -i '/PermitUserEnvironment/s/^#//g' /etc/ssh/sshd_config
else
	echo "/etc/ssh/sshd_config file not found"
fi
grep "PermitUserEnvironment" /etc/ssh/sshd_config
echo ''

#ClientAliveInterval variable is set, ssh sessions that have no activity for the specified length of time are terminated.
#ClientAliveCountMax is set to 3 means if ClientAliveInterval is set to 15sec then after 15x3=45sec, session terminated
echo "--Ensure SSH idle timeout interval is configured--"
if [ -e /etc/ssh/sshd_config ]; then
	sed -i '/ClientAliveInterval/s/^#//g' /etc/ssh/sshd_config
	sed -i '/ClientAliveCountMax/s/^#//g' /etc/ssh/sshd_config
	sed -i 's/ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
	sed -i 's/ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config
else	
	echo "/etc/ssh/sshd_config file not found"
fi
grep "ClientAlive" /etc/ssh/sshd_config
echo ''

#The time after which the server disconnects if the user has not successfully logged in.
echo "--Ensure SSH LoginGraceTime is set to one minute--"
if [ -e /etc/ssh/sshd_config ]; then
	sed -i '/LoginGraceTime/s/^#//g' /etc/ssh/sshd_config
	sed -i 's/LoginGraceTime 2m/LoginGraceTime 60/' /etc/ssh/sshd_config
else
	echo "/etc/ssh/sshd_config file not found"
fi
grep "LoginGraceTime" /etc/ssh/sshd_config
echo ''

echo "--Ensure SSH warning banner is configured--"
if [ -e /etc/ssh/sshd_config ]; then
	sed -i '/Banner/s/^#//g' /etc/ssh/sshd_config
	if [ -e /etc/issue.net ]; then
		sed -i 's/Banner none/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
		else
			echo "/etc/issue.net file not found"
	fi
	else
		echo "/etc/ssh/sshd_config file not found"
fi
grep "Banner" /etc/ssh/sshd_config
echo ''


progress "Configure PAM"
echo "--Ensure password creation requirements are configured--"
if [ -e /etc/security/pwquality.conf ]; then
	echo "**password must be 14 characters or more"
	sed -i '/minlen/s/^# //g' /etc/security/pwquality.conf
	sed -i 's/minlen = 9/minlen = 14/' /etc/security/pwquality.conf
	echo "**provide at least one digit"
	sed -i '/dcredit/s/^# //g' /etc/security/pwquality.conf
	sed -i 's/dcredit = 1/dcredit = -1/' /etc/security/pwquality.conf
	echo "**provide at least one uppercase characters"
	sed -i '/ucredit/s/^# //g' /etc/security/pwquality.conf
	sed -i 's/ucredit = 1/ucredit = -1/' /etc/security/pwquality.conf
	echo "**provide at least one special characters"
	sed -i '/ocredit/s/^# //g' /etc/security/pwquality.conf
	sed -i 's/ocredit = 1/ocredit = -1/' /etc/security/pwquality.conf
	echo "**provide at least one lowercase characters"  
	sed -i '/lcredit/s/^# //g' /etc/security/pwquality.conf
	sed -i 's/lcredit = 1/lcredit = -1/' /etc/security/pwquality.conf
	
	else	
		echo "/etc/security/pwquality.conf file not found"
fi
grep "minlen" /etc/security/pwquality.conf
grep "dcredit" /etc/security/pwquality.conf
grep "ucredit" /etc/security/pwquality.conf
grep "ocredit" /etc/security/pwquality.conf
grep "lcredit" /etc/security/pwquality.conf
echo ''

if [ -e /etc/pam.d/password-auth ]; then 
	echo "**removing local_users_only for password-auth"
	sed -i 's/local_users_only//' /etc/pam.d/password-auth
	else
		echo "/etc/pam.d/password-auth file not found"
fi
grep "pam_pwquality.so" /etc/pam.d/password-auth


if [ -e /etc/pam.d/system-auth ]; then
	echo "**removing local_users_only for system-auth"
	sed -i 's/local_users_only//' /etc/pam.d/system-auth
	else 
		echo "/etc/pam.d/system-auth file not found"
fi
grep "pam_pwquality.so" /etc/pam.d/system-auth
echo ''


echo "--Ensure password reuse is limited--"
if [ -e /etc/pam.d/password-auth ]; then
	echo "--For /etc/pam.d/password-auth"
    if grep -q "remember=5" "/etc/pam.d/password-auth"
    then
        echo "remember=5 configured. Nothing to do"
    else
        sed -i 's/sha512/& remember=5/g' /etc/pam.d/password-auth
    fi
else
        echo "/etc/pam.d/password-auth file not found"
fi
grep "remember=5" /etc/pam.d/password-auth
echo ''

if [ -e /etc/pam.d/system-auth ]; then
	echo "--For /etc/pam.d/system-auth"
	if grep -q "remember=5" "/etc/pam.d/system-auth"
	then
		echo "remember=5 configured. Nothing to do"
	else
		sed -i 's/sha512/& remember=5/g' /etc/pam.d/system-auth
	fi
else
	echo "/etc/pam.d/system-auth file not found"
fi
grep "remember=5" /etc/pam.d/system-auth
echo ''

echo "--Ensure password expiration is 90 days--"
if [ -e /etc/login.defs ]; then
	if grep -q "99999" "/etc/login.defs"
	then
		sed -i 's/99999/90/g' /etc/login.defs 
	else
		echo "PASS_MAX_DAYS was 90"
	fi
fi
grep "^PASS_MAX_DAYS" /etc/login.defs
chage --maxdays 90 root

echo "--Ensure minimum days between password changes is 7 or more--"
if [ -e /etc/login.defs ]; then
	if grep -q "PASS_MIN_DAYS   7" /etc/login.defs
	then
		echo "PASS_MIN_DAYS was 7"
	else
		a=`grep -n "^PASS_MIN_DAYS" /etc/login.defs | cut -d: -f1`
		sed -i ''$a'd' /etc/login.defs
		sed -i ''$a'iPASS_MIN_DAYS   7' /etc/login.defs
	fi
fi
grep "^PASS_MIN_DAYS" /etc/login.defs
chage --mindays 7 root

echo "--Ensure password expiration warning days is 7 or more--"
if [ -e /etc/login.defs ]; then
	if grep -q "PASS_WARN_AGE   7" /etc/login.defs
	then
		echo "PASS_WARN_AGE was 7"
	else
		a=`grep -n "^PASS_WARN_AGE" /etc/login.defs | cut -d: -f1`
		sed -i ''$a'd' /etc/login.defs
		sed -i ''$a'iPASS_WARN_AGE   7' /etc/login.defs
	fi
fi
grep "^PASS_WARN_AGE" /etc/login.defs
chage --warndays 7 root

useradd -D -f 30
chage --inactive 30 root
echo ''
chage --list root

echo "--Ensure permission on /etc/passwd are configured--"
chown root:root /etc/passwd
chmod 644 /etc/passwd
stat /etc/passwd | grep 'Uid'
echo ''

echo "--Ensure permission on /etc/shadow are configured--"
chown root:root /etc/shadow
chmod 000 /etc/shadow
stat /etc/shadow | grep 'Uid'
echo ''

echo "--Ensure permission on /etc/group are configured--"
chown root:root /etc/group
chmod 644 /etc/group
stat /etc/group | grep 'Uid'
echo ''

echo "--Ensure permission on /etc/gshadow--"
chown root:root /etc/gshadow
chmod 000 /etc/gshadow
stat /etc/gshadow | grep 'Uid'
echo ''

echo "--Ensure permissions on /etc/passwd- are configured--"
chown root:root /etc/passwd-
chmod 600 /etc/passwd-
stat /etc/passwd- | grep 'Uid'
echo ''

echo "--Ensure permission on /etc/shadow- are configued--"
chown root:root /etc/shadow-
chmod 600 /etc/shadow-
stat /etc/shadow- | grep 'Uid'
echo ''

echo "--Ensure permission on /etc/group- are configured--"
chown root:root /etc/group-
chmod 600 /etc/group-
stat /etc/group- | grep 'Uid'
echo ''

echo "--Ensure permission on /etc/gshadow- are configured--"
chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-
stat /etc/gshadow- | grep 'Uid'
echo ''















