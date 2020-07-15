#!/usr/bin/env -S bats -p
#
# (c) 2020 ZibaSec Inc
#
# Audits a Linux System for sane security defaults
#

if [[ `whoami` != "root" ]]; then
  echo "Must run with sudo or as root" >&2
  exit 1
fi

@test "Disk encryption is enabled" {
    # Checks for at least one encrypted volume
    result="$(blkid | grep crypt)"
    [[ ! -z "$result" ]]
}

@test "Firewall is present" {
    # iptables should be present on Linux by default
    result="$(iptables -L)"
    [[ ! -z "$result" ]]
}

@test "FTP is not running" {
    run systemctl status ftpd
    [[ "$status" -eq 4 ]]
}

@test "Remote shell is not installed" {
    # Fix by uninstalling any of the packages present
    run command -v rsh-server
    [[ "$status" -eq 1 ]]
    run command -v openssh-server
    [[ "$status" -eq 1 ]]
    run command -v rsh-redone-server
    [[ "$status" -eq 1 ]]
    run command -v sbrsh
    [[ "$status" -eq 1 ]]
    run command -v sbrshd
    [[ "$status" -eq 1 ]]
}

@test "SMB is not installed" {
    # Fix by uninstalling any of the packages present
    run command -v smbnetfx
    [[ "$status" -eq 1 ]]
    run command -v smb4k
    [[ "$status" -eq 1 ]]
    run command -v sambda-vfs-modules
    [[ "$status" -eq 1 ]]
}

@test "New terminal session must re-prompt for sudo password" {
    # Fix by adding 'Defaults tty_tickets' to /etc/sudoers
    # if you run into complaints that your user is not in the sudoers file, you can add '<yourusername> ALL=(ALL) ALL' to the file
    # Make sure that the 'Defaults tty_tickets' is declared before the line adding your user.
    result="$(grep tty_tickets /etc/sudoers)"
    [[ ${result} =~ ^Defaults.*tty_tickets$ ]]
}

@test "Auditing is configured and active" {
    # Fix by installing auditd: `sudo apt install auditd`
    result="$(systemctl status auditd | grep Active)"
    [[ ${result} == *"Active: active (running)"* ]]
}

@test "Audit issues warning to syslog at 75 MB of space left" {
    # Fix by adding `space_left = 75` to /etc/audit/auditd.conf
    result="$(grep -c 'space_left = 75' /etc/audit/auditd.conf)"
    [[ ${result} == "1" ]]
    # Fix by adding `space_left_action = SYSLOG` to /etc/audit/auditd.conf
    result="$(grep -c 'space_left_action = SYSLOG' /etc/audit/auditd.conf)"
    [[ ${result} == "1" ]]
}

@test "Audit admin-level actions (kernel modules, etc)" {
    # Fix by adding `-w /etc/sudoers -p wa -k actions` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-w /etc/sudoers -p wa -k actions' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-w /etc/sudoers.d/ -p wa -k actions` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-w /etc/sudoers.d/ -p wa -k actions' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
}

@test "Audit access restriction enforcement" {
    # Fix by adding `-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
}

@test "Audit login/access type actions" {
    # Fix by adding `-w /var/log/tallylog -p wa -k logins` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-w /var/log/tallylog -p wa -k logins' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-w /var/run/faillock/ -p wa -k logins` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-w /var/run/faillock/ -p wa -k logins' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-w /var/log/lastlog -p wa -k logins` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-w /var/log/lastlog -p wa -k logins' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-w /var/run/utmp -p wa -k session` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-w /var/run/utmp -p wa -k session' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-w /var/log/btmp -p wa -k session` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-w /var/log/btmp -p wa -k session' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
    # Fix by adding `-w /var/log/wtmp -p wa -k session` to /etc/audit/rules.d/audit.rules
    result="$(grep -i '\-w /var/log/wtmp -p wa -k session' /etc/audit/audit.rules)"
    [[ ! -z "$result" ]]
}
