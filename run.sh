#!/usr/bin/env bats -p
#
# (c) 2019 ZibaSec Inc
#
# Audits a MacOS/Linux System for sane security defaults
#

if [[ `whoami` != "root" ]]; then
  echo "Must run with sudo or as root" >&2
  exit 1
fi

@test "FireVault is enabled" {
  # Mac OS 10.15 Enable via System Preferences > Security & Privacy
  result="$(fdesetup status)"
  [[ ${result} == "FileVault is On." ]]
}

@test "Firewall is enabled" {
  # Mac OS 10.15 Enable via System Preferences > Security & Privacy
  result="$(defaults read /Library/Preferences/com.apple.alf globalstate)"
  [[ ${result} -eq 1 ]]
}

@test "FTP is disabled" {
  # Fix via `sudo launchctl disable system/com.apple.ftpd`
  result="$(launchctl print-disabled system | /usr/bin/grep com.apple.ftpd)"
  [[ ${result} == *"\"com.apple.ftpd\" => true"* ]]
}

@test "Telnet is disabled" {
  # Fix via `sudo launchctl disable system/com.apple.telnetd`
  result="$(launchctl print-disabled system | /usr/bin/grep com.apple.telnetd)"
  [[ ${result} == *"\"com.apple.telnetd\" => true"* ]]
}

@test "rshd is disabled" {
  # Fix via `sudo launchctl disable system/com.apple.rshd`
  result="$(launchctl print-disabled system | /usr/bin/grep com.apple.rshd)"
  [[ ${result} == *"\"com.apple.rshd\" => true"* ]]
}

@test "SSHD is disabled" {
  # Fix via `sudo launchctl disable system/com.openssh.sshd`
  result="$(launchctl print-disabled system | /usr/bin/grep com.openssh.sshd)"
  [[ ${result} == *"\"com.openssh.sshd\" => true"* ]]
}

@test "tftp is disabled" {
  # Fix via `sudo launchctl disable system/com.apple.tftp`
  result="$(launchctl print-disabled system | /usr/bin/grep com.apple.tftp)"
  [[ ${result} == *"\"com.apple.tftp\" => true"* ]]
}

@test "smb is disabled" {
  # Fix via `sudo launchctl disable system/com.apple.smbd`
  result="$(launchctl print-disabled system | /usr/bin/grep com.apple.smbd)"
  [[ ${result} == *"\"com.apple.smbd\" => true"* ]]
}

@test "Apple File Server is disabled" {
  # Fix via `sudo launchctl disable system/com.apple.AppleFileServer`
  result="$(launchctl print-disabled system | /usr/bin/grep com.apple.AppleFileServer)"
  [[ ${result} == *"\"com.apple.AppleFileServer\" => true"* ]]
}

@test "MacOS-native Screen Sharing is disabled" {
  # Fix via `sudo launchctl disable system/com.apple.screensharing`
  result="$(launchctl print-disabled system | /usr/bin/grep com.apple.screensharing)"
  [[ ${result} == *"\"com.apple.screensharing\" => true"* ]]
}

@test "Security Assessment Subsystem Enabled" {
  # Fix via `sudo spctl --master-enable`
  result="$(spctl --status)"
  [[ ${result} == "assessments enabled" ]]
}

@test "New terminal session must re-prompt for sudo password" {
  # Fix by adding 'Defaults tty_tickets' to /etc/sudoers
  # if you run into complaints that your user is not in the sudoers file, you can add '<yourusername> ALL=(ALL) ALL' to the file
  # Make sure that the 'Defaults tty_tickets' is declared before the line adding your user.
  result="$(grep tty_tickets /etc/sudoers)"
  [[ ${result} =~ ^Defaults.*tty_tickets$ ]]
}

@test "Audit admin-level actions (kernel modules, etc)" {
  # Fix via `sudo sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; sudo audit -s`
  result="$(grep ^flags /etc/security/audit_control)"
  [[ ${result} == *"ad"* ]]
}

@test "Audit access restriction enforcement" {
  # Fix via `sudo /usr/bin/sed -i.bak '/^flags/ s/$/,fm,-fr,-fw/' /etc/security/audit_control; sudo audit -s`
  result="$(grep ^flags /etc/security/audit_control)"
  [[ ${result} =~ ^.*fm.*-fr.*-fw.*$ ]]
}

@test "Audit login/access type actions" {
  # Fix via `sudo /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s`
  result="$(grep ^flags /etc/security/audit_control)"
  [[ ${result} == *"aa"* ]]
}

@test "Audit logger must log to syslogd" {
  # Fix via `sudo sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; sudo audit -s`
  result="$(grep logger /etc/security/audit_warn)"
  [[ ${result} == *"-s"* ]]
}

@test "Set disk space warning to 25% with regards to audit logs" {
  # Fix via `sudo sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; sudo audit -s`
  result="$(grep ^minfree /etc/security/audit_control)"
  [[ ${result} == "minfree:25" ]]
}

@test "Infrared [IR] support disabled" {
  # Fix via `sudo /usr/bin/defaults write /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled -bool FALSE`
  result="$(defaults read /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled)"
    [[ ${result} -eq 0 ]]
}