#!/bin/bash
# audit_check.sh - Verification script for Linux Server Hardening Controls
# Author: Jacob John

echo "=================================================="
echo " Linux Security Hardening Audit Summary"
echo "=================================================="

echo ""
echo "[+] 1. Checking SSH Hardening Parameters:"
grep -E "PermitRootLogin|MaxAuthTries|PermitEmptyPasswords|ClientAliveInterval" /etc/ssh/sshd_config 2>/dev/null || echo "[!] Could not read sshd_config"

echo ""
echo "[+] 2. Checking UFW Firewall Status:"
sudo ufw status verbose 2>/dev/null || echo "[!] UFW status requires root privileges"

echo ""
echo "[+] 3. Checking Fail2Ban Jail Status (sshd):"
sudo fail2ban-client status sshd 2>/dev/null || echo "[!] Fail2Ban status requires root privileges"

echo ""
echo "[+] 4. Checking Active Auditd Rules (identity/privilege):"
sudo auditctl -l 2>/dev/null | grep -E "identity|privilege" || echo "[!] Auditd status requires root privileges"

echo ""
echo "=================================================="
echo "[+] Security Audit Inspection Complete."
