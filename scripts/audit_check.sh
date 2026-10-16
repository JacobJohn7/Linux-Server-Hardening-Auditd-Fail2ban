#!/usr/bin/env bash
# audit_check.sh - Host Security Compliance & Hardening Verification Script
# Verifies SSH, UFW, Fail2Ban, Auditd CIS rules, and Kernel sysctl parameters

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass_count=0
fail_count=0
warn_count=0

log_pass() {
    echo -e "  [${GREEN}PASS${NC}] $1"
    pass_count=$((pass_count + 1))
}

log_fail() {
    echo -e "  [${RED}FAIL${NC}] $1"
    fail_count=$((fail_count + 1))
}

log_warn() {
    echo -e "  [${YELLOW}WARN${NC}] $1"
    warn_count=$((warn_count + 1))
}

log_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

echo "=================================================="
echo " Linux OS Baseline Security & Hardening Audit"
echo " Target Host: $(hostname -f 2>/dev/null || hostname)"
echo " Kernel: $(uname -r)"
echo " Timestamp: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo "=================================================="

# 1. SSH Hardening Audit
log_section "1. Effective SSH Daemon Configuration"
if command -v sshd >/dev/null 2>&1; then
    # Minimal containers may have no host keys, preventing sshd -T from
    # printing resolved settings. In that case, report unknown rather than
    # treating an uninspected configuration as compliant or non-compliant.
    ssh_error=""
    ssh_effective=$(sshd -T -C "user=root,host=localhost,addr=127.0.0.1" 2>&1) || ssh_error="$ssh_effective"
    if [ -n "$ssh_error" ] && ! grep -qi 'no hostkeys available' <<< "$ssh_error"; then
        log_fail "sshd configuration validation failed: ${ssh_error//$'\n'/; }"
    elif [ -z "$ssh_error" ]; then
        ssh_setting() {
            awk -v key="$1" '$1 == key { print $2; exit }' <<< "$ssh_effective"
        }

        root_login=$(ssh_setting permitrootlogin)
        if [ "$root_login" = "no" ]; then
            log_pass "PermitRootLogin is disabled (effective value: no)"
        else
            log_fail "PermitRootLogin is '$root_login' for root at localhost (expected: no)"
        fi

        max_tries=$(ssh_setting maxauthtries)
        if [[ "$max_tries" =~ ^[0-9]+$ ]] && (( max_tries >= 1 && max_tries <= 4 )); then
            log_pass "MaxAuthTries is $max_tries (maximum: 4)"
        else
            log_fail "MaxAuthTries is '$max_tries' (expected: 1-4)"
        fi

        empty_passwords=$(ssh_setting permitemptypasswords)
        if [ "$empty_passwords" = "no" ]; then
            log_pass "PermitEmptyPasswords is disabled (effective value: no)"
        else
            log_fail "PermitEmptyPasswords is '$empty_passwords' (expected: no)"
        fi

        alive_interval=$(ssh_setting clientaliveinterval)
        if [[ "$alive_interval" =~ ^[0-9]+$ ]] && (( alive_interval >= 1 && alive_interval <= 15 )); then
            log_pass "ClientAliveInterval is ${alive_interval}s (maximum: 15s)"
        else
            log_fail "ClientAliveInterval is '$alive_interval' (expected: 1-15 seconds)"
        fi

        alive_count=$(ssh_setting clientalivecountmax)
        if [[ "$alive_count" =~ ^[0-9]+$ ]] && (( alive_count >= 1 && alive_count <= 3 )); then
            log_pass "ClientAliveCountMax is $alive_count (maximum: 3)"
        else
            log_fail "ClientAliveCountMax is '$alive_count' (expected: 1-3)"
        fi
    else
        log_warn "sshd -T cannot report effective settings: host keys are unavailable"
    fi
else
    log_fail "sshd binary not found; effective SSH settings could not be validated"
fi

# 2. UFW Firewall Audit
log_section "2. Uncomplicated Firewall (UFW) Status"
if command -v ufw >/dev/null 2>&1; then
    if sudo -n ufw status 2>/dev/null | grep -q "Status: active"; then
        log_pass "UFW is active and enforcing rules"
        
        # Check default incoming policy
        if sudo -n ufw status verbose 2>/dev/null | grep -q "Default: deny (incoming)"; then
            log_pass "Default ingress policy is set to DENY"
        else
            log_warn "Default ingress policy is not strictly DENY"
        fi
    else
        log_warn "UFW is inactive or requires root credentials to inspect"
    fi
else
    log_fail "UFW binary not found"
fi

# 3. Fail2Ban Intrusion Prevention Audit
log_section "3. Fail2Ban Daemon & SSH Jail"
if command -v fail2ban-client >/dev/null 2>&1; then
    if sudo -n fail2ban-client ping 2>/dev/null | grep -q "Server replied: pong"; then
        log_pass "Fail2Ban service is running"
        
        # Inspect sshd jail
        if sudo -n fail2ban-client status sshd >/dev/null 2>&1; then
            banned_ips=$(sudo -n fail2ban-client status sshd 2>/dev/null | grep "Banned IP list" | awk -F: '{print $2}' | sed 's/^[ \t]*//')
            log_pass "sshd jail is actively monitored (Currently banned: ${banned_ips:-None})"
        else
            log_warn "sshd jail is not enabled or accessible"
        fi
    else
        log_warn "Fail2Ban daemon is stopped or requires root credentials"
    fi
else
    log_fail "Fail2Ban binary not installed"
fi

# 4. Auditd Kernel Rules Audit
log_section "4. Auditd Kernel Rules (CIS Benchmark)"
if command -v auditctl >/dev/null 2>&1; then
    active_rules=$(sudo -n auditctl -l 2>/dev/null || echo "")
    if [ -n "$active_rules" ]; then
        log_pass "Auditd is active and rules are loaded in kernel"

        # Check key watches
        echo "$active_rules" | grep -q "k identity" && log_pass "Watch rule active: identity credentials (/etc/passwd, /etc/shadow)" || log_fail "Missing audit watch: identity"
        echo "$active_rules" | grep -q "k privilege_mod" && log_pass "Watch rule active: privilege escalation (/etc/sudoers)" || log_fail "Missing audit watch: privilege_mod"
        echo "$active_rules" | grep -q "k system-locale" && log_pass "Watch rule active: system network & locale (/etc/hosts, /etc/issue)" || log_warn "Missing audit watch: system-locale"
        echo "$active_rules" | grep -q "k login-logs" && log_pass "Watch rule active: login session logs (/var/log/faillog, /var/log/lastlog)" || log_warn "Missing audit watch: login-logs"
    else
        log_warn "Auditd rule inspection requires sudo privileges or no rules loaded"
    fi
else
    log_fail "Auditd binary not installed"
fi

# 5. Kernel Network Parameter Hardening (sysctl)
log_section "5. Kernel IP Stack Hardening (sysctl)"
check_sysctl() {
    local param="$1"
    local expected="$2"
    local actual
    actual=$(sysctl -n "$param" 2>/dev/null || echo "unknown")
    if [ "$actual" = "$expected" ]; then
        log_pass "$param = $actual"
    else
        log_warn "$param = $actual (expected: $expected)"
    fi
}

check_sysctl "net.ipv4.conf.all.rp_filter" "1"
check_sysctl "net.ipv4.conf.default.rp_filter" "1"
check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
check_sysctl "net.ipv4.conf.all.accept_source_route" "0"
check_sysctl "net.ipv4.conf.all.accept_redirects" "0"
check_sysctl "net.ipv4.tcp_syncookies" "1"

# Summary Report
echo -e "\n=================================================="
echo -e " Audit Summary: ${GREEN}${pass_count} Passed${NC}, ${RED}${fail_count} Failed${NC}, ${YELLOW}${warn_count} Warnings${NC}"
echo "=================================================="
exit 0
