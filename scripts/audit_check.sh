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
log_section "1. SSH Daemon Configuration (/etc/ssh/sshd_config)"
if [ -r /etc/ssh/sshd_config ]; then
    # Check PermitRootLogin
    if grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+no' /etc/ssh/sshd_config; then
        log_pass "PermitRootLogin is explicitly disabled"
    else
        log_fail "PermitRootLogin is not set to 'no'"
    fi

    # Check MaxAuthTries <= 4
    max_tries=$(grep -E '^[[:space:]]*MaxAuthTries' /etc/ssh/sshd_config | awk '{print $2}' || echo "unconfigured")
    if [ "$max_tries" != "unconfigured" ] && [ "$max_tries" -le 4 ]; then
        log_pass "MaxAuthTries set to $max_tries (<= 4)"
    else
        log_fail "MaxAuthTries ($max_tries) exceeds CIS recommendation (<= 4)"
    fi

    # Check PermitEmptyPasswords
    if grep -Eq '^[[:space:]]*PermitEmptyPasswords[[:space:]]+no' /etc/ssh/sshd_config; then
        log_pass "PermitEmptyPasswords is explicitly set to 'no'"
    else
        log_fail "PermitEmptyPasswords is not set to 'no'"
    fi

    # Check ClientAliveInterval
    if grep -Eq '^[[:space:]]*ClientAliveInterval[[:space:]]+1[0-9]{1,2}' /etc/ssh/sshd_config; then
        log_pass "ClientAliveInterval configured with active timeout"
    else
        log_warn "ClientAliveInterval not set or exceeds recommended threshold"
    fi
else
    log_fail "Cannot read /etc/ssh/sshd_config (permission denied or missing)"
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
