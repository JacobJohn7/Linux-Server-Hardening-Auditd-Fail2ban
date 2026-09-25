# Linux Server Security Hardening (Auditd, UFW, Fail2Ban & SSH)

![Ubuntu Server](https://img.shields.io/badge/Ubuntu-Server_LTS-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Auditd](https://img.shields.io/badge/Auditd-CIS_Benchmark_Rules-brightgreen?style=for-the-badge)
![Fail2Ban](https://img.shields.io/badge/Fail2Ban-UFW_Binding-red?style=for-the-badge)
![OpenSSH](https://img.shields.io/badge/OpenSSH-Hardened-blue?style=for-the-badge&logo=openssh&logoColor=white)

Configurations, audit rules, and intrusion prevention policies implemented on an Ubuntu Server VirtualBox virtual machine (`192.168.56.106`) to establish baseline OS hardening and event auditing.

---

## 1. SSH Server Hardening (`/etc/ssh/sshd_config`)

Configured OpenSSH daemon parameters to disable root logins, enforce strict authentication attempt limits, and set idle session timeouts:

```text
Include /etc/ssh/sshd_config.d/*.conf
LogLevel INFO
LoginGraceTime 60
PermitRootLogin no
MaxAuthTries 4
MaxSessions 10
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
ClientAliveInterval 15
ClientAliveCountMax 3
```

- **`PermitRootLogin no`**: Prevents direct root account SSH authentication.
- **`MaxAuthTries 4`**: Limits failed authentication attempts per connection before terminating session.
- **`ClientAliveInterval 15`**: Sends keepalive probe every 15 seconds; disconnects after 3 missed probes (`ClientAliveCountMax 3`).

---

## 2. Stateful Host Firewall Hardening (UFW)

Enforced default-deny ingress policy and stateful rules:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default deny routed
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw enable
```

Verified rule application via `sudo ufw status verbose`:
```text
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp (SSH)               ALLOW IN    Anywhere
```

---

## 3. Intrusion Prevention & Auto-Banning (`config/jail.local`)

Installed Fail2Ban and configured custom jail settings in `/etc/fail2ban/jail.local`, binding packet drops directly to UFW (`banaction = ufw`):

```ini
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
```

### Verification & Attack Simulation
Simulated brute-force authentication attempts against `/var/log/auth.log` and verified active ban insertion:

```bash
sudo fail2ban-client status sshd
```

Output showing active banned IP:
```text
Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  `- Total failed:     5
`- Actions
   |- Currently banned: 1
   |- Total banned:     1
   `- Banned IP list:   192.168.1.100
```

---

## 4. System Auditing & CIS Rules (`config/cis-hardening.rules`)

Configured Linux Audit Daemon (`auditd`) with rules targeting identity file modification, privilege escalation attempt tracking, and system configuration edits:

```ini
# Identity & Credential File Monitoring
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity

# Sudoers & Privilege Escalation File Modifications
-w /etc/sudoers -p wa -k privilege_mod
-w /etc/sudoers.d/ -p wa -k privilege_mod

# System Environment Modifications
-w /etc/issue -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
```

Loaded rules using `sudo augenrules --load` and verified via `sudo auditctl -l`:
```text
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_mod
```

### Audit Log Inspection Commands
- Search identity modification events:
  ```bash
  sudo ausearch -k identity
  ```
- Generate summary audit report:
  ```bash
  sudo aureport --summary
  ```

---

## Setup & Tuning Notes

- **Fail2Ban + UFW Integration**: Setting `banaction = ufw` ensures Fail2Ban inserts iptables rules directly into UFW's rule chain rather than creating isolated `iptables-multiport` rules.
- **Rule Loading via `augenrules`**: On modern Ubuntu releases, edit rules in `/etc/audit/rules.d/*.rules` and execute `augenrules --load` to compile them into `/etc/audit/audit.rules`.
