## TryHackMe | Mountaineer challenge

🔍 Recon

![nmap](nmap_scan.png)

![web_page](web_page.png)

![web_page](gobuster.png)

When we try to see the webpage "https://mountaineer.thm/wordpress/" it says server not found.
We need to change our /etc/hosts file with the dns

📂 Hosts File Update

We add "<ip> mountaineer.thm" to our host file

![etc_change](etc_change.png)

Then finely can we see the webpage!

![etc_change](webpage1.png)

🔐 WordPress Vulnerability Scan

![etc_change](outdated.png)

We also get a list of usernames

![etc_change](usernames.png)

🔍 More Directory Search

![etc_change](gobuster1.png)

Lets turn on BurpSuite and intercept some things, below we find this website is vulnarable to path traversal.

We can read the /etc/passwd file

![etc_change](path.png)

Here we see another domain we can use.

![etc_change](new.png)

We also find another path

![etc_change](new1.png)

📂 Hosts Update for Admin Access

We add "<ip> mountaineer.thm adminroundcubemail.mountaineer.thm" the it to our /etc/hosts file.

![etc_change](etc1.png)

Trying random logins such as user:user, k2:k2 found it was the password

![etc_change](login.png)

We find out some information about Lhotse

![etc_change](email3.png)

We find a security risk

![etc_change](email1.png)

And we find the admins credentials "th3_tall3st_password_in_th3_world"

![etc_change](email2.png)

With the credentials we find we can login at "http://mountaineer.thm/wordpress/wp-admin/"

![etc_change](wpadmin.png)

🛠️ Exploring WordPress Plugins

We can find our exploit here "https://www.exploit-db.com/exploits/50082"

And we can run it using this command

![etc_change](exploit.png)

We get a shell

![etc_change](shell.png)

After some manual digging we find "Backup.kdbx" at /home/lhotse#

We start a netcat listener on our machine to get the file:

![etc_change](attacker.png)

And on the victims side we use:

![etc_change](victim.png)

We got it

![etc_change](received.png)

📜 Generating Password Lists

Creating a wordlist with cupp

![etc_change](capp1.png)

![etc_change](capp2.png)

🔓 Cracking the Backup.kdbx File

Convert the Backup file to a has

![etc_change](bhash.png)

The cracked hash

    └─$ john keepass_hash --wordlist=mount.txt 
    Using default input encoding: UTF-8
    Loaded 1 password hash (KeePass [SHA256 AES 32/64])
    Cost 1 (iteration count) is 60000 for all loaded hashes
    Cost 2 (version) is 2 for all loaded hashes
    Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
    Will run 16 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    Lhotse56185      (Backup)     
    1g 0:00:00:13 DONE (2025-06-05 15:55) 0.07558g/s 237.0p/s 237.0c/s 237.0C/s Lhotse45..Lhotse71
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed. 

With this we can crack the backup and find the credentials for another users

![etc_change](cred2.png)

🔑 SSH Access

We have ssh access to the machine

![etc_change](ssh.png)

With this we can cat local.txt for our first flag

![etc_change](flag1.png)

📂 Analyzing Bash History

Doing some enumeration and looking at the bash history we find the password for root

![etc_change](bash.png)

We can use this to login as root, then cat local.txt and voila the challenge is done

![etc_change](flag2.png)












