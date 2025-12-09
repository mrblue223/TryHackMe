# 🏆 TryHackMe Room Writeup: Rick and Morty (Assumed Room Name)

This writeup details the steps taken to enumerate and exploit the target system to find the flags, which represent the secret ingredients.
# 1. Enumeration

The initial step involved running an aggressive Nmap scan to discover open ports and running services on the target IP address, 10.80.159.255.

Nmap Scan Results

The scan revealed two open TCP ports:

Port	State	Service	Version	Details
22/tcp	open	ssh	

OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)

	The SSH service is running, indicating a potential way to gain a shell.
80/tcp	open	http	

Apache httpd 2.4.41 ((Ubuntu))

	An HTTP web server is running.

The scan also identified the operating system as Linux 4.15.

Web Enumeration (Port 80)

    Checking the Root Page:

        Visiting the IP address 10.80.159.255 showed the page title: "Rick is sup4r cool".

This is confirmed by the http-title script output in the Nmap scan.

Directory Brute-Forcing:

    A directory brute-forcing tool (like FeroxBuster) was used to discover hidden files and directories on the web server.

The scan discovered several interesting paths, including:

    /login.php (HTTP 200) 

/portal.php (HTTP 302 Redirect, likely after login)

/denied.php (HTTP 302 Redirect, likely authentication failure)

/assets (Directory)

/index.html (HTTP 200)

    Source Code/File Analysis for Clues:

        The file robots.txt was likely checked (though not explicitly in the scan output, it's a standard enumeration step) and a string was found: "Wubbalubbadubdub".

        Static analysis of the web page source code revealed a hidden HTML comment containing a potential username: "R1ckRul3s".

# 2. Initial Access

The discovered username and string were tested against the /login.php portal as potential credentials.

    Username: R1ckRul3s (static analysis of web page)

    Password: Wubbalubbadubdub (robots.txt)

These credentials successfully granted access to the web portal.
# 3. Finding the Flags (Ingredients)

Gaining access provided the first hint about the secret ingredient: "less Sup3rS3cretPickl3Ingred.txt".

## Flag 1: The First Ingredient

After finding and reading the file mentioned in the clue, the first ingredient (Flag 1) was revealed:

    mr. meeseek hair

## Flag 2: The Second Ingredient

The next clue was to "Look around the file system for the other ingredient". Enumerating the home directory of the user rick (/home/rick) revealed a file named second ingredients.

Reading this file (less /home/rick/second\ ingredients) revealed the second ingredient (Flag 2):

    1 jerry tear

## Flag 3: The Third Ingredient

The final flag required elevated privileges. The user had sudo access, which was leveraged to find the third ingredient.

    List the contents of the /root directory using sudo: sudo ls /root.

    This revealed the file 3rd.txt.

    Read the file using sudo: sudo less /root/3rd.txt.

The third ingredient (Flag 3) was found within 3rd.txt:

    3rd ingredients: fleeb juice

# Summary of Ingredients (Flags)
Ingredient #	File Location	Flag/Ingredient
1	Sup3rS3cretPickl3Ingred.txt	mr. meeseek hair
2	/home/rick/second ingredients	1 jerry tear
3	/root/3rd.txt	fleeb juice