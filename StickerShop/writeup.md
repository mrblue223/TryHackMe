# The Sticker Shop - Writeup

## Overview
**The Sticker Shop** is a web-based Capture The Flag (CTF) challenge that focuses on identifying and exploiting a **Stored Cross-Site Scripting (XSS)** vulnerability to bypass local access controls.

## Challenge Description
The sticker shop has developed a new webpage. A key detail provided in the description is that the developers host the site on the same computer they use for browsing the internet and reviewing customer feedback. The goal is to read the flag located at `http://10.81.165.16:8080/flag.txt`, which is currently inaccessible to external users.

## Vulnerability Identification
1. **Access Control Bypass**: Attempting to browse directly to `/flag.txt` results in a **401 Unauthorized** error. This suggests the server is configured to only allow requests originating from the local machine (127.0.0.1).
2. **Staff Interaction**: The shop staff reviews feedback via a browser on the same host machine.
3. **Stored XSS**: The `/submit_feedback` endpoint accepts a `feedback` parameter via a POST request. If this input is not properly sanitized before being viewed by staff, it allows for the execution of arbitrary JavaScript in the context of the local user.



## Exploitation Strategy
The attack involves three main phases:
* **Listener Setup**: Setting up a local HTTP server on a reachable interface (e.g., `tun0` at `192.168.155.45`) to catch the exfiltrated data.
* **Payload Crafting**: Creating a JavaScript payload that uses `fetch()` or `XMLHttpRequest` to read the contents of the local `/flag.txt` file.
* **Exfiltration**: Since the staff member's browser is "internal," it can successfully load the flag. The script then encodes this data (often using Base64) and sends it to the attacker's listener as a URL parameter.
* **You can receive the flag by using the script attached.

## Mitigation
To secure the application, the developers should:
* **Sanitize Inputs**: Implement strict input validation and output encoding on all user-submitted feedback to prevent script execution.
* **Content Security Policy (CSP)**: Implement a CSP to restrict where the browser can send data and prevent unauthorized script execution.
* **Least Privilege**: Ensure the web server process has minimal permissions and that sensitive files like `flag.txt` are not stored in the web root unless strictly necessary.

---
**Flag Format**: `THM{...}`
