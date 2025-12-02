# JWT Vulnerability Exploits

This repository contains a series of Python scripts designed to demonstrate and exploit common JSON Web Token (JWT) vulnerabilities. These scripts are intended for **educational and defensive security testing purposes only**.

A JWT consists of three base64URL-encoded parts: Header, Payload, and Signature. Exploits often target the validation logic or the confidentiality of these components.


**Disclaimer:** All scripts default to attacking a dummy environment (`http://10.64.168.127`) and **must only** be run against environments you own or have explicit permission to test.

## Prerequisites

* Python 3.x
* The `requests` library: `pip install requests`
* **For `script4.py` (Weak Secret):** You will need [Hashcat](https://hashcat.net/hashcat/) (for brute-forcing the secret) and a wordlist (e.g., `jwt.secrets.list`).

---

## The Scripts

The table below summarizes the vulnerability exploited by each script, its mechanism, and execution instructions.

| Script | Vulnerability | Mechanism of Attack | Usage |
| :--- | :--- | :--- | :--- |
| **`script1.py`** | **Sensitive Information Disclosure** | The script authenticates, retrieves the token, and base64-decodes the payload to extract sensitive information (like an internal flag) improperly stored within the JWT claims. | `python3 script1.py [target_ip]` |
| **`script2.py`** | **No Signature Verification** | The script modifies the token payload (e.g., setting `"admin": 1`) and completely removes the signature component. The server's weak logic accepts the token without verifying the signature. | `python3 script2.py [target_ip]` |
| **`script3.py`** | **Algorithm Confusion (`alg: None`)** | The script sets the JWT header's `alg` claim to `"None"` and removes the signature. The server is tricked into skipping verification entirely, allowing arbitrary payload modification.  | The target IP and initial token are hardcoded. Run directly: `python3 script3.py` |
| **`script4.py`** | **Weak Signing Secret (HS256)** | **1. Cracking:** The token is saved to a file (`jwt.txt`) for brute-forcing the weak secret key using Hashcat (`-m 16500`).<br>**2. Forging:** The script then uses the cracked secret to sign a malicious token with escalated privileges (`"admin": 1`). | **Requires Hashcat setup.** Run the script, follow instructions to crack, then the script finishes the exploit. |
| **`script5.py`** | **HS256 Key Reused as RS256 Public Key** | This attack exploits a server that uses an asymmetric `RS256` key but can be confused into verifying a symmetric `HS256` token. The script retrieves the server's public key and uses it as the symmetric secret to forge a valid `HS256` admin token.  | `python3 script5.py [target_ip]` |
| **`script6.py`** | **Permanent Token (No Expiry Claim)** | Demonstrates an application flaw where tokens lack the `exp` (expiration) claim, resulting in session tokens that never expire. The exploit uses a pre-forged, permanent admin token to gain access. | `python3 script6.py [target_ip]` |
| **`scrip7.py`** | **Cross-Service Relay (Incorrect `aud` Check)** | The script authenticates to a secondary application (App B) to get a token with `aud: 'appB'`. It then relays this token to the vulnerable target (App A), which accepts it because it fails to validate the `aud` (Audience) claim. | The script will prompt for the target IP: `python3 scrip7.py` |
