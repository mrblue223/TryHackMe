# JWT Vulnerability Exploits

This repository contains a series of Python scripts designed to demonstrate and exploit common JSON Web Token (JWT) vulnerabilities. These scripts are intended for educational and defensive security testing purposes only.

**Note:** Each script is configured to attack a dummy environment (defaulting to `http://10.64.168.127`) and should only be run against environments you own or have explicit permission to test.

## Prerequisites

* Python 3.x
* The `requests` library: `pip install requests`
* **For `script4.py` (Weak Secret):** You will also need [Hashcat](https://hashcat.net/hashcat/) and a wordlist (e.g., `jwt.secrets.list`).

---

## The Scripts

The following table summarizes the purpose and usage of each exploitation script.

| Script | Vulnerability | Description | Usage |
| :--- | :--- | :--- | :--- |
| **`script1.py`** | **Sensitive Information Disclosure** | The JWT payload contains sensitive or unnecessary information (like a `flag` or secret data). The script simply decodes the payload to extract the data. 

[Image of JWT structure]
 | `python3 script1.py [target_ip]` |
| **`script2.py`** | **No Signature Verification (Insecure Server Logic)** | The server is vulnerable to accepting tokens that have the signature component removed (i.e., `Header.Payload.`). The script modifies the payload for privilege escalation (`"admin": 1`) and sends the token with an empty signature. | `python3 script2.py [target_ip]` |
| **`script3.py`** | **Algorithm Confusion (`alg: None`)** | The server checks the `alg` claim in the header and, if it is set to `"None"`, skips signature verification entirely. The script modifies the token header to set `alg` to `None`, modifies the payload for privilege escalation, and removes the signature. | The target IP and initial token are hardcoded. Run directly: `python3 script3.py` |
| **`script4.py`** | **Weak Signing Secret** | The server uses a weak, easily guessable secret key (`"secret"` in this scenario) for HS256 signing. This requires an external brute-forcing step. | **1. Extract JWT:** Run the script, which saves the base JWT to `jwt.txt`.<br>**2. Crack Secret (External):** Use Hashcat on the `jwt.txt` file (mode `-m 16500`).<br>**3. Exploit:** The script then automatically uses the cracked secret to forge an admin token and retrieve the flag. |
| **`script5.py`** | **`HS256` key Reused as `RS256` Public Key** | This attack exploits a common flaw where a server using an `RS256` (asymmetric) key can be tricked into using an `HS256` (symmetric) algorithm, re-using its own public key as the secret key. The script retrieves the public key, uses it to sign a malicious HS256 token, and sends it.  | `python3 script5.py [target_ip]` |
| **`script6.py`** | **Permanent (No Expiry) Token** | This script demonstrates an application that issues a token with no expiration claim (`exp`), resulting in a "permanent" session token. The provided exploit uses a pre-forged, permanent token to gain access. | `python3 script6.py [target_ip]` |
| **`scrip7.py`** | **Cross-Service Relay (Incorrect `aud` Check)** | The server fails to properly validate the `aud` (Audience) claim. The script authenticates to a secondary application (App B) that grants an admin token for *itself*, then relays that token to the vulnerable target application (App A), which accepts it despite the audience mismatch. | The script will prompt for the target IP: `python3 scrip7.py` |

---

## Usage Example

To run any script (e.g., `script1.py`) against a target IP:
python3 [script] 
# Example against a specific IP
python3 script1.py 192.168.1.100
