# Breaking Crypto the Simple Way — Writeup

This repository contains a detailed walkthrough and notes for the "Breaking Crypto the Simple Way" room. This room explores common cryptographic implementation errors, demonstrating that even strong algorithms like AES and RSA can be bypassed if configured incorrectly.
## Task 2: Brute-forcing Keys (RSA Factorization)

RSA security relies on the mathematical difficulty of factoring a large modulus n into two primes, p and q. If n is small or primes are weakly generated, the private key can be recovered.
Steps

    Identify Vulnerability: The modulus n provided is a product of weak primes.

    Factoring: Use the RSA_Factor_Cracker.py script to query FactorDB and retrieve the primes p and q.

    Decryption:

        The script calculates the totient ϕ(n) by multiplying (p−1) for each factor found: ϕ(n)=(p−1)(q−1).

        It derives the private exponent d using the modular inverse of e(modϕ(n)).

        It decrypts the ciphertext using the formula: m=cd(modn).

Terminal Output

python RSA_Factor_Cracker.py

[] Target Modulus (n): 43941819371451617899...29466519309346255747
[] Contacting FactorDB...
[+] Found 2 factors!

==============================
CRACKED FLAG: THM{Psssss_4nd_Qsssssss}
## Task 3: Breaking Hashes (HMAC-SHA1)

HMAC-SHA1 combines a hash function with a secret key. If the key is weak (e.g., a common dictionary word), it can be cracked via brute force.
Steps

    Prepare Hash File:
    echo "1484c3a5d65a55d70984b4d10b1884bda8876c1d:CanYouGuessMySecret" > digest.txt

    Run Hashcat: Use Mode 150 (HMAC-SHA1) and the rockyou.txt wordlist.
    hashcat -a 0 -m 150 digest.txt /usr/share/wordlists/rockyou.txt

Result: The cracked key is revealed as sunshine.
## Task 4: Exposed Keys

Hardcoding keys in client-side code allows attackers to recreate the encryption process or forge valid data.
Steps

    Source Code Inspection: The application uses a hardcoded 16-byte AES key: 1234567890123456.

    Brute Force: Use Exposed_keys.py to iterate through a custom wordlist (wordlist.txt).

    Exploitation: The script encrypts each word using AES-CBC with a random IV and sends the payload to the server until "Access granted!" is received.

Terminal Output

python3 Exposed_keys.py

Trying: ankhzljjgu
Response: Access granted! Here's your flag: THM{3nD_2_3nd_is_n0t_c0mpl1c4ted}
[+] Found the correct message: ankhzljjgu
## Task 5: Bit Flipping Attacks

Unauthenticated encryption like AES-CBC does not verify data integrity. Attackers can modify ciphertext to predictably change the decrypted plaintext.
Steps

    Analyze Cookie: The role cookie represents an encrypted 0.

    The Bit Flip: XORing a byte in the Initialization Vector (IV) results in the same XOR difference in the decrypted plaintext.

        ASCII '0' is 0x30, '1' is 0x31. The XOR difference is 0x01.

    Exploit:

        Run python3 bit_flip.py <current_cookie_hex>.

        The script XORs the byte at the target offset (offset 0) with 0x01.

        Update the cookie in your browser with the modified token and refresh the page.

Terminal Output

python3 exploit.py <hex_token>

[] Original Token: 7849cb8841a6aae29558b99a4dd1611580e7f1f78883d21deb364b39821bbcbaff0db0053caffe029d4e9fd68e2050a0
[] Flipping bit at offset 0...

==============================
MODIFIED TOKEN: 7949cb8841a6aae29558b99a4dd1611580e7f1f78883d21deb364b39821bbcbaff0db0053caffe029d4e9fd68e2050a0
Flag: THM{flip_n_flip}



