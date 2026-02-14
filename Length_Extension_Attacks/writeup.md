## Hash Functions
- What property prevents an attacker from reversing a hash to get the original input?: Pre-image Resistance
- What property ensures that no two different messages produce the same hash?: Collision Resistance

## Hashing Internals
- What block size does SHA-256 use?: 512
- What function ensures data is aligned to fit block size requirements?: Padding
- How many words does SHA-256’s internal state have?: 8 

## Understanding Length Extension Attacks
- What hashing method prevents length extension attacks by using a secret key?: HMAC

## Practical - Attacking Signatures
    python3 script1.py 
    --- ATTEMPT FOR SECRET LENGTH 8 ---
    Signature: a9f7878a39b10d0a9d3d1765d3e83dd34b0b0242fa7e1567f085a5a9c467337a
    File Parameter: %31%2e%70%6e%67%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%68%2f%2e%2e%2f%34%2e%70%6e%67

Visit the link with the new signature

    http://lea.thm/labs/lab1/product.php?file=<>signature>

- flag: THM{L3n6th_3Xt33ns10nssss}

## Practical - Modifying a Signed Cookie
    python3 script2.py 
    hsh (Signature): daf3dbdc47fd93fabe110ef0ed58a39d1eb59c234a7fd66d0fe2e1dd76f1e37f
    auth (Cookie Data):   %75%73%65%72%6e%61%6d%65%3d%75%73%65%72%3b%72%6f%6c%65%3d%30%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%e0%3b%72%6f%6c%65%3d%31

Inspect the page and changes the respecting values with the payloads the script provides and refresh
the page.

- flag: THM{l3n6th_2_4dM1n}

