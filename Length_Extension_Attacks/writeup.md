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

http://lea.thm/labs/lab1/product.php?file=<>signature>

- flag: THM{L3n6th_3Xt33ns10nssss}
