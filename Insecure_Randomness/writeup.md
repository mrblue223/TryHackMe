# TryHackMe: Insecure Randomness Writeup

Insecure randomness occurs when applications use predictable or poorly generated values for security-sensitive operations. This room covers the transition from fundamental theory to practical exploitation and mitigation.

---

## Task 1: Introduction
Randomness is essential for securing tokens, session IDs, and cryptographic keys. When implemented poorly, it allows attackers to:
* Bypass authentication
* Hijack sessions
* Decrypt sensitive data

---

## Task 2: Key Concepts

### Randomness & Entropy
* **Randomness:** The lack of pattern or predictability.
* **Entropy:** Measures the amount of uncertainty in a system. High entropy equals high security.
* **Cryptographic Keys:** Secret values whose strength depends on length and randomness.



**Questions:**
* **2.1 What measures the amount of randomness or unpredictability in a system?**
    * **Answer:** `Entropy`
* **2.2 Is it a good practice to keep the same seed value for all cryptographic functions? (yea/nay)**
    * **Answer:** `nay`

---

## Task 3: Types of Random Number Generators

| Type | Source | Use Case | Speed |
| :--- | :--- | :--- | :--- |
| **TRNG** | Physical phenomena (Thermal noise) | RSA Keys, Certificates | Slower |
| **PRNG** | Mathematical algorithms (Seeds) | Simulations, Gaming | Faster |

**Questions:**
* **3.1 You prepare a game involving immediate interaction... but with no critical security requirements. Which type of RNG would be most appropriate?**
    * **Answer:** `B` (Statistical PRNG)

---

## Task 4: Weak or Insufficient Entropy
When entropy sources (like system clocks) are predictable, the complexity of finding a key is significantly reduced.



**Questions:**
* **4.1 What is the flag value after logging in as the victim user?**
    * **Answer:** `THM{VICTIM_SIGNED_IN}`
* **4.2 What is the flag value after logging in as the master user?**
    * **Answer:** `THM{ADMIN_SIGNED_IN007}`
* **4.3 What is the PHP function used to create the token variable in the code above?**
    * **Answer:** `time()`

---

## Task 5: Predictable Seed in PRNGs
If an attacker knows the seed (like a timestamp), they can replicate the entire sequence of "random" numbers. This is often used to bypass CAPTCHAs or manipulate lottery outcomes.

**Questions:**
* **5.1 What is the flag value after logging in as magic@mail.random.thm?**
    * **Answer:** `THM{MAGIC_SIGNED_IN11010}`
* **5.2 What is the flag value after logging in as hr@mail.random.thm?**
    * **Answer:** `THM{HR_SIGNED_IN_9910}`
* **5.3 What is the PHP function used to seed the RNG in the code above?**
    * **Answer:** `mt_srand`

---

## Task 6: Mitigation Measures

### For Pentesters:
* Look for weak functions like `mt_rand()` or `rand()`.
* Use tools like `php_mt_seed` to reverse-engineer tokens.

### For Developers:
* **Use CSPRNGs:** Use `random_bytes()` or `openssl_random_pseudo_bytes()`.
* **Avoid Weak Seeds:** Never use Timestamps, IP addresses, or PIDs.
* **Freshness:** Regenerate randomness for every critical operation.

**Questions:**
* **6.1 Which of the following can be considered as a weak seed value?**
    * **Answer:** `D` (All of the above)

---

## Task 7: Conclusion
Securing randomness is about ensuring that the "unpredictable" actually stays unpredictable. By using high-entropy sources and Cryptographically Secure PRNGs, we prevent most of the attacks demonstrated in this room.
