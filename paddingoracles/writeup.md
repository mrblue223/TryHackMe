# TryHackMe: Padding Oracles Writeup

This room explores the mechanics of **Padding Oracle Attacks**, a cryptographic vulnerability that allows an attacker to decrypt ciphertext without knowing the encryption key. It focuses on **AES-CBC** mode and how servers leaking padding error information can be exploited.

---

## 1. Introduction to Padding

In block ciphers, data is processed in fixed-size chunks (blocks). If the plaintext isn't a perfect multiple of the block size, we add **padding**.

* **1.1 In cryptography, extra bytes added to fill the remaining space in the last block during encryption or decryption is called?**
    * **Answer:** `Padding`
* **1.2 What is the byte value padded after padding the term HelloWorld?**
    * **Explanation:** `HelloWorld` is 10 bytes. In a 16-byte block (AES standard), you need 6 more bytes to fill the block. According to PKCS#7 standards, each padding byte's value is equal to the total number of padding bytes added.
    * **Answer:** `06`

---

## 2. Cipher Block Chaining (CBC)



CBC is a mode of operation where each block of plaintext is XORed with the previous ciphertext block before being encrypted. This ensures that identical plaintext blocks produce different ciphertext blocks.

* **2.1 The encryption mode in which each plaintext block is XORed with the previous ciphertext block before being encrypted is called?**
    * **Answer:** `Cipher Block Chaining`
* **2.2 What is the last byte after encrypting the word Hacker using the secret MyActualSecrets1?**
    * **Answer:** `54`

---

## 3. Decryption and Initialization Vectors (IV)

The **Initialization Vector (IV)** is a random block of data used to ensure that the first block of ciphertext is unique, even if the plaintext is the same across different sessions.

* **3.1 What is the plaintext after decrypting b1e090de4abbc8b54769ba79a98a4cffaf59a89e58bcc474794d1e8b7e5315b2 using the secret key abcdefghijklmnop?**
    * **Answer:** `THM{Encryption_007}`
* **3.2 What should the IV size be in bytes if you try decrypting a string using AES (16-byte block size)?**
    * **Answer:** `16`

---

## 4. The Padding Oracle Attack

A Padding Oracle occurs when a server tells you whether the padding of a decrypted message is correct or incorrect (e.g., via a `200 OK` vs. a `400 Bad Request`).



* **4.1 What is the flag value after decrypting the ciphertext?**
    * **Answer:** `THM-{brUt3-f0rC3}`
* **4.2 While performing a padding oracle attack, what is the expected value for the last plaintext byte if you only modify the 16th byte of the modified IV?**
    * **Answer:** `01`
* **4.3 The foundation of the padding oracle lies in the formula $P_i = D_k(C_i) \oplus C_{i-1}$. What is the missing operator?**
    * **Answer:** `Xor`

---

## 5. Practical Exploitation (PadBuster)

In this section, we use `padBuster`, a tool designed to automate the process of testing and exploiting padding oracles.

* **5.1 What is the status code shown on the page when an “Invalid padding” error occurs?**
    * **Answer:** `400`
* **5.2 What is the decrypted value (ASCII) for the ciphertext 31323334353637383930313233343536bdcc4a2319946dc9b30203d89dba9fce with a block size of 16?**
    * **Answer:** `Got_The_Flag007`

---

## 6. Security Best Practices

* **6.1 Is it a good practice to display padding errors on the production server (yea/nay)?**
    * **Answer:** `nay`
    * **Note:** Providing specific error messages allows attackers to distinguish between "Incorrect Key" and "Incorrect Padding." This "Oracle" is exactly what allows the attack to work.

---

### Summary Table

| Concept | Key Takeaway |
| :--- | :--- |
| **Padding** | Ensures data fits fixed block sizes (e.g., PKCS#7). |
| **CBC Mode** | Chains blocks together using XOR for diffusion. |
| **The Oracle** | Any side-channel (HTTP codes/timing) that reveals padding validity. |
| **Prevention** | Use Authenticated Encryption (AES-GCM) or generic error messages. |
