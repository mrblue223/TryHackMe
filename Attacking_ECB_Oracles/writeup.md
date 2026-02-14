## Introduction
No anwser needed

## Symmetric Encryption
In what year did NIST hold a competition to find a new encryption algorithm that correctly implemented the three fundamental rules of cryptography?: 1997
- What is the AES cipher otherwise known as?: Rijdael Cipher
- What type of encryption is AES? (Symmetric/Asymmetric): Symmetric

## Code Books and Cipher Modes
- AES is a cipher block which means that the text will be broken down into fixed-sized blocks to be converted into ciphertext.
- What is used when the last AES block of the original message isn't completely filled?: padding
- What is the ciphertext when encrypting the message CryptographyAndADreamToSecurity using the secret NotAGreatSecret!?: c35a97106295a3101b6be8a9af954d198462b30f0af7f669d46766cbeea7eabf
 
## ECB Insecurities
- What types of files are notoriously difficult for ECB to encrypt?: diffusion
- What type of files are notoriously difficult for ECB to encrypt: images

## Chosen-Plaintext attack
    ─$ python3 script2.py 
    --- Initializing Attack ---
    [+] Block Size: 16
    [+] Offset: 11
    
    --- Recovering Secret ---
    Current Progress: O
    Current Progress: Or
    Current Progress: Ora
    Current Progress: Orac
    Current Progress: Oracl
    Current Progress: Oracle
    Current Progress: OracleK
    Current Progress: OracleKn
    Current Progress: OracleKno
    Current Progress: OracleKnow
    Current Progress: OracleKnows
    [!] No more characters detected.
    
    [FINAL SECRET]: OracleKnows

## Cipher Mode Best Practices (copy pasted)
Pentesters

If you see an ECB implementation, you should raise alarm bells. This might sound silly, but it has been found in the wild in cases as late as 2022! Sometimes, you may have to enumerate to determine if ECB is being used. As shown in this room, a good way to determine this is to use raw image data, which can often show recognisable patterns in the ciphertext. Furthermore, if you find an ECB oracle that accepts input data from you, you can stage an attack to recover additional and potentially sensitive plaintext data.
Mitigation Measures for Secure Coders

For developers, it is critical to ensure they are not using insecure cipher modes, such as ECB. Instead, cipher modes such as AES-GCM or AES-CCM should be used, especially when the ciphertext is calculated using user-provided data, and the output will be returned to the end user.
Conclusion

We focused on symmetric encryption throughout this room and explained how block ciphers worked. We explained how a secure encryption algorithm such as AES can be insecurely implemented if an outdated and vulnerable cipher mode is used. We highlighted the insecurities of ECB, how it is possible to determine when it is being used, and how an ECB oracle can be attacked to uncover potentially sensitive information.

We hope you enjoyed this room and found it insightful. Let us know through our Discord channel or X account if you have any feedback or thoughts. See you around.
