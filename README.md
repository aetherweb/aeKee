# aeKee
Simple client-side Javascript only PBKDF2->AES->HMAC and back encryption/decryption implementation.

Makes use of, with thanks, portions of both CryptoJS and SaltThePass:

https://github.com/brix/crypto-js (used for all cryptographic functionality)

https://github.com/nicjansma/saltthepass.js (used to generate random IV)

Uses the same encryption/decryption algorithm as used at https://aekee.com for secure vaults, password generator and secure notes.

Does not use jQuery.

Runs in all modern browsers (that have been tested so far). Does not require an internet connection.

Download aekee.html and 'inc' folder and contents, maintain file structure.

Open aekee.html in a 'modern' browser. Ideally Chrome or Firefox, 2017+ version.

Initial pre-loaded ciphertext decrypts with passphrase 'aekee'.

Live demo:
https://aekee.com/ol/aekee.html


Encryption follows this protocol (decryption reverses it, decoding the HMAC first - if this fails, decryption ceases at that point.)

1. Generate a random IV using SaltThePass.

2. Perform around 10,000 iterations of PBKDF2 on the entered passphrase using the IV as a salt - number of iterations dependent partly on a simple sum of character values in the the passphrase to generate a key 'K'.

3. Split the key into two halves. Encryption Ke and Km.

4. Encrypt the plaintext with AES in CBC mode, padding with PKCS#7 using the IV, and Ke as key.

5. Concatenate the IV and encrypted data and generate a SHA-256 HMAC of this using Km as key.

6. The final output is then the concatenation of the IV, the encrypted data and the HMAC. The IV and HMAC are of known length so can easily be extracted ready for decryption when needed.

Credit to Thomas Pornin for providing the details for much of the above algorithm here:
https://security.stackexchange.com/questions/63132/when-to-use-hmac-alongside-aes



