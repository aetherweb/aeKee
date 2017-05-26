# aeKee
Simple client-side Javascript only PBKDF2->AES->HMAC and back encryption/decryption implementation.

Makes use of, with thanks, portions of both CryptoJS and SaltThePass:

https://github.com/brix/crypto-js

https://github.com/nicjansma/saltthepass.js/tree/master

Uses the same encryption/decryption algorithm as used at https://aekee.com for secure vaults, password generator and secure notes.

Does not use jQuery.

Runs in all modern browsers.

Download aekee.html and 'inc' folder and contents, maintain file structure.

Open aekee.html in a 'modern' browser. Ideally Chrome or Firefox, 2017+ version.

Initial pre-loaded ciphertext decrypts with passphrase 'aekee'.

Live demo:
https://aekee.com/ol/aekee.html
