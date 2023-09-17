# PasswordManager

A simple command-line password manager I made with C++. Libraries used are [libsodium](https://doc.libsodium.org/) and [crypto++](https://www.cryptopp.com/) for encryption. This password manager is intended for learning purposes and not actual use.

Master password is encrypted using SHA-256 with crypto++, and passwords are encryted using key derivation and authenticated encryption using libsodium. An encrypted password, nonce and encrypted password length (no padding) is stored within every entry. Given a key (produced from a confidential salt, and a confidential hashed master password, both stored locally), the password can be freely encrypted and decrypted.
