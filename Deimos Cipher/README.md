# Deimos Cipher CLI

This directory contains the standalone C++ command-line implementation of Deimos Cipher.

## What It Does

- Derives keys from a password with HKDF + BLAKE2b.
- Encrypts with XChaCha20.
- Authenticates ciphertext with HMAC-SHA256.
- Supports encryption and decryption from the terminal.

## Build

Run these commands from this directory:

```bash
g++ -std=c++17 -O2 -o deimos_cipher "Deimos Cipher.cpp" -lsodium -lssl -lcrypto
./deimos_cipher
```

## Usage

1. Choose `E` to encrypt or `D` to decrypt.
2. Enter plaintext or hex ciphertext based on your selection.
3. Enter the key when prompted.
4. Read the output from the terminal.
