# Deimos Cipher

Deimos Cipher is an encryption project that combines HKDF (BLAKE2b), XChaCha20, and HMAC-SHA256. This repository includes a standalone CLI implementation, an API-style C++ core for integration, and entropy test suites.

## Web App

You can also use the browser application at [deimoscipher.space](https://deimoscipher.space) to encrypt and decrypt text, images, and videos directly in your browser.

## Repository Layout

- `Deimos Cipher/`: standalone CLI encryption and decryption program.
- `Deimos Cipher (API)/`: reusable C++ core with a demo `main.cpp`.
- `Deimos Cipher (Entropy Test)/`: entropy-focused C++ and Python test programs.

## Cryptographic Workflow

1. Derive internal keys from password + random salt using HKDF with BLAKE2b.
2. Encrypt plaintext with XChaCha20 keystream XOR.
3. Compute HMAC-SHA256 over encrypted payload for integrity verification.
4. Output payload as `salt | nonce | ciphertext | hmac`.

## Prerequisites

- C++17 compiler (`g++` recommended)
- OpenSSL development libraries
- libsodium
- Python 3.10+ and `cryptography` (only for the Python entropy script)

## Build and Run

### Standalone CLI

```bash
g++ -std=c++17 -O2 -o deimos_cipher "Deimos Cipher/Deimos Cipher.cpp" -lsodium -lssl -lcrypto
./deimos_cipher
```

### API Demo

```bash
g++ -std=c++17 -O2 -o deimos_api_demo "Deimos Cipher (API)/main.cpp" "Deimos Cipher (API)/Deimos Cipher Core.cpp" -lsodium -lssl -lcrypto
./deimos_api_demo
```

### Entropy Tests

```bash
g++ -std=c++17 -O2 -o entropy_cli "Deimos Cipher (Entropy Test)/Deimos Cipher (Entropy Test).cpp" -lsodium -lssl -lcrypto -lm
./entropy_cli

g++ -std=c++17 -O2 -o entropy_large "Deimos Cipher (Entropy Test)/Deimos Cipher (Large Data Set Entropy Test).cpp" -lsodium -lssl -lcrypto -lm
./entropy_large
```

For the Python entropy test:

```bash
pip install cryptography
python "Deimos Cipher (Entropy Test)/Deimos Cipher (Large Data Set Entropy Test).py"
```

## Notes

- This project is useful for experimentation and learning, but it has not been externally audited.
- Use strong secrets and secure key handling if you integrate it into a real system.
