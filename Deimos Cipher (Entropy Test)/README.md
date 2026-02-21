# Deimos Cipher Entropy Tests

This directory contains programs used to evaluate ciphertext entropy for Deimos Cipher.

## Available Tests

- `Deimos Cipher (Entropy Test).cpp`: interactive encryption/decryption test with entropy output.
- `Deimos Cipher (Large Data Set Entropy Test).cpp`: automated large-sample entropy averaging.
- `Deimos Cipher (Large Data Set Entropy Test).py`: Python implementation of the large-sample test.

## Build and Run C++ Tests

Run these commands from this directory:

```bash
g++ -std=c++17 -O2 -o entropy_cli "Deimos Cipher (Entropy Test).cpp" -lsodium -lssl -lcrypto -lm
./entropy_cli

g++ -std=c++17 -O2 -o entropy_large "Deimos Cipher (Large Data Set Entropy Test).cpp" -lsodium -lssl -lcrypto -lm
./entropy_large
```

## Run Python Test

```bash
pip install cryptography
python "Deimos Cipher (Large Data Set Entropy Test).py"
```
