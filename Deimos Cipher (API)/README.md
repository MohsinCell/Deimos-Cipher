# Deimos Cipher API

This directory provides a reusable C++ core implementation plus a small demo executable.

## Files

- `deimos_cipher.h`: public function declarations.
- `Deimos Cipher Core.cpp`: encryption/decryption implementation.
- `main.cpp`: interactive demo application.

## Build Demo

Run these commands from this directory:

```bash
g++ -std=c++17 -O2 -o deimos_api_demo main.cpp "Deimos Cipher Core.cpp" -lsodium -lssl -lcrypto
./deimos_api_demo
```

## Integrating Into Your Project

1. Include `deimos_cipher.h` in your source.
2. Compile and link `Deimos Cipher Core.cpp` with your code.
3. Link against `libsodium`, `libssl`, and `libcrypto`.
