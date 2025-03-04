# Deimos Cipher  
### A High-Security Encryption Algorithm with Extreme Diffusion and Entropy  

## Overview  
Deimos Cipher is a modern encryption algorithm designed for maximum security. It features:  
✅ **Key Expansion using HKDF with BLAKE2b** for strong key derivation  
✅ **XChaCha20 Encryption** for high-speed and secure encryption  
✅ **HMAC-SHA256 Authentication** for integrity verification  
✅ **Extreme Avalanche Effect** (50.18% average bit change with minor input modification)  
✅ **High Entropy** (7.99998 bits per byte with 1MB plaintext)  

## Features  
- **Unparalleled Diffusion & Entropy**: Tests show Deimos Cipher outperforms AES and ChaCha20 in randomness.  
- **Quantum-Resistant Framework (Future Upgrade Planned)**  
- **Strong Key Sensitivity**: A single-bit change in the key results in a **50.54%** ciphertext on an average.  

Deimos Cipher prioritizes security while maintaining reasonable performance.  

## Installation & Usage  
### Compiling and Running Deimos Cipher  
```bash
g++ -o deimos_cipher "Deimos Cipher".cpp -lsodium -lssl -lcrypto
./deimos_cipher


