#ifndef deimos_cipher
#define deimos_cipher

#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sodium.h>

// Key Expansion using HKDF with BLAKE2b
std::array<std::vector<uint8_t>, 3> deriveKeysHKDF(const std::string& password, const std::vector<uint8_t>& salt);

// HMAC Generation (SHA-256)
std::vector<uint8_t> generateHMAC(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

// Mars Cipher Encryption
std::vector<uint8_t> deimosCipherEncrypt(const std::string& plaintext, const std::string& password);

// Mars Cipher Decryption
std::string deimosCipherDecrypt(const std::vector<uint8_t>& ciphertext, const std::string& password);

#endif 
