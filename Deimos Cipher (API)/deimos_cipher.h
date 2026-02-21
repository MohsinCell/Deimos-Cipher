#ifndef DEIMOS_CIPHER_H
#define DEIMOS_CIPHER_H

#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sodium.h>

std::array<std::vector<uint8_t>, 3> deriveKeysHKDF(const std::string& password, const std::vector<uint8_t>& salt);

std::vector<uint8_t> generateHMAC(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

std::vector<uint8_t> deimosCipherEncrypt(const std::string& plaintext, const std::string& password);

std::string deimosCipherDecrypt(const std::vector<uint8_t>& ciphertext, const std::string& password);

#endif
