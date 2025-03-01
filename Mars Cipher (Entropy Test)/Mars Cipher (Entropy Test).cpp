#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <cmath>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sodium.h>
#include <cstring>

// Key Expansion using HKDF (BLAKE2b)
std::array<std::vector<uint8_t>, 3> deriveKeysHKDF(const std::string& password, const std::vector<uint8_t>& salt) {
    std::array<std::vector<uint8_t>, 3> keys;
    std::vector<uint8_t> prk(128);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_blake2b512());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size());
    EVP_PKEY_CTX_set1_hkdf_key(pctx, reinterpret_cast<const unsigned char*>(password.data()), password.size());
    EVP_PKEY_derive(pctx, prk.data(), nullptr);
    EVP_PKEY_CTX_free(pctx);

    for (int i = 0; i < 3; ++i) {
        keys[i].resize(32);
        std::vector<uint8_t> info = {'K', 'E', 'Y', static_cast<uint8_t>(i)};
        
        EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        EVP_PKEY_derive_init(key_ctx);
        EVP_PKEY_CTX_set_hkdf_md(key_ctx, EVP_blake2b512());
        EVP_PKEY_CTX_set1_hkdf_salt(key_ctx, salt.data(), salt.size());
        EVP_PKEY_CTX_set1_hkdf_key(key_ctx, prk.data(), prk.size());
        EVP_PKEY_CTX_add1_hkdf_info(key_ctx, info.data(), info.size());

        EVP_PKEY_derive(key_ctx, keys[i].data(), nullptr);
        EVP_PKEY_CTX_free(key_ctx);
    }

    return keys;
}

// Generate HMAC (SHA-256)
std::vector<uint8_t> generateHMAC(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> hmac(SHA256_DIGEST_LENGTH);
    unsigned int len = SHA256_DIGEST_LENGTH;
    HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), hmac.data(), &len);
    hmac.resize(len);
    return hmac;
}

// Mars Cipher Encryption
std::vector<uint8_t> marsCipherEncrypt(const std::string& plaintext, const std::string& password) {
    std::vector<uint8_t> salt(32);
    randombytes_buf(salt.data(), salt.size());

    auto keys = deriveKeysHKDF(password, salt);
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());

    unsigned char nonce[crypto_stream_xchacha20_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<uint8_t> keystream(plaintextVec.size());
    crypto_stream_xchacha20(keystream.data(), keystream.size(), nonce, keys[0].data());

    for (size_t i = 0; i < plaintextVec.size(); ++i) {
        plaintextVec[i] ^= keystream[i];
        plaintextVec[i] = (plaintextVec[i] + 37) ^ 23;  // Nonlinear mixing
    }

    std::vector<uint8_t> hmac = generateHMAC(plaintextVec, keys[2]);

    std::vector<uint8_t> ciphertext;
    ciphertext.insert(ciphertext.end(), salt.begin(), salt.end());
    ciphertext.insert(ciphertext.end(), nonce, nonce + crypto_stream_xchacha20_NONCEBYTES);
    ciphertext.insert(ciphertext.end(), plaintextVec.begin(), plaintextVec.end());
    ciphertext.insert(ciphertext.end(), hmac.begin(), hmac.end());

    return ciphertext;
}

// Mars Cipher Decryption
std::string marsCipherDecrypt(const std::vector<uint8_t>& ciphertext, const std::string& password) {
    if (ciphertext.size() < 32 + crypto_stream_xchacha20_NONCEBYTES + SHA256_DIGEST_LENGTH) {
        return "Error: Ciphertext too short!";
    }

    std::vector<uint8_t> salt(ciphertext.begin(), ciphertext.begin() + 32);
    unsigned char nonce[crypto_stream_xchacha20_NONCEBYTES];
    std::memcpy(nonce, ciphertext.data() + 32, crypto_stream_xchacha20_NONCEBYTES);

    std::vector<uint8_t> encryptedData(ciphertext.begin() + 32 + crypto_stream_xchacha20_NONCEBYTES, 
                                       ciphertext.end() - SHA256_DIGEST_LENGTH);
    std::vector<uint8_t> receivedHMAC(ciphertext.end() - SHA256_DIGEST_LENGTH, ciphertext.end());

    auto keys = deriveKeysHKDF(password, salt);
    std::vector<uint8_t> calculatedHMAC = generateHMAC(encryptedData, keys[2]);

    if (!std::equal(receivedHMAC.begin(), receivedHMAC.end(), calculatedHMAC.begin())) {
        return "Error: Integrity check failed!";
    }

    std::vector<uint8_t> keystream(encryptedData.size());
    crypto_stream_xchacha20(keystream.data(), keystream.size(), nonce, keys[0].data());

    for (size_t i = 0; i < encryptedData.size(); ++i) {
        encryptedData[i] = (encryptedData[i] ^ 23) - 37;  // 🔥 Reverse nonlinear mixing
        encryptedData[i] ^= keystream[i];
    }

    return std::string(encryptedData.begin(), encryptedData.end());
}

// Entropy Calculation
double calculateEntropy(const std::vector<uint8_t>& data) {
    int freq[256] = {0};
    for (uint8_t byte : data) {
        freq[byte]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / data.size();
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// Main Function (Encrypt / Decrypt CLI)
int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    std::string password, input;
    char choice;

    std::cout << "Welcome to Mars Cipher!\nDo you want to encrypt or decrypt? (E/D): ";
    std::cin >> choice;
    std::cin.ignore();

    std::cout << "Enter the key: ";
    std::getline(std::cin, password);

    if (choice == 'E' || choice == 'e') {
        std::cout << "Enter the plaintext: ";
        std::getline(std::cin, input);
        std::vector<uint8_t> ciphertext = marsCipherEncrypt(input, password);
        
        double entropy = calculateEntropy(ciphertext);
        
        std::cout << "Ciphertext (hex): ";
        for (uint8_t c : ciphertext)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        std::cout << "\nEntropy (bits per byte): " << entropy << std::endl;

    } else {
        std::cout << "Enter the ciphertext (hex): ";
        std::getline(std::cin, input);
        std::vector<uint8_t> ciphertext;
        for (size_t i = 0; i < input.length(); i += 2)
            ciphertext.push_back(std::stoi(input.substr(i, 2), nullptr, 16));
        
        std::string plaintext = marsCipherDecrypt(ciphertext, password);
        std::cout << "Plaintext: " << plaintext << std::endl;
    }

    return 0;
}
