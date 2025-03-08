import os
import hmac
import ctypes
import math
import secrets
from hashlib import blake2b
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import BLAKE2b

# Load Libsodium
libsodium = ctypes.cdll.LoadLibrary("libsodium.so")

# Define Libsodium function prototypes
libsodium.crypto_stream_xchacha20_xor.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # output
    ctypes.POINTER(ctypes.c_ubyte),  # input
    ctypes.c_ulonglong,  # length
    ctypes.POINTER(ctypes.c_ubyte),  # nonce
    ctypes.POINTER(ctypes.c_ubyte),  # key
]

def calculate_entropy(data: bytes):
    if not data:
        print("⚠️ Empty data input!")
        return 0.0
    
    freq = [0] * 256  # Equivalent to int freq[256] = {0};
    total_length = len(data)

    for byte in data:
        freq[byte] += 1

    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total_length
            entropy -= p * math.log2(p)

    return entropy

# HKDF using BLAKE2b-512
def hkdf_blake2b(input_key: bytes, salt: bytes, info: bytes, length: int = 32):
    hkdf = HKDF(
        algorithm=BLAKE2b(64),  # 512-bit output
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key)

# Derive Encryption, MAC, and Extra Key (Match C++ exactly)
def derive_keys(password: str, salt: bytes):
    input_key = password.encode()
    key_enc = hkdf_blake2b(input_key, salt, b"KEY\x00")  # Match C++: {'K', 'E', 'Y', 0}
    key_mac = hkdf_blake2b(input_key, salt, b"KEY\x01")  # Match C++: {'K', 'E', 'Y', 1}
    key_extra = hkdf_blake2b(input_key, salt, b"KEY\x02")  # Match C++: {'K', 'E', 'Y', 2}
    return key_enc, key_mac, key_extra

# Generate HMAC-SHA256
def generate_hmac(data: bytes, key: bytes):
    return hmac.new(key, data, digestmod="sha256").digest()

# XChaCha20 XOR Encryption/Decryption using Libsodium
def xchacha20_xor(data: bytes, nonce: bytes, key: bytes):
    data_len = len(data)
    out = (ctypes.c_ubyte * data_len)()
    data_buf = (ctypes.c_ubyte * data_len).from_buffer_copy(data)
    nonce_buf = (ctypes.c_ubyte * 24).from_buffer_copy(nonce)
    key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key)

    libsodium.crypto_stream_xchacha20_xor(out, data_buf, data_len, nonce_buf, key_buf)
    return bytes(out)

# Deimos Cipher Encryption
def deimos_cipher_encrypt(plaintext: bytes, password: str):
    salt = os.urandom(32)  # 256-bit salt
    key_enc, _, key_mac = derive_keys(password, salt)
    nonce = os.urandom(24)  # 192-bit nonce

    # Encrypt using XChaCha20 keystream XOR
    ciphertext = xchacha20_xor(plaintext, nonce, key_enc)

    # ⚠️ Change: HMAC now covers only `ciphertext` (Match C++)
    hmac_value = generate_hmac(ciphertext, key_mac)

    encrypted_data = salt + nonce + ciphertext + hmac_value
    return encrypted_data

# Deimos Cipher Decryption
def deimos_cipher_decrypt(ciphertext: bytes, password: str):
    if len(ciphertext) < 32 + 24 + 32:
        return "Error: Ciphertext too short!"

    salt, nonce, encrypted_data, received_hmac = (
        ciphertext[:32], ciphertext[32:56], ciphertext[56:-32], ciphertext[-32:]
    )

    key_enc, _, key_mac = derive_keys(password, salt)

    # ⚠️ Change: HMAC now verifies only `ciphertext` (Match C++)
    calculated_hmac = generate_hmac(encrypted_data, key_mac)
    if not hmac.compare_digest(calculated_hmac, received_hmac):
        return "Error: Integrity check failed!"

    # Decrypt using XOR keystream
    plaintext_bytes = xchacha20_xor(encrypted_data, nonce, key_enc)
    return plaintext_bytes

# ✅ Fix: Define `password`
password = "a"

# ✅ Fix: Generate random plaintext
def generate_random_string(length: int) -> bytes:
    return secrets.token_bytes(length)

# Example usage
random_bytes = generate_random_string(6)

numtest = 100000
totalEntropy = 0.0

for i in range(numtest):
    plaintext = random_bytes
    ciphertext = deimos_cipher_encrypt(plaintext, password)
    totalEntropy += calculate_entropy(ciphertext)

average_entropy = totalEntropy/numtest
print(f"Average Entropy: {average_entropy:.5f}")
