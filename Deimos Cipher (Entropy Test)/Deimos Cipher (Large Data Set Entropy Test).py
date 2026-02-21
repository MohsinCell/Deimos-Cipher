import ctypes
import hmac
import math
import os
import secrets

from cryptography.hazmat.primitives.hashes import BLAKE2b
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

libsodium = ctypes.cdll.LoadLibrary("libsodium.so")

libsodium.crypto_stream_xchacha20_xor.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_ulonglong,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte),
]


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq = [0] * 256
    total_length = len(data)

    for byte in data:
        freq[byte] += 1

    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total_length
            entropy -= p * math.log2(p)

    return entropy


def hkdf_blake2b(input_key: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=BLAKE2b(64),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key)


def derive_keys(password: str, salt: bytes):
    input_key = password.encode()
    key_enc = hkdf_blake2b(input_key, salt, b"KEY\x00")
    key_aux = hkdf_blake2b(input_key, salt, b"KEY\x01")
    key_mac = hkdf_blake2b(input_key, salt, b"KEY\x02")
    return key_enc, key_aux, key_mac


def generate_hmac(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, digestmod="sha256").digest()


def xchacha20_xor(data: bytes, nonce: bytes, key: bytes) -> bytes:
    data_len = len(data)
    out = (ctypes.c_ubyte * data_len)()
    data_buf = (ctypes.c_ubyte * data_len).from_buffer_copy(data)
    nonce_buf = (ctypes.c_ubyte * 24).from_buffer_copy(nonce)
    key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key)

    libsodium.crypto_stream_xchacha20_xor(out, data_buf, data_len, nonce_buf, key_buf)
    return bytes(out)


def deimos_cipher_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(32)
    key_enc, _, key_mac = derive_keys(password, salt)
    nonce = os.urandom(24)
    ciphertext = xchacha20_xor(plaintext, nonce, key_enc)
    hmac_value = generate_hmac(ciphertext, key_mac)
    return salt + nonce + ciphertext + hmac_value


def deimos_cipher_decrypt(ciphertext: bytes, password: str):
    if len(ciphertext) < 32 + 24 + 32:
        return "Error: Ciphertext too short!"

    salt, nonce, encrypted_data, received_hmac = (
        ciphertext[:32],
        ciphertext[32:56],
        ciphertext[56:-32],
        ciphertext[-32:],
    )

    key_enc, _, key_mac = derive_keys(password, salt)
    calculated_hmac = generate_hmac(encrypted_data, key_mac)
    if not hmac.compare_digest(calculated_hmac, received_hmac):
        return "Error: Integrity check failed!"

    plaintext_bytes = xchacha20_xor(encrypted_data, nonce, key_enc)
    return plaintext_bytes


def generate_random_string(length: int) -> bytes:
    return secrets.token_bytes(length)


password = "a"
num_tests = 100000
total_entropy = 0.0

for _ in range(num_tests):
    plaintext = generate_random_string(6)
    ciphertext = deimos_cipher_encrypt(plaintext, password)
    total_entropy += calculate_entropy(ciphertext)

average_entropy = total_entropy / num_tests
print(f"Average Entropy: {average_entropy:.5f}")
