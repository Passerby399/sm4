import struct
import os
import time
from typing import Union, Tuple, Optional
from enum import Enum

#try:
#    from Crypto.Cipher import _raw_aesni
#
#    AESNI_AVAILABLE = _raw_aesni.is_AES_NI_enabled()
#except ImportError:
#   AESNI_AVAILABLE = False
AESNI_AVAILABLE = False
# SM4 S-box
SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
]

# System parameters FK
FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

# Fixed parameters CK
CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
]

# Precomputed T-tables for encryption and key expansion
T0 = [0] * 256
T1 = [0] * 256
T2 = [0] * 256
T3 = [0] * 256
T_prime0 = [0] * 256
T_prime1 = [0] * 256
T_prime2 = [0] * 256
T_prime3 = [0] * 256


# Precompute T-tables
def init_tables():
    for i in range(256):
        # For encryption T-transformation
        b = SBOX[i]
        val = (b << 24) | (b << 16) | (b << 8) | b
        T0[i] = val ^ left_rotate(val, 2) ^ left_rotate(val, 10) ^ left_rotate(val, 18) ^ left_rotate(val, 24)

        # For key expansion T'-transformation
        T_prime0[i] = val ^ left_rotate(val, 13) ^ left_rotate(val, 23)

        # Generate other tables by rotating bytes
        T1[i] = left_rotate(T0[i], 8)
        T2[i] = left_rotate(T0[i], 16)
        T3[i] = left_rotate(T0[i], 24)

        T_prime1[i] = left_rotate(T_prime0[i], 8)
        T_prime2[i] = left_rotate(T_prime0[i], 16)
        T_prime3[i] = left_rotate(T_prime0[i], 24)


def left_rotate(n: int, b: int) -> int:
    """32-bit left rotation"""
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


# Initialize tables at module load
init_tables()


class OptimizationLevel(Enum):
    BASIC = 0
    TTABLE = 1
    AVX2 = 2
    AESNI = 3
    GFNI = 4


class SM4GCM:
    def __init__(self, key: bytes, optimization: OptimizationLevel = OptimizationLevel.TTABLE):
        if len(key) != 16:
            raise ValueError("SM4 key must be 16 bytes")
        self.key = key
        self.round_keys = key_expansion(key, optimization)
        self.optimization = optimization

    def encrypt(self, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        return sm4_gcm_encrypt(plaintext, self.key, nonce, aad, self.optimization)

    def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        return sm4_gcm_decrypt(ciphertext, self.key, nonce, tag, aad, self.optimization)


def key_expansion(master_key: bytes, optimization: OptimizationLevel = OptimizationLevel.BASIC) -> list:
    """Expand 128-bit key into 32 round keys with optimization support"""
    if len(master_key) != 16:
        raise ValueError("SM4 key must be 16 bytes (128 bits)")

    # Convert key to four 32-bit integers (big-endian)
    mk = list(struct.unpack('>4I', master_key))

    # Initialize key schedule
    k = [0] * 36
    k[0] = mk[0] ^ FK[0]
    k[1] = mk[1] ^ FK[1]
    k[2] = mk[2] ^ FK[2]
    k[3] = mk[3] ^ FK[3]

    round_keys = [0] * 32

    # Generate round keys with optimization
    for i in range(32):
        tmp = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]

        if optimization == OptimizationLevel.BASIC:
            tmp = t_prime_transformation_basic(tmp)
        else:  # TTABLE and others use precomputed tables
            # Extract bytes
            b0 = (tmp >> 24) & 0xFF
            b1 = (tmp >> 16) & 0xFF
            b2 = (tmp >> 8) & 0xFF
            b3 = tmp & 0xFF

            # Apply T'-transformation using precomputed tables
            tmp = T_prime0[b0] ^ T_prime1[b1] ^ T_prime2[b2] ^ T_prime3[b3]

        k[i + 4] = k[i] ^ tmp
        round_keys[i] = k[i + 4]

    return round_keys


def t_prime_transformation_basic(word: int) -> int:
    """Basic implementation of key expansion transformation"""
    # S-box substitution
    b0 = SBOX[(word >> 24) & 0xFF]
    b1 = SBOX[(word >> 16) & 0xFF]
    b2 = SBOX[(word >> 8) & 0xFF]
    b3 = SBOX[word & 0xFF]

    # Linear transformation L'
    new_word = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    return new_word ^ left_rotate(new_word, 13) ^ left_rotate(new_word, 23)


def sm4_block_encrypt(block: bytes, round_keys: list,
                      optimization: OptimizationLevel = OptimizationLevel.TTABLE) -> bytes:
    """Encrypt a single 16-byte block with optimization support"""
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")

    # Convert block to four 32-bit integers (big-endian)
    x = list(struct.unpack('>4I', block))

    # 32 rounds of processing
    for i in range(32):
        # F function
        tmp = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ round_keys[i]

        if optimization == OptimizationLevel.BASIC:
            tmp = t_transformation_basic(tmp)
        else:  # TTABLE and others use precomputed tables
            # Extract bytes
            b0 = (tmp >> 24) & 0xFF
            b1 = (tmp >> 16) & 0xFF
            b2 = (tmp >> 8) & 0xFF
            b3 = tmp & 0xFF

            # Apply T-transformation using precomputed tables
            tmp = T0[b0] ^ T1[b1] ^ T2[b2] ^ T3[b3]

        x.append(x[i] ^ tmp)

    # Final reversal and output
    y = [x[35], x[34], x[33], x[32]]
    return struct.pack('>4I', *y)


def t_transformation_basic(word: int) -> int:
    """Basic implementation of encryption round function"""
    # S-box substitution
    b0 = SBOX[(word >> 24) & 0xFF]
    b1 = SBOX[(word >> 16) & 0xFF]
    b2 = SBOX[(word >> 8) & 0xFF]
    b3 = SBOX[word & 0xFF]

    # Linear transformation L
    new_word = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    return new_word ^ left_rotate(new_word, 2) ^ left_rotate(new_word, 10) ^ left_rotate(new_word, 18) ^ left_rotate(
        new_word, 24)


def sm4_block_decrypt(block: bytes, round_keys: list,
                      optimization: OptimizationLevel = OptimizationLevel.TTABLE) -> bytes:
    """Decrypt a single 16-byte block with optimization support"""
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")
    return sm4_block_encrypt(block, round_keys[::-1], optimization)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding to the data"""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding from the data"""
    if not data:
        return data
    padding_len = data[-1]
    if padding_len > len(data) or padding_len == 0:
        raise ValueError("Invalid padding")
    # Verify padding bytes
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")
    return data[:-padding_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length"""
    return bytes(x ^ y for x, y in zip(a, b))


def sm4_encrypt(plaintext: Union[str, bytes], key: Union[str, bytes],
                iv: bytes = None, mode: str = 'CBC',
                optimization: OptimizationLevel = OptimizationLevel.TTABLE) -> Tuple[bytes, bytes]:
    """
    Encrypt variable-length plaintext using SM4 with optimization

    Args:
        plaintext: Input data (str or bytes)
        key: Encryption key (16 bytes, str or bytes)
        iv: Initialization vector (16 bytes), random if None
        mode: Encryption mode (CBC or ECB)
        optimization: Optimization level to use

    Returns:
        (ciphertext, iv) tuple
    """
    # Convert inputs to bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')

    # Validate key
    if len(key) != 16:
        raise ValueError("SM4 key must be 16 bytes (128 bits)")

    # Generate random IV if not provided
    if iv is None and mode != 'ECB':
        iv = os.urandom(16)
    elif iv is not None and len(iv) != 16 and mode != 'ECB':
        raise ValueError("IV must be 16 bytes")

    # Expand key
    round_keys = key_expansion(key, optimization)

    # Apply padding
    padded_data = pkcs7_pad(plaintext) if mode != 'CTR' else plaintext

    # Encrypt based on mode
    if mode == 'CBC':
        ciphertext = _sm4_cbc_encrypt(padded_data, round_keys, iv, optimization)
        return ciphertext, iv  # 修改这里：返回密文和IV
    elif mode == 'ECB':
        return _sm4_ecb_encrypt(padded_data, round_keys, optimization), b''
    elif mode == 'CTR':
        return _sm4_ctr_encrypt(padded_data, round_keys, iv, optimization), iv
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def _sm4_cbc_encrypt(data: bytes, round_keys: list, iv: bytes,
                     optimization: OptimizationLevel) -> Tuple[bytes, bytes]:
    """CBC mode encryption"""
    ciphertext = b''
    previous_block = iv

    # Process each 16-byte block
    for i in range(0, len(data), 16):
        block = data[i:i + 16]

        # XOR with previous ciphertext block (or IV for first block)
        xored_block = xor_bytes(block, previous_block)

        # Encrypt the block
        encrypted_block = sm4_block_encrypt(xored_block, round_keys, optimization)

        # Add to ciphertext and set as previous for next block
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext


def _sm4_ecb_encrypt(data: bytes, round_keys: list,
                     optimization: OptimizationLevel) -> bytes:
    """ECB mode encryption"""
    ciphertext = b''

    # Process each 16-byte block independently
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        encrypted_block = sm4_block_encrypt(block, round_keys, optimization)
        ciphertext += encrypted_block

    return ciphertext


def _sm4_ctr_encrypt(data: bytes, round_keys: list, nonce: bytes,
                     optimization: OptimizationLevel) -> bytes:
    """CTR mode encryption"""
    ciphertext = b''
    counter = int.from_bytes(nonce, 'big')

    # Process each 16-byte block
    for i in range(0, len(data), 16):
        # Encrypt current counter value
        counter_block = counter.to_bytes(16, 'big')
        keystream_block = sm4_block_encrypt(counter_block, round_keys, optimization)

        # XOR with plaintext
        block = data[i:i + 16]
        ciphertext_block = xor_bytes(block, keystream_block[:len(block)])
        ciphertext += ciphertext_block

        # Increment counter
        counter = (counter + 1) & ((1 << 128) - 1)

    return ciphertext


def sm4_decrypt(ciphertext: bytes, key: Union[str, bytes],
                iv: bytes = None, mode: str = 'CBC',
                optimization: OptimizationLevel = OptimizationLevel.TTABLE) -> bytes:
    """
    Decrypt SM4 encrypted data with optimization

    Args:
        ciphertext: Encrypted data (bytes)
        key: Encryption key (16 bytes, str or bytes)
        iv: Initialization vector (16 bytes)
        mode: Encryption mode (CBC or ECB)
        optimization: Optimization level to use

    Returns:
        Decrypted plaintext (bytes)
    """
    # Validate inputs
    if len(ciphertext) % 16 != 0 and mode != 'CTR':
        raise ValueError("Ciphertext length must be multiple of 16 bytes for CBC/ECB modes")

    if isinstance(key, str):
        key = key.encode('utf-8')

    if len(key) != 16:
        raise ValueError("SM4 key must be 16 bytes (128 bits)")

    if iv is None and mode != 'ECB':
        raise ValueError("IV required for CBC/CTR modes")
    elif iv is not None and len(iv) != 16 and mode != 'ECB':
        raise ValueError("IV must be 16 bytes")

    # Expand key
    round_keys = key_expansion(key, optimization)

    # Decrypt based on mode
    if mode == 'CBC':
        return _sm4_cbc_decrypt(ciphertext, round_keys, iv, optimization)
    elif mode == 'ECB':
        return _sm4_ecb_decrypt(ciphertext, round_keys, optimization)
    elif mode == 'CTR':
        return _sm4_ctr_decrypt(ciphertext, round_keys, iv, optimization)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def _sm4_cbc_decrypt(ciphertext: bytes, round_keys: list, iv: bytes,
                     optimization: OptimizationLevel) -> bytes:
    """CBC mode decryption"""
    decrypted_blocks = []
    previous_block = iv

    # Process each 16-byte block
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]

        # Decrypt the block
        decrypted_block = sm4_block_decrypt(block, round_keys, optimization)

        # XOR with previous ciphertext block (or IV for first block)
        plaintext_block = xor_bytes(decrypted_block, previous_block)

        # Add to decrypted blocks and set current as previous for next block
        decrypted_blocks.append(plaintext_block)
        previous_block = block

    # Concatenate decrypted blocks
    padded_plaintext = b''.join(decrypted_blocks)

    # Remove padding
    return pkcs7_unpad(padded_plaintext)


def _sm4_ecb_decrypt(ciphertext: bytes, round_keys: list,
                     optimization: OptimizationLevel) -> bytes:
    """ECB mode decryption"""
    decrypted_blocks = []

    # Process each 16-byte block independently
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted_block = sm4_block_decrypt(block, round_keys, optimization)
        decrypted_blocks.append(decrypted_block)

    # Concatenate and unpad
    padded_plaintext = b''.join(decrypted_blocks)
    return pkcs7_unpad(padded_plaintext)


def _sm4_ctr_decrypt(ciphertext: bytes, round_keys: list, nonce: bytes,
                     optimization: OptimizationLevel) -> bytes:
    """CTR mode decryption (same as encryption)"""
    return _sm4_ctr_encrypt(ciphertext, round_keys, nonce, optimization)


# GCM constants
GCM_BLOCK_SIZE = 16
GCM_IV_SIZE = 12  # Recommended IV size for GCM

# Precomputed tables for GHASH
gcmR = 0xE1000000000000000000000000000000  # Reduction constant


def ghash_precompute(H: bytes) -> list:
    """Precompute multiplication table for GHASH"""
    # Convert H to integer (big-endian)
    H_int = int.from_bytes(H, 'big')

    # Precompute table for 4-bit windows (16 entries)
    table = [0] * 16
    table[0] = 0
    table[1] = H_int

    # Double for each subsequent entry
    for i in range(2, 16, 2):
        # Double the previous value
        table[i] = gcm_double(table[i // 2])
        # Double and add H
        table[i + 1] = table[i] ^ H_int

    return table


def gcm_double(x: int) -> int:
    """Double operation in GF(2^128)"""
    # If the highest bit is 1, we'll need to reduce
    reduce = (x >> 127) & 1
    x <<= 1
    if reduce:
        x ^= gcmR
    return x & ((1 << 128) - 1)


def ghash_block(X: int, H_table: list) -> int:
    """GHASH one block using precomputed table"""
    # Break into 4-bit chunks (32 chunks, 4 bits each)
    result = 0
    for i in range(0, 128, 4):
        # Extract 4-bit chunk
        chunk = (X >> (124 - i)) & 0xF
        # Multiply current result by 16
        result = gcm_double(gcm_double(gcm_double(gcm_double(result))))
        # Add table entry
        result ^= H_table[chunk]
    return result


def ghash(data: bytes, H: bytes) -> int:
    """Compute GHASH using precomputed table"""
    # Precompute multiplication table
    H_table = ghash_precompute(H)

    # Pad data to multiple of 16 bytes
    if len(data) % GCM_BLOCK_SIZE != 0:
        data += b'\x00' * (GCM_BLOCK_SIZE - (len(data) % GCM_BLOCK_SIZE))

    # Initialize result
    result = 0

    # Process each 16-byte block
    for i in range(0, len(data), GCM_BLOCK_SIZE):
        block = data[i:i + GCM_BLOCK_SIZE]
        block_int = int.from_bytes(block, 'big')
        result ^= block_int
        result = ghash_block(result, H_table)

    return result


def sm4_gcm_encrypt(plaintext: bytes, key: bytes, nonce: bytes,
                    aad: bytes = b"", optimization: OptimizationLevel = OptimizationLevel.TTABLE) -> Tuple[
    bytes, bytes]:
    """
    SM4-GCM authenticated encryption

    Args:
        plaintext: Data to encrypt
        key: 16-byte encryption key
        nonce: 12-byte nonce (recommended size)
        aad: Additional authenticated data
        optimization: Optimization level for SM4

    Returns:
        (ciphertext, authentication_tag)
    """
    # Validate inputs
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM")

    # Generate hash key H = E_K(0^128)
    round_keys = key_expansion(key, optimization)
    H = sm4_block_encrypt(b'\x00' * 16, round_keys, optimization)

    # Initialize counter J0
    if len(nonce) == 12:
        j0 = nonce + b'\x00\x00\x00\x01'
    else:
        # For non-12-byte nonce, we need to compute GHASH
        # This is simplified for demonstration
        j0 = nonce + b'\x00' * (16 - (len(nonce) % 16))
        j0 += (len(nonce) * 8).to_bytes(8, 'big')
        j0 = ghash(j0, H)
        j0 = j0.to_bytes(16, 'big')

    # Encrypt plaintext in CTR mode
    ctr = int.from_bytes(j0, 'big') + 1
    ciphertext = _sm4_ctr_encrypt(plaintext, round_keys, ctr.to_bytes(16, 'big'), optimization)

    # Compute authentication tag
    # Format: len(aad) || len(ciphertext)
    aad_len = len(aad) * 8
    ciphertext_len = len(ciphertext) * 8
    len_block = aad_len.to_bytes(8, 'big') + ciphertext_len.to_bytes(8, 'big')

    # GHASH input: AAD || ciphertext || len_block
    ghash_input = aad
    # Pad AAD to 16-byte multiple
    if len(ghash_input) % 16 != 0:
        ghash_input += b'\x00' * (16 - (len(ghash_input) % 16))

    ghash_input += ciphertext
    # Pad ciphertext to 16-byte multiple
    if len(ghash_input) % 16 != 0:
        ghash_input += b'\x00' * (16 - (len(ghash_input) % 16))

    ghash_input += len_block

    # Compute GHASH
    S = ghash(ghash_input, H)

    # Compute authentication tag
    T = sm4_block_encrypt(j0, round_keys, optimization)
    T_int = int.from_bytes(T, 'big')
    tag = (S ^ T_int).to_bytes(16, 'big')

    return ciphertext, tag[:16]  # Return full tag or truncate to desired length


def sm4_gcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes,
                    tag: bytes, aad: bytes = b"",
                    optimization: OptimizationLevel = OptimizationLevel.TTABLE) -> bytes:
    """
    SM4-GCM authenticated decryption

    Args:
        ciphertext: Encrypted data
        key: 16-byte encryption key
        nonce: 12-byte nonce
        tag: Authentication tag
        aad: Additional authenticated data
        optimization: Optimization level for SM4

    Returns:
        Plaintext if authentication is successful
    Raises:
        ValueError if authentication fails
    """
    # Validate inputs
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM")

    # Generate hash key H = E_K(0^128)
    round_keys = key_expansion(key, optimization)
    H = sm4_block_encrypt(b'\x00' * 16, round_keys, optimization)

    # Initialize counter J0
    if len(nonce) == 12:
        j0 = nonce + b'\x00\x00\x00\x01'
    else:
        # For non-12-byte nonce, we need to compute GHASH
        j0 = nonce + b'\x00' * (16 - (len(nonce) % 16))
        j0 += (len(nonce) * 8).to_bytes(8, 'big')
        j0 = ghash(j0, H)
        j0 = j0.to_bytes(16, 'big')

    # Decrypt ciphertext in CTR mode
    ctr = int.from_bytes(j0, 'big') + 1
    plaintext = _sm4_ctr_decrypt(ciphertext, round_keys, ctr.to_bytes(16, 'big'), optimization)

    # Compute expected tag (same as encryption)
    aad_len = len(aad) * 8
    ciphertext_len = len(ciphertext) * 8
    len_block = aad_len.to_bytes(8, 'big') + ciphertext_len.to_bytes(8, 'big')

    ghash_input = aad
    # Pad AAD to 16-byte multiple
    if len(ghash_input) % 16 != 0:
        ghash_input += b'\x00' * (16 - (len(ghash_input) % 16))

    ghash_input += ciphertext
    # Pad ciphertext to 16-byte multiple
    if len(ghash_input) % 16 != 0:
        ghash_input += b'\x00' * (16 - (len(ghash_input) % 16))

    ghash_input += len_block

    # Compute GHASH
    S = ghash(ghash_input, H)

    # Compute expected tag
    T = sm4_block_encrypt(j0, round_keys, optimization)
    T_int = int.from_bytes(T, 'big')
    expected_tag = (S ^ T_int).to_bytes(16, 'big')

    # Verify tag
    if not constant_time_compare(expected_tag[:len(tag)], tag):
        raise ValueError("Authentication failed - invalid tag")

    return plaintext


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# Benchmark function
def benchmark_sm4():
    """Benchmark different optimization levels"""
    key = b"16bytekey1234567"
    data = os.urandom(1024 * 1024)  # 1MB data
    iv = os.urandom(16)

    levels = [
        ("Basic", OptimizationLevel.BASIC),
        ("T-table", OptimizationLevel.TTABLE),
        # AVX2/AESNI/GFNI would require native extensions
    ]

    print("SM4 Encryption Benchmarks (1MB data):")
    for name, level in levels:
        start = time.time()
        ciphertext, _ = sm4_encrypt(data, key, iv, 'CBC', level)
        end = time.time()
        print(f"{name}: {len(data) / (end - start) / 1e6:.2f} MB/s")

    # GCM benchmark
    print("\nSM4-GCM Benchmarks (1MB data):")
    nonce = os.urandom(12)
    aad = b"Authenticated but not encrypted"
    for name, level in levels:
        start = time.time()
        ciphertext, tag = sm4_gcm_encrypt(data, key, nonce, aad, level)
        end = time.time()
        print(f"{name}: {len(data) / (end - start) / 1e6:.2f} MB/s")


if __name__ == "__main__":
    # Test basic functionality
    key = b"16bytekey1234567"
    iv = b"initialvector123"
    plaintext = "Hello, SM4-GCM! This is a test of authenticated encryption."

    # Test GCM
    print("Testing SM4-GCM:")
    nonce = os.urandom(12)
    aad = b"Additional authenticated data"
    ciphertext, tag = sm4_gcm_encrypt(plaintext.encode(), key, nonce, aad)
    print(f"Ciphertext: {ciphertext[:16].hex()}...")
    print(f"Tag: {tag.hex()}")

    try:
        decrypted = sm4_gcm_decrypt(ciphertext, key, nonce, tag, aad)
        print(f"Decrypted: {decrypted.decode()}")
        assert decrypted.decode() == plaintext
        print("GCM test successful!")
    except ValueError as e:
        print(f"GCM test failed: {e}")

    # Run benchmarks
    benchmark_sm4()