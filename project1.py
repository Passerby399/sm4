import struct
import os
from typing import Union, Tuple

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


def left_rotate(n: int, b: int) -> int:
    """32-bit left rotation"""
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def t_transformation(word: int) -> int:
    """Encryption round function transformation"""
    # S-box substitution
    b0 = SBOX[(word >> 24) & 0xFF]
    b1 = SBOX[(word >> 16) & 0xFF]
    b2 = SBOX[(word >> 8) & 0xFF]
    b3 = SBOX[word & 0xFF]

    # Linear transformation L
    new_word = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    return new_word ^ left_rotate(new_word, 2) ^ left_rotate(new_word, 10) ^ left_rotate(new_word, 18) ^ left_rotate(
        new_word, 24)


def t_prime_transformation(word: int) -> int:
    """Key expansion transformation"""
    # S-box substitution
    b0 = SBOX[(word >> 24) & 0xFF]
    b1 = SBOX[(word >> 16) & 0xFF]
    b2 = SBOX[(word >> 8) & 0xFF]
    b3 = SBOX[word & 0xFF]

    # Linear transformation L'
    new_word = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    return new_word ^ left_rotate(new_word, 13) ^ left_rotate(new_word, 23)


def key_expansion(master_key: bytes) -> list:
    """Expand 128-bit key into 32 round keys"""
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

    # Generate round keys
    for i in range(32):
        tmp = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]
        tmp = t_prime_transformation(tmp)
        k[i + 4] = k[i] ^ tmp
        round_keys[i] = k[i + 4]

    return round_keys


def sm4_block_encrypt(block: bytes, round_keys: list) -> bytes:
    """Encrypt a single 16-byte block"""
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")

    # Convert block to four 32-bit integers (big-endian)
    x = list(struct.unpack('>4I', block))

    # 32 rounds of processing
    for i in range(32):
        # F function
        tmp = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ round_keys[i]
        tmp = t_transformation(tmp)
        x.append(x[i] ^ tmp)

    # Final reversal and output
    y = [x[35], x[34], x[33], x[32]]
    return struct.pack('>4I', *y)


def sm4_block_decrypt(block: bytes, round_keys: list) -> bytes:
    """Decrypt a single 16-byte block"""
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")

    # Reverse the round keys for decryption
    return sm4_block_encrypt(block, round_keys[::-1])


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
                iv: bytes = None, mode: str = 'CBC') -> Tuple[bytes, bytes]:
    """
    Encrypt variable-length plaintext using SM4 in CBC mode

    Args:
        plaintext: Input data (str or bytes)
        key: Encryption key (16 bytes, str or bytes)
        iv: Initialization vector (16 bytes), random if None
        mode: Only CBC mode is supported for now

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
        #print(key, len(key))
        raise ValueError("SM4 key must be 16 bytes (128 bits)")

    # Generate random IV if not provided
    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    # Expand key
    round_keys = key_expansion(key)

    # Apply padding
    padded_data = pkcs7_pad(plaintext)

    # Encrypt in CBC mode
    ciphertext = b''
    previous_block = iv

    # Process each 16-byte block
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i + 16]

        # XOR with previous ciphertext block (or IV for first block)
        xored_block = xor_bytes(block, previous_block)

        # Encrypt the block
        encrypted_block = sm4_block_encrypt(xored_block, round_keys)

        # Add to ciphertext and set as previous for next block
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext, iv


def sm4_decrypt(ciphertext: bytes, key: Union[str, bytes],
                iv: bytes, mode: str = 'CBC') -> bytes:
    """
    Decrypt SM4 encrypted data in CBC mode

    Args:
        ciphertext: Encrypted data (bytes)
        key: Encryption key (16 bytes, str or bytes)
        iv: Initialization vector (16 bytes)
        mode: Only CBC mode is supported for now

    Returns:
        Decrypted plaintext (bytes)
    """
    # Validate inputs
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16 bytes")

    if isinstance(key, str):
        key = key.encode('utf-8')

    if len(key) != 16:
        raise ValueError("SM4 key must be 16 bytes (128 bits)")

    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    # Expand key
    round_keys = key_expansion(key)

    # Decrypt in CBC mode
    decrypted_blocks = []
    previous_block = iv

    # Process each 16-byte block
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]

        # Decrypt the block
        decrypted_block = sm4_block_decrypt(block, round_keys)

        # XOR with previous ciphertext block (or IV for first block)
        plaintext_block = xor_bytes(decrypted_block, previous_block)

        # Add to decrypted blocks and set current as previous for next block
        decrypted_blocks.append(plaintext_block)
        previous_block = block

    # Concatenate decrypted blocks
    padded_plaintext = b''.join(decrypted_blocks)

    # Remove padding
    return pkcs7_unpad(padded_plaintext)


# Example usage with variable-length plaintext
if __name__ == "__main__":
    # Test key and IV
    key = b"16bytekey1234567"  # 16 bytes key
    iv = b"initialvector123"  # 16 bytes IV

    # Test messages of different lengths
    messages = [
        b"",  # Empty message
        b"A",  # 1 byte
        b"Hello, SM4!",  # 11 bytes
        b"1234567890" * 10,  # 100 bytes
        b"Padding test" * 17  # 204 bytes (exactly 16 blocks)
    ]

    for i, plaintext in enumerate(messages):
        print(f"\nTest {i + 1}: {len(plaintext)} bytes")
        print("Original: ", plaintext[:50] + (b"..." if len(plaintext) > 50 else b""))

        # Encrypt
        ciphertext, iv_used = sm4_encrypt(plaintext, key, iv)
        print(f"Ciphertext ({len(ciphertext)} bytes):", ciphertext[:16].hex() + "...")

        # Decrypt
        decrypted = sm4_decrypt(ciphertext, key, iv_used)
        print("Decrypted: ", decrypted[:50] + (b"..." if len(decrypted) > 50 else b""))

        # Verify
        assert decrypted == plaintext, f"Test {i + 1} failed! {decrypted} != {plaintext}"
        print("✓ Decryption verified successfully!")

    print("\nAll tests passed!")