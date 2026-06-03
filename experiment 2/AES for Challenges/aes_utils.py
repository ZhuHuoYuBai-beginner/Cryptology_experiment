from __future__ import annotations

import os
from functools import lru_cache


BLOCK_SIZE = 16

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_S_BOX = [0] * 256
for index, value in enumerate(S_BOX):
    INV_S_BOX[value] = index

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def random_bytes(length: int) -> bytes:
    return os.urandom(length)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("Inputs must have the same length.")
    return bytes(a ^ b for a, b in zip(left, right))


def chunks(data: bytes, size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not 1 <= block_size <= 255:
        raise ValueError("Block size must be in [1, 255].")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid PKCS#7 padded length.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding byte.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding content.")
    return data[:-pad_len]


def gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return result


MUL2 = [gf_mul(value, 0x02) for value in range(256)]
MUL3 = [gf_mul(value, 0x03) for value in range(256)]
MUL9 = [gf_mul(value, 0x09) for value in range(256)]
MUL11 = [gf_mul(value, 0x0B) for value in range(256)]
MUL13 = [gf_mul(value, 0x0D) for value in range(256)]
MUL14 = [gf_mul(value, 0x0E) for value in range(256)]


@lru_cache(maxsize=32)
def expand_key(key: bytes) -> tuple[bytes, ...]:
    if len(key) != 16:
        raise ValueError("Only AES-128 keys are supported for these challenges.")

    words = [list(key[i : i + 4]) for i in range(0, len(key), 4)]
    for index in range(4, 44):
        temp = words[index - 1].copy()
        if index % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[b] for b in temp]
            temp[0] ^= RCON[index // 4]
        words.append([a ^ b for a, b in zip(words[index - 4], temp)])

    round_keys = []
    for round_index in range(11):
        round_key = bytearray()
        for word in words[round_index * 4 : (round_index + 1) * 4]:
            round_key.extend(word)
        round_keys.append(bytes(round_key))
    return tuple(round_keys)


def add_round_key(state: list[int], round_key: bytes) -> None:
    for index, value in enumerate(round_key):
        state[index] ^= value


def sub_bytes(state: list[int]) -> None:
    for index, value in enumerate(state):
        state[index] = S_BOX[value]


def inv_sub_bytes(state: list[int]) -> None:
    for index, value in enumerate(state):
        state[index] = INV_S_BOX[value]


def shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def inv_shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def mix_columns(state: list[int]) -> None:
    for column in range(4):
        i = 4 * column
        a0, a1, a2, a3 = state[i : i + 4]
        state[i + 0] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3
        state[i + 1] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3
        state[i + 2] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3]
        state[i + 3] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]


def inv_mix_columns(state: list[int]) -> None:
    for column in range(4):
        i = 4 * column
        a0, a1, a2, a3 = state[i : i + 4]
        state[i + 0] = MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3]
        state[i + 1] = MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3]
        state[i + 2] = MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3]
        state[i + 3] = MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3]


def aes_encrypt_block_with_round_keys(block: bytes, round_keys: tuple[bytes, ...]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be exactly 16 bytes.")
    state = list(block)

    add_round_key(state, round_keys[0])
    for round_index in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_index])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    return bytes(state)


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    return aes_encrypt_block_with_round_keys(block, expand_key(key))


def aes_decrypt_block_with_round_keys(block: bytes, round_keys: tuple[bytes, ...]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be exactly 16 bytes.")
    state = list(block)

    add_round_key(state, round_keys[10])
    for round_index in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[round_index])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    return bytes(state)


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    return aes_decrypt_block_with_round_keys(block, expand_key(key))


def aes_ecb_encrypt(plaintext: bytes, key: bytes, pad: bool = True) -> bytes:
    data = pkcs7_pad(plaintext) if pad else plaintext
    if len(data) % BLOCK_SIZE:
        raise ValueError("ECB plaintext must be block aligned when pad=False.")
    round_keys = expand_key(key)
    return b"".join(aes_encrypt_block_with_round_keys(block, round_keys) for block in chunks(data))


def aes_ecb_decrypt(ciphertext: bytes, key: bytes, unpad: bool = True) -> bytes:
    if len(ciphertext) % BLOCK_SIZE:
        raise ValueError("ECB ciphertext must be block aligned.")
    round_keys = expand_key(key)
    data = b"".join(aes_decrypt_block_with_round_keys(block, round_keys) for block in chunks(ciphertext))
    return pkcs7_unpad(data) if unpad else data


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes, pad: bool = True) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes.")
    data = pkcs7_pad(plaintext) if pad else plaintext
    if len(data) % BLOCK_SIZE:
        raise ValueError("CBC plaintext must be block aligned when pad=False.")

    previous = iv
    result = bytearray()
    round_keys = expand_key(key)
    for block in chunks(data):
        encrypted = aes_encrypt_block_with_round_keys(xor_bytes(block, previous), round_keys)
        result.extend(encrypted)
        previous = encrypted
    return bytes(result)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes.")
    if len(ciphertext) % BLOCK_SIZE:
        raise ValueError("CBC ciphertext must be block aligned.")

    previous = iv
    result = bytearray()
    round_keys = expand_key(key)
    for block in chunks(ciphertext):
        result.extend(xor_bytes(aes_decrypt_block_with_round_keys(block, round_keys), previous))
        previous = block
    data = bytes(result)
    return pkcs7_unpad(data) if unpad else data


def count_duplicate_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> int:
    blocks = chunks(data, block_size)
    return len(blocks) - len(set(blocks))


def is_ecb_ciphertext(data: bytes, block_size: int = BLOCK_SIZE) -> bool:
    return count_duplicate_blocks(data, block_size) > 0


if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = "69c4e0d86a7b0430d8cdb78070b4c55a"

    ciphertext = aes_encrypt_block(plaintext, key)
    recovered = aes_decrypt_block(ciphertext, key)

    print(f"AES test ciphertext: {ciphertext.hex()}")
    print(f"Expected ciphertext: {expected}")
    print(f"Encrypt test passed: {ciphertext.hex() == expected}")
    print(f"Decrypt test passed: {recovered == plaintext}")
