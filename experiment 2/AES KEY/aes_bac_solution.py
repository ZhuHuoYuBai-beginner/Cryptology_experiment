#!/usr/bin/env python3
"""Solve the BAC-derived AES challenge from mtc3-hick-01-BAC-en.pdf.

No third-party package is required. The script derives the BAC encryption key
from the MRZ-like line, decrypts the Base64 ciphertext with AES-CBC using a
zero IV, and removes 01-00 padding.
"""

from __future__ import annotations

import base64
import hashlib


CIPHERTEXT_B64 = (
    "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jx"
    "aa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2N"
    "fNnWFBTXyf7SDI"
)

MRZ_WITH_GAP = "12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4"

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
for i, value in enumerate(S_BOX):
    INV_S_BOX[value] = i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def mrz_value(ch: str) -> int:
    if "0" <= ch <= "9":
        return ord(ch) - ord("0")
    if "A" <= ch <= "Z":
        return ord(ch) - ord("A") + 10
    if ch == "<":
        return 0
    raise ValueError(f"Invalid MRZ character: {ch!r}")


def check_digit(field: str) -> str:
    weights = [7, 3, 1]
    total = sum(mrz_value(ch) * weights[i % 3] for i, ch in enumerate(field))
    return str(total % 10)


def recover_mrz_line(line: str) -> str:
    # In the given line, the missing character is the expiry-date check digit.
    missing = check_digit(line[21:27])
    return line.replace("?", missing)


def odd_parity(data: bytes) -> bytes:
    """Set each byte to odd parity as BAC does for DES key material."""

    adjusted = bytearray()
    for byte in data:
        top_seven_bits = byte & 0xFE
        parity_bit = 0 if bin(top_seven_bits).count("1") % 2 else 1
        adjusted.append(top_seven_bits | parity_bit)
    return bytes(adjusted)


def derive_kenc(mrz_line: str) -> tuple[bytes, bytes, bytes]:
    # BAC MRZ information: document number+CD, birth date+CD, expiry date+CD.
    mrz_info = (mrz_line[0:10] + mrz_line[13:20] + mrz_line[21:28]).encode("ascii")
    kseed = hashlib.sha1(mrz_info).digest()[:16]
    d_enc = kseed + b"\x00\x00\x00\x01"
    kenc = odd_parity(hashlib.sha1(d_enc).digest()[:16])
    return mrz_info, kseed, kenc


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


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def expand_key(key: bytes) -> list[bytes]:
    if len(key) != 16:
        raise ValueError("This challenge uses AES-128, so the key must be 16 bytes.")

    words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i - 1].copy()
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])

    round_keys = []
    for round_index in range(11):
        round_key = bytearray()
        for word in words[round_index * 4 : (round_index + 1) * 4]:
            round_key.extend(word)
        round_keys.append(bytes(round_key))
    return round_keys


def add_round_key(state: list[int], round_key: bytes) -> None:
    for i, value in enumerate(round_key):
        state[i] ^= value


def inv_sub_bytes(state: list[int]) -> None:
    for i, value in enumerate(state):
        state[i] = INV_S_BOX[value]


def inv_shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def inv_mix_columns(state: list[int]) -> None:
    for column in range(4):
        i = 4 * column
        a0, a1, a2, a3 = state[i : i + 4]
        state[i + 0] = gf_mul(a0, 0x0E) ^ gf_mul(a1, 0x0B) ^ gf_mul(a2, 0x0D) ^ gf_mul(a3, 0x09)
        state[i + 1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0E) ^ gf_mul(a2, 0x0B) ^ gf_mul(a3, 0x0D)
        state[i + 2] = gf_mul(a0, 0x0D) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0E) ^ gf_mul(a3, 0x0B)
        state[i + 3] = gf_mul(a0, 0x0B) ^ gf_mul(a1, 0x0D) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0E)


def aes_decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
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


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % 16:
        raise ValueError("AES-CBC ciphertext length must be a multiple of 16 bytes.")

    round_keys = expand_key(key)
    previous = iv
    plaintext = bytearray()
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset : offset + 16]
        plaintext.extend(xor_bytes(aes_decrypt_block(block, round_keys), previous))
        previous = block
    return bytes(plaintext)


def remove_01_00_padding(data: bytes) -> bytes:
    index = len(data) - 1
    while index >= 0 and data[index] == 0:
        index -= 1
    if index < 0 or data[index] != 1:
        raise ValueError("Plaintext does not end in 01-00 padding.")
    return data[:index]


def main() -> None:
    mrz_line = recover_mrz_line(MRZ_WITH_GAP)
    mrz_info, kseed, kenc = derive_kenc(mrz_line)
    ciphertext = base64.b64decode(CIPHERTEXT_B64)

    padded_plaintext = aes_cbc_decrypt(ciphertext, kenc, iv=b"\x00" * 16)
    plaintext = remove_01_00_padding(padded_plaintext).decode("utf-8")

    print(f"Recovered MRZ line: {mrz_line}")
    print(f"MRZ information:    {mrz_info.decode('ascii')}")
    print(f"Kseed:              {kseed.hex()}")
    print(f"KENC/AES key:       {kenc.hex()}")
    print(f"Plaintext:          {plaintext}")
    print(f"Code word:          {plaintext.rsplit(':', 1)[-1].strip().rstrip('!')}")


if __name__ == "__main__":
    main()
