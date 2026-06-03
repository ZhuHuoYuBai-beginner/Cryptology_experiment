from __future__ import annotations

from dataclasses import dataclass
from math import gcd


@dataclass(frozen=True)
class RSAKeyPair:
    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    gcd_value, x1, y1 = extended_gcd(b, a % b)
    return gcd_value, y1, x1 - (a // b) * y1


def mod_inverse(value: int, modulus: int) -> int:
    gcd_value, x, _ = extended_gcd(value, modulus)
    if gcd_value != 1:
        raise ValueError("Inverse does not exist.")
    return x % modulus


def build_keypair(p: int, q: int, e: int) -> RSAKeyPair:
    if p == q:
        raise ValueError("p and q must be distinct primes.")

    n = p * q
    phi = (p - 1) * (q - 1)
    if not 1 < e < phi:
        raise ValueError("e must satisfy 1 < e < phi.")
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi.")

    d = mod_inverse(e, phi)
    return RSAKeyPair(p=p, q=q, n=n, phi=phi, e=e, d=d)


def encrypt_int(message: int, e: int, n: int) -> int:
    if not 0 <= message < n:
        raise ValueError("Message integer must satisfy 0 <= m < n.")
    return pow(message, e, n)


def decrypt_int(ciphertext: int, d: int, n: int) -> int:
    if not 0 <= ciphertext < n:
        raise ValueError("Ciphertext integer must satisfy 0 <= c < n.")
    return pow(ciphertext, d, n)


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")


def int_to_bytes(value: int) -> bytes:
    if value < 0:
        raise ValueError("Only non-negative integers are supported.")
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, byteorder="big")


def encrypt_bytes(data: bytes, e: int, n: int) -> int:
    return encrypt_int(bytes_to_int(data), e, n)


def decrypt_bytes(ciphertext: int, d: int, n: int) -> bytes:
    return int_to_bytes(decrypt_int(ciphertext, d, n))


def is_unconcealed_message(message: int, e: int, n: int) -> bool:
    return pow(message, e, n) == message


def unconcealed_message_count(e: int, p: int, q: int) -> int:
    return (1 + gcd(e - 1, p - 1)) * (1 + gcd(e - 1, q - 1))
