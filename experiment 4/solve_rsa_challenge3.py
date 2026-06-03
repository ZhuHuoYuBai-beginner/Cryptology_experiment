from __future__ import annotations

from dataclasses import dataclass
from math import gcd, isqrt
from pathlib import Path

import local_env  # noqa: F401


ROOT_DIR = Path(__file__).resolve().parents[1]
CHALLENGE_DIR = next(ROOT_DIR.glob("*赛题三*"))
INTERCEPT_DIR = next(CHALLENGE_DIR.glob("附件3-2*"))

PREFIX_HEX = "9876543210abcdef"
PADDING_ZERO_HEX_LEN = 88


@dataclass(frozen=True)
class Frame:
    name: str
    n: int
    e: int
    c: int


def load_frames() -> list[Frame]:
    frames: list[Frame] = []
    for path in sorted(INTERCEPT_DIR.glob("Frame*"), key=lambda p: int(p.name[5:])):
        payload = path.read_text().strip()
        n = int(payload[0:256], 16)
        e = int(payload[256:512], 16)
        c = int(payload[512:768], 16)
        frames.append(Frame(path.name, n, e, c))
    return frames


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(value: int, modulus: int) -> int:
    g, x, _ = egcd(value, modulus)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % modulus


def decrypt_from_factors(frame: Frame, p: int, q: int) -> int:
    phi = (p - 1) * (q - 1)
    d = mod_inverse(frame.e, phi)
    return pow(frame.c, d, frame.n)


def decode_message_int(message: int) -> tuple[str, int, bytes]:
    hex_message = f"{message:0128x}"
    prefix = hex_message[:16]
    seq = int(hex_message[16:24], 16)
    tail = bytes.fromhex(hex_message[-16:])
    return prefix, seq, tail


def build_message_int(seq: int, chunk: str) -> int:
    message_hex = PREFIX_HEX + f"{seq:08x}" + ("0" * PADDING_ZERO_HEX_LEN) + chunk.encode().hex()
    return int(message_hex, 16)


def recover_common_modulus(frame_a: Frame, frame_b: Frame) -> int:
    g, x, y = egcd(frame_a.e, frame_b.e)
    if g != 1:
        raise ValueError("exponents are not coprime")

    left = frame_a.c
    right = frame_b.c
    if x < 0:
        left = mod_inverse(left, frame_a.n)
        x = -x
    if y < 0:
        right = mod_inverse(right, frame_a.n)
        y = -y

    return (pow(left, x, frame_a.n) * pow(right, y, frame_a.n)) % frame_a.n


def fermat_factor(n: int) -> tuple[int, int]:
    a = isqrt(n)
    if a * a < n:
        a += 1

    while True:
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1


def pollard_pm1_factor(n: int, bound: int) -> tuple[int, int]:
    a = 2
    for prime in primes_up_to(bound):
        exponent = prime
        while exponent * prime <= bound:
            exponent *= prime
        a = pow(a, exponent, n)
    factor = gcd(a - 1, n)
    if factor in (1, n):
        raise ValueError("pollard p-1 failed")
    return factor, n // factor


def primes_up_to(limit: int) -> list[int]:
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for value in range(2, isqrt(limit) + 1):
        if sieve[value]:
            start = value * value
            sieve[start : limit + 1 : value] = b"\x00" * (((limit - start) // value) + 1)
    return [index for index, flag in enumerate(sieve) if flag]


def recover_by_shared_prime(frame_a: Frame, frame_b: Frame) -> tuple[int, int]:
    shared = gcd(frame_a.n, frame_b.n)
    if shared == 1:
        raise ValueError("no shared prime")
    return decrypt_from_factors(frame_a, shared, frame_a.n // shared), decrypt_from_factors(frame_b, shared, frame_b.n // shared)


def main() -> None:
    frames = {frame.name: frame for frame in load_frames()}

    recovered: dict[int, str] = {}
    evidence: list[str] = []

    # 1. Common modulus attack: Frame0 / Frame4.
    m0 = recover_common_modulus(frames["Frame0"], frames["Frame4"])
    prefix, seq, chunk = decode_message_int(m0)
    recovered[seq] = chunk.decode("ascii")
    evidence.append(f"Frame0 + Frame4: common modulus attack -> seq={seq}, chunk={chunk.decode('ascii')!r}, prefix={prefix}")

    # 2. Shared prime attack: Frame1 / Frame18.
    m1, m18 = recover_by_shared_prime(frames["Frame1"], frames["Frame18"])
    for label, message in [("Frame1", m1), ("Frame18", m18)]:
        prefix, seq, chunk = decode_message_int(message)
        recovered[seq] = chunk.decode("ascii")
        evidence.append(f"{label}: shared-prime factorization -> seq={seq}, chunk={chunk.decode('ascii')!r}, prefix={prefix}")

    # 3. Fermat near-square factorization: Frame10.
    p10, q10 = fermat_factor(frames["Frame10"].n)
    m10 = decrypt_from_factors(frames["Frame10"], p10, q10)
    prefix, seq, chunk = decode_message_int(m10)
    recovered[seq] = chunk.decode("ascii")
    evidence.append(f"Frame10: Fermat factorization -> seq={seq}, chunk={chunk.decode('ascii')!r}, prefix={prefix}")

    # 4. Pollard p-1 factorization.
    for name, bound in [("Frame2", 10_000), ("Frame6", 1_000_000), ("Frame19", 10_000)]:
        p, q = pollard_pm1_factor(frames[name].n, bound)
        message = decrypt_from_factors(frames[name], p, q)
        prefix, seq, chunk = decode_message_int(message)
        recovered[seq] = chunk.decode("ascii")
        evidence.append(f"{name}: Pollard p-1 (B={bound}) -> seq={seq}, chunk={chunk.decode('ascii')!r}, prefix={prefix}")

    inferred_message = (
        'My secret is a famous quote by: Albert Einstein. '
        'That is "Logic will get you from A to B. Imagination will take you everywhere."'
    )
    inferred_chunks = [inferred_message[i : i + 8] for i in range(0, len(inferred_message), 8)]

    verified_mapping: dict[int, list[str]] = {}
    for seq, chunk in enumerate(inferred_chunks):
        message = build_message_int(seq, chunk)
        matches: list[str] = []
        for frame in frames.values():
            if pow(message, frame.e, frame.n) == frame.c:
                matches.append(frame.name)
        if matches:
            verified_mapping[seq] = matches

    print("Recovered chunks from direct cryptanalysis:")
    for seq in sorted(recovered):
        print(f"  seq={seq:02d} chunk={recovered[seq]!r}")

    print("\nAttack evidence:")
    for item in evidence:
        print(f"  - {item}")

    print("\nVerified chunks by re-encryption against intercepted frames:")
    for seq in sorted(verified_mapping):
        print(f"  seq={seq:02d} chunk={inferred_chunks[seq]!r} -> frames={verified_mapping[seq]}")

    missing = [seq for seq in range(len(inferred_chunks)) if seq not in verified_mapping]
    print(f"\nUnverified by direct collision: {missing}")
    if missing:
        for seq in missing:
            print(f"  inferred seq={seq:02d} chunk={inferred_chunks[seq]!r}")

    print("\nCandidate full plaintext:")
    print(inferred_message)


if __name__ == "__main__":
    main()
