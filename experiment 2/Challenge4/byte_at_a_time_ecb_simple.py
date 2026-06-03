from pathlib import Path
import base64
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "AES for Challenges"))
from aes_utils import aes_ecb_encrypt, is_ecb_ciphertext, pkcs7_unpad


KEY = b"Simple ECB key!!"
UNKNOWN_SUFFIX = base64.b64decode(
    b"Um9sbGluJyBpbiBteSA1LjAK"
    b"V2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpU"
    b"aGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBo"
    b"aQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
)


def oracle(attacker_input: bytes) -> bytes:
    return aes_ecb_encrypt(attacker_input + UNKNOWN_SUFFIX, KEY)


def find_block_size() -> int:
    base_len = len(oracle(b""))
    for size in range(1, 65):
        new_len = len(oracle(b"A" * size))
        if new_len > base_len:
            return new_len - base_len
    raise RuntimeError("Block size not found.")


def decrypt_suffix() -> bytes:
    block_size = find_block_size()
    if not is_ecb_ciphertext(oracle(b"A" * block_size * 4), block_size):
        raise RuntimeError("Oracle is not using ECB.")

    recovered = bytearray()
    total_len = len(oracle(b""))

    for _ in range(total_len):
        prefix_len = block_size - 1 - (len(recovered) % block_size)
        prefix = b"A" * prefix_len
        block_index = len(recovered) // block_size
        start = block_index * block_size
        end = start + block_size
        target_block = oracle(prefix)[start:end]

        lookup = {}
        known = prefix + bytes(recovered)
        for candidate in range(256):
            block = oracle(known + bytes([candidate]))[start:end]
            lookup[block] = candidate

        if target_block not in lookup:
            break
        recovered.append(lookup[target_block])

    recovered_bytes = bytes(recovered)
    try:
        return pkcs7_unpad(recovered_bytes)
    except ValueError:
        pad_len = recovered_bytes[-1] if recovered_bytes else 0
        if 1 <= pad_len <= block_size and recovered_bytes.endswith(bytes([pad_len]) * pad_len):
            return recovered_bytes[:-pad_len]
        return recovered_bytes


def main() -> None:
    block_size = find_block_size()
    plaintext = decrypt_suffix()

    print(f"Detected block size: {block_size}")
    print(f"ECB detected: {is_ecb_ciphertext(oracle(b'A' * block_size * 4), block_size)}")
    print(plaintext.decode("utf-8"))


if __name__ == "__main__":
    main()
