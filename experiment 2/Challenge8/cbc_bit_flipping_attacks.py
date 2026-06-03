from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "AES for Challenges"))
from aes_utils import aes_cbc_decrypt, aes_cbc_encrypt


KEY = b"CBCBitFlipKey!!!"
IV = b"\x00" * 16
PREFIX = b"comment1=cooking%20MCs;userdata="
SUFFIX = b";comment2=%20like%20a%20pound%20of%20bacon"


def sanitize(userdata: bytes) -> bytes:
    return userdata.replace(b";", b"").replace(b"=", b"")


def encrypt_userdata(userdata: bytes) -> bytes:
    return aes_cbc_encrypt(PREFIX + sanitize(userdata) + SUFFIX, KEY, IV)


def is_admin(ciphertext: bytes) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, KEY, IV)
    return b";admin=true;" in plaintext


def forge_admin_ciphertext() -> bytes:
    block_size = 16
    ciphertext = bytearray(encrypt_userdata(b"A" * 32))
    target = b";admin=true;AAAA"
    original = b"A" * len(target)

    controlled_block_index = len(PREFIX) // block_size + 1
    previous_block_offset = (controlled_block_index - 1) * block_size

    for index, (old, new) in enumerate(zip(original, target)):
        ciphertext[previous_block_offset + index] ^= old ^ new

    return bytes(ciphertext)


def main() -> None:
    forged = forge_admin_ciphertext()
    plaintext = aes_cbc_decrypt(forged, KEY, IV)

    print(f"Admin success: {is_admin(forged)}")
    print(plaintext)


if __name__ == "__main__":
    main()
