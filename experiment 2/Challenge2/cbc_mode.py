from pathlib import Path
import base64
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "AES for Challenges"))
from aes_utils import aes_cbc_decrypt, aes_cbc_encrypt, count_duplicate_blocks


KEY = b"YELLOW SUBMARINE"
IV = b"\x00" * 16


def decrypt_official_file() -> bytes | None:
    data_path = Path(__file__).with_name("10.txt")
    if not data_path.exists():
        return None
    ciphertext = base64.b64decode(data_path.read_text(encoding="utf-8"))
    return aes_cbc_decrypt(ciphertext, KEY, IV)


def self_test() -> None:
    plaintext = (
        b"CBC mode chains blocks together. "
        b"Equal plaintext blocks will not produce equal ciphertext blocks."
    )
    ciphertext = aes_cbc_encrypt(plaintext, KEY, IV)
    recovered = aes_cbc_decrypt(ciphertext, KEY, IV)

    repeated_plaintext = b"A" * 64
    repeated_ciphertext = aes_cbc_encrypt(repeated_plaintext, KEY, IV)

    print(f"Round-trip passed: {recovered == plaintext}")
    print(f"Ciphertext length: {len(ciphertext)}")
    print(f"Duplicate CBC blocks for repeated plaintext: {count_duplicate_blocks(repeated_ciphertext)}")


def main() -> None:
    plaintext = decrypt_official_file()
    if plaintext is None:
        print("Challenge2/10.txt not found; running CBC self-test instead.")
        self_test()
    else:
        preview = plaintext.decode("utf-8", errors="replace")[:400]
        print("Official challenge file decrypted.")
        print(preview)


if __name__ == "__main__":
    main()
