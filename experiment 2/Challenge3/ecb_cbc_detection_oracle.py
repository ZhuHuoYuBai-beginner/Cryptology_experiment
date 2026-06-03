from pathlib import Path
import random
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "AES for Challenges"))
from aes_utils import aes_cbc_encrypt, aes_ecb_encrypt, is_ecb_ciphertext, random_bytes


def encryption_oracle(plaintext: bytes) -> tuple[bytes, str]:
    key = random_bytes(16)
    prefix = random_bytes(random.randint(5, 10))
    suffix = random_bytes(random.randint(5, 10))
    data = prefix + plaintext + suffix

    if random.choice([True, False]):
        return aes_ecb_encrypt(data, key), "ECB"

    iv = random_bytes(16)
    return aes_cbc_encrypt(data, key, iv), "CBC"


def detect_mode(ciphertext: bytes) -> str:
    return "ECB" if is_ecb_ciphertext(ciphertext) else "CBC"


def main() -> None:
    correct = 0
    trials = 20
    for index in range(1, trials + 1):
        ciphertext, actual = encryption_oracle(b"A" * 64)
        detected = detect_mode(ciphertext)
        correct += detected == actual
        print(f"Trial {index:02d}: actual={actual}, detected={detected}")

    print(f"Accuracy: {correct}/{trials}")


if __name__ == "__main__":
    main()
