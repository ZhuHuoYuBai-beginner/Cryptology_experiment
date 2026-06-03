from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "AES for Challenges"))
from aes_utils import pkcs7_unpad


def is_valid_pkcs7(data: bytes, block_size: int = 16) -> bool:
    try:
        pkcs7_unpad(data, block_size)
        return True
    except ValueError:
        return False


def main() -> None:
    tests = [
        b"ICE ICE BABY\x04\x04\x04\x04",
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x01\x02\x03\x04",
    ]

    for item in tests:
        print(f"{item!r} -> {is_valid_pkcs7(item)}")

    print(f"Valid unpad result: {pkcs7_unpad(tests[0])!r}")


if __name__ == "__main__":
    main()
