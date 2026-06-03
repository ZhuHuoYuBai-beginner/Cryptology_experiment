from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "AES for Challenges"))
from aes_utils import pkcs7_pad


def main() -> None:
    plaintext = b"YELLOW SUBMARINE"
    padded = pkcs7_pad(plaintext, 20)

    print(f"Original: {plaintext!r}")
    print(f"Padded:   {padded!r}")
    print(f"Hex:      {padded.hex()}")
    print(f"Passed:   {padded == b'YELLOW SUBMARINE' + bytes([4]) * 4}")


if __name__ == "__main__":
    main()
