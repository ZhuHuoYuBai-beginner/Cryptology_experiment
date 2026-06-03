from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "RSA for Challenges"))
from rsa_utils import build_keypair, decrypt_int, encrypt_int


def main() -> None:
    p = 61
    q = 53
    e = 17
    message = 65

    keypair = build_keypair(p, q, e)
    ciphertext = encrypt_int(message, keypair.e, keypair.n)
    recovered = decrypt_int(ciphertext, keypair.d, keypair.n)

    print(f"p = {keypair.p}, q = {keypair.q}")
    print(f"n = {keypair.n}, phi = {keypair.phi}")
    print(f"public exponent e = {keypair.e}")
    print(f"private exponent d = {keypair.d}")
    print(f"message m = {message}")
    print(f"ciphertext c = {ciphertext}")
    print(f"decrypted message = {recovered}")
    print(f"round-trip success = {recovered == message}")


if __name__ == "__main__":
    main()
