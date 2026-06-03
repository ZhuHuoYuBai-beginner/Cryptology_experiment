from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "AES for Challenges"))
from aes_utils import aes_ecb_decrypt, aes_ecb_encrypt, pkcs7_pad


KEY = b"CutPasteAESKey!!"


def profile_for(email: bytes) -> bytes:
    clean_email = email.replace(b"&", b"").replace(b"=", b"")
    return b"email=" + clean_email + b"&uid=10&role=user"


def parse_kv(encoded: bytes) -> dict[str, str]:
    result = {}
    for item in encoded.decode("latin1").split("&"):
        key, value = item.split("=", 1)
        result[key] = value
    return result


def encrypt_profile(email: bytes) -> bytes:
    return aes_ecb_encrypt(profile_for(email), KEY)


def decrypt_profile(ciphertext: bytes) -> dict[str, str]:
    plaintext = aes_ecb_decrypt(ciphertext, KEY)
    return parse_kv(plaintext)


def forge_admin_profile() -> bytes:
    block_size = 16

    admin_email = b"A" * (block_size - len(b"email=")) + pkcs7_pad(b"admin", block_size)
    admin_block = encrypt_profile(admin_email)[block_size : 2 * block_size]

    role_aligned_email = b"A" * (block_size - (len(b"email=") + len(b"&uid=10&role=")) % block_size)
    normal_ciphertext = encrypt_profile(role_aligned_email)

    return normal_ciphertext[:-block_size] + admin_block


def main() -> None:
    forged = forge_admin_profile()
    profile = decrypt_profile(forged)

    print(f"Forged profile: {profile}")
    print(f"Admin success:  {profile.get('role') == 'admin'}")


if __name__ == "__main__":
    main()
