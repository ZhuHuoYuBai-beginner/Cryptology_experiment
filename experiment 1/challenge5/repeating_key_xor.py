def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    """
    使用重复密钥异或算法对明文进行加密/解密
    由于异或运算的可逆性，同一个函数既可以加密也可以解密
    :param plaintext: 明文字节（加密时）或密文字节（解密时）
    :param key: 密钥字节
    :return: 加密后的密文字节或解密后的明文字节
    """
    ciphertext = []
    key_length = len(key)

    for i, byte in enumerate(plaintext):
        # 核心逻辑：循环使用密钥，第i个字节与密钥第i%key_length个字节异或
        key_byte = key[i % key_length]
        ciphertext.append(byte ^ key_byte)

    return bytes(ciphertext)


# 题目给出的测试用例
if __name__ == "__main__":
    # 注意：必须包含题目中的换行符\n，否则结果会不一致
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    # 执行加密
    ciphertext = repeating_key_xor(plaintext, key)
    ciphertext_hex = ciphertext.hex()

    # 输出结果并验证
    print(f"加密结果(十六进制): {ciphertext_hex}")
    print(f"验证结果: {'✅ 通过' if ciphertext_hex == expected_hex else '❌ 失败'}")

    # 额外验证：异或运算的可逆性（用同一个函数解密）
    decrypted_plaintext = repeating_key_xor(ciphertext, key)
    print(f"\n解密验证结果:\n{decrypted_plaintext.decode('utf-8')}")