def fixed_xor(buffer1: bytes, buffer2: bytes) -> bytes:
    """
    对两个等长的字节缓冲区执行逐字节异或操作
    :param buffer1: 第一个字节缓冲区
    :param buffer2: 第二个字节缓冲区
    :return: 异或后的字节缓冲区
    :raises ValueError: 当两个缓冲区长度不相等时抛出
    """
    if len(buffer1) != len(buffer2):
        raise ValueError("固定异或操作要求两个缓冲区长度必须完全相等")

    # 逐字节进行异或运算
    return bytes(a ^ b for a, b in zip(buffer1, buffer2))


# 题目给出的测试用例
if __name__ == "__main__":
    hex_input1 = "1c0111001f010100061a024b53535009181c"
    hex_input2 = "686974207468652062756c6c277320657965"
    expected_hex_output = "746865206b696420646f6e277420706c6179"

    # 第一步：将十六进制字符串解码为原始字节（核心操作）
    raw_buffer1 = bytes.fromhex(hex_input1)
    raw_buffer2 = bytes.fromhex(hex_input2)

    # 第二步：执行固定异或操作
    result_bytes = fixed_xor(raw_buffer1, raw_buffer2)

    # 第三步：将结果编码为十六进制字符串用于验证
    result_hex = result_bytes.hex()

    # 输出结果并验证
    print(f"异或结果(十六进制): {result_hex}")
    print(f"验证结果: {'通过' if result_hex == expected_hex_output else '失败'}")

    # 额外：解码为明文查看（本题解密后为英文句子）
    print(f"解密后明文: {result_bytes.decode('utf-8')}")
