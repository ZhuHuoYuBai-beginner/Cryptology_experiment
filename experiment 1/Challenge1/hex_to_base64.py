import base64

def hex_to_base64(hex_str):
    # 第一步：将十六进制字符串解码为原始字节（核心操作）
    raw_bytes = bytes.fromhex(hex_str)
    # 第二步：将原始字节编码为Base64字符串
    base64_str = base64.b64encode(raw_bytes).decode('utf-8')
    return base64_str

# 题目给出的输入
hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
# 题目给出的预期输出
expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

# 执行转换并验证
result = hex_to_base64(hex_input)
print(f"转换结果: {result}")
print(f"验证结果: {'通过' if result == expected_output else '失败'}")