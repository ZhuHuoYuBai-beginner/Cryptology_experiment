from typing import Tuple

# 标准英文字符频率表（包含空格，这是英文文本中最常见的字符）
ENGLISH_FREQ = {
    ' ': 0.15, 'e': 0.12702, 't': 0.09056, 'a': 0.08167, 'o': 0.07507,
    'i': 0.06966, 'n': 0.06749, 's': 0.06327, 'h': 0.06094, 'r': 0.05987,
    'd': 0.04253, 'l': 0.04025, 'c': 0.02782, 'u': 0.02758, 'm': 0.02406,
    'w': 0.02360, 'f': 0.02228, 'g': 0.02015, 'y': 0.01974, 'p': 0.01929,
    'b': 0.01492, 'v': 0.00978, 'k': 0.00772, 'j': 0.00153, 'x': 0.00150,
    'q': 0.00095, 'z': 0.00074
}


def score_plaintext(text: bytes) -> float:
    """
    对解密后的字节文本进行英文评分
    评分越高，文本越可能是有意义的英文
    :param text: 待评分的字节文本
    :return: 评分值
    """
    score = 0.0
    for byte in text:
        char = chr(byte).lower()
        if char in ENGLISH_FREQ:
            score += ENGLISH_FREQ[char]
        else:
            # 对非英文字符进行惩罚
            score -= 0.1
    return score


def single_byte_xor(ciphertext: bytes, key: int) -> bytes:
    """
    使用单字节密钥对密文进行异或解密
    :param ciphertext: 密文字节
    :param key: 单字节密钥(0-255)
    :return: 解密后的明文字节
    """
    return bytes(byte ^ key for byte in ciphertext)


def break_single_byte_xor(ciphertext: bytes) -> Tuple[int, bytes, float]:
    """
    暴力破解单字节XOR密码
    :param ciphertext: 密文字节
    :return: (最佳密钥, 最佳明文, 最佳评分)
    """
    best_score = -float('inf')
    best_key = 0
    best_plaintext = b''

    # 遍历所有可能的单字节密钥(0-255)
    for key in range(256):
        plaintext = single_byte_xor(ciphertext, key)
        current_score = score_plaintext(plaintext)

        if current_score > best_score:
            best_score = current_score
            best_key = key
            best_plaintext = plaintext

    return best_key, best_plaintext, best_score


# 题目给出的测试用例
if __name__ == "__main__":
    hex_ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    # 第一步：将十六进制密文解码为原始字节
    ciphertext_bytes = bytes.fromhex(hex_ciphertext)

    # 第二步：暴力破解单字节XOR
    key, plaintext, score = break_single_byte_xor(ciphertext_bytes)

    # 输出结果
    print(f"找到的最佳密钥: {chr(key)} (ASCII码: {key})")
    print(f"解密后的明文: {plaintext.decode('utf-8')}")
    print(f"明文评分: {score:.4f}")