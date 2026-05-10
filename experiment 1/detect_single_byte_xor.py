from typing import Tuple
import requests

# 复用挑战3的核心函数（模块化设计，无需重复编写）
ENGLISH_FREQ = {
    ' ': 0.15, 'e': 0.12702, 't': 0.09056, 'a': 0.08167, 'o': 0.07507,
    'i': 0.06966, 'n': 0.06749, 's': 0.06327, 'h': 0.06094, 'r': 0.05987,
    'd': 0.04253, 'l': 0.04025, 'c': 0.02782, 'u': 0.02758, 'm': 0.02406,
    'w': 0.02360, 'f': 0.02228, 'g': 0.02015, 'y': 0.01974, 'p': 0.01929,
    'b': 0.01492, 'v': 0.00978, 'k': 0.00772, 'j': 0.00153, 'x': 0.00150,
    'q': 0.00095, 'z': 0.00074
}


def score_plaintext(text: bytes) -> float:
    score = 0.0
    for byte in text:
        char = chr(byte).lower()
        if char in ENGLISH_FREQ:
            score += ENGLISH_FREQ[char]
        else:
            score -= 0.1
    return score


def single_byte_xor(ciphertext: bytes, key: int) -> bytes:
    return bytes(byte ^ key for byte in ciphertext)


def break_single_byte_xor(ciphertext: bytes) -> Tuple[int, bytes, float]:
    best_score = -float('inf')
    best_key = 0
    best_plaintext = b''

    for key in range(256):
        plaintext = single_byte_xor(ciphertext, key)
        current_score = score_plaintext(plaintext)

        if current_score > best_score:
            best_score = current_score
            best_key = key
            best_plaintext = plaintext

    return best_key, best_plaintext, best_score


# 挑战4新增：批量检测单字符XOR加密的密文
def detect_single_byte_xor(ciphertexts: list[bytes]) -> Tuple[int, bytes, float, int]:
    """
    从多个密文中检测出被单字节XOR加密的那一个
    :param ciphertexts: 密文字节列表
    :return: (最佳密钥, 最佳明文, 最佳评分, 密文所在行号)
    """
    overall_best_score = -float('inf')
    overall_best_key = 0
    overall_best_plaintext = b''
    overall_best_line = 0

    for line_num, ciphertext in enumerate(ciphertexts):
        key, plaintext, score = break_single_byte_xor(ciphertext)

        if score > overall_best_score:
            overall_best_score = score
            overall_best_key = key
            overall_best_plaintext = plaintext
            overall_best_line = line_num + 1  # 行号从1开始计数

    return overall_best_key, overall_best_plaintext, overall_best_score, overall_best_line


# 主程序
if __name__ == "__main__":
    # 方式1：直接从Cryptopals官网下载4.txt文件（推荐，无需手动保存）
    url = "https://cryptopals.com/static/challenge-data/4.txt"
    response = requests.get(url)
    lines = response.text.splitlines()

    # 方式2：读取本地4.txt文件（如果已经下载到本地）
    # with open("4.txt", "r") as f:
    #     lines = f.read().splitlines()

    # 将每一行十六进制字符串解码为字节
    ciphertexts = [bytes.fromhex(line) for line in lines if line.strip()]

    # 检测被单字节XOR加密的密文
    key, plaintext, score, line_num = detect_single_byte_xor(ciphertexts)

    # 输出结果
    print(f"找到被加密的行号: {line_num}")
    print(f"解密密钥: {chr(key)} (ASCII码: {key})")
    print(f"解密后的明文: {plaintext.decode('utf-8').strip()}")
    print(f"明文评分: {score:.4f}")