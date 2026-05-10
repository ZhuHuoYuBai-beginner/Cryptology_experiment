import base64
import requests
from typing import Tuple, List

# 复用挑战3的核心函数
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


# 复用挑战5的核心函数
def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    ciphertext = []
    key_length = len(key)

    for i, byte in enumerate(plaintext):
        key_byte = key[i % key_length]
        ciphertext.append(byte ^ key_byte)

    return bytes(ciphertext)


# 挑战6新增函数1：计算汉明距离（比特差异数）
def hamming_distance(a: bytes, b: bytes) -> int:
    """
    计算两个字节串之间的汉明距离（不同比特的数量）
    :param a: 第一个字节串
    :param b: 第二个字节串
    :return: 汉明距离
    :raises ValueError: 当两个字节串长度不相等时抛出
    """
    if len(a) != len(b):
        raise ValueError("汉明距离计算要求两个字节串长度必须相等")

    distance = 0
    for byte1, byte2 in zip(a, b):
        # 异或后统计1的个数，即为不同比特的数量
        distance += bin(byte1 ^ byte2).count('1')

    return distance


# 挑战6新增函数2：猜测密钥长度
def guess_key_length(ciphertext: bytes, min_len: int = 2, max_len: int = 40, num_blocks: int = 4) -> List[
    Tuple[int, float]]:
    """
    通过汉明距离分析猜测最可能的密钥长度
    :param ciphertext: 密文字节
    :param min_len: 最小猜测密钥长度
    :param max_len: 最大猜测密钥长度
    :param num_blocks: 用于计算平均距离的块数（越多越准确）
    :return: 按归一化汉明距离从小到大排序的(密钥长度, 距离)列表
    """
    key_length_scores = []

    for key_len in range(min_len, max_len + 1):
        # 确保有足够的块进行计算
        if len(ciphertext) < key_len * num_blocks:
            continue

        # 提取前num_blocks个块
        blocks = [ciphertext[i * key_len: (i + 1) * key_len] for i in range(num_blocks)]

        # 计算所有块对之间的平均汉明距离
        total_distance = 0
        num_pairs = 0

        for i in range(num_blocks):
            for j in range(i + 1, num_blocks):
                total_distance += hamming_distance(blocks[i], blocks[j])
                num_pairs += 1

        # 归一化：除以密钥长度，消除长度影响
        normalized_distance = total_distance / num_pairs / key_len
        key_length_scores.append((key_len, normalized_distance))

    # 按归一化距离从小到大排序
    return sorted(key_length_scores, key=lambda x: x[1])


# 挑战6新增函数3：转置密文块
def transpose_blocks(ciphertext: bytes, key_len: int) -> List[bytes]:
    """
    将密文转置为key_len个块，每个块包含密文中所有第i个字节
    这样每个块就相当于一个单字节XOR加密的密文
    :param ciphertext: 密文字节
    :param key_len: 密钥长度
    :return: 转置后的块列表
    """
    transposed = [[] for _ in range(key_len)]

    for i, byte in enumerate(ciphertext):
        transposed[i % key_len].append(byte)

    # 转换为bytes对象
    return [bytes(block) for block in transposed]


# 挑战6主函数：破解重复密钥XOR
def break_repeating_key_xor(ciphertext: bytes) -> Tuple[bytes, bytes]:
    """
    破解重复密钥XOR加密的密文
    :param ciphertext: 密文字节
    :return: (密钥, 明文)
    """
    # 步骤1：猜测最可能的密钥长度（取前3个候选进行验证）
    key_length_candidates = guess_key_length(ciphertext)
    best_key = b''
    best_plaintext = b''
    best_score = -float('inf')

    # 尝试前3个最可能的密钥长度，选择得分最高的结果
    for key_len, _ in key_length_candidates[:3]:
        # 步骤2：转置密文块
        transposed_blocks = transpose_blocks(ciphertext, key_len)

        # 步骤3：逐个破解每个转置块的密钥字节
        key = []
        for block in transposed_blocks:
            key_byte, _, _ = break_single_byte_xor(block)
            key.append(key_byte)

        key = bytes(key)

        # 步骤4：使用得到的密钥解密整个密文
        plaintext = repeating_key_xor(ciphertext, key)

        # 步骤5：评估解密结果的质量
        current_score = score_plaintext(plaintext)

        if current_score > best_score:
            best_score = current_score
            best_key = key
            best_plaintext = plaintext

    return best_key, best_plaintext


# 主程序
if __name__ == "__main__":
    # 第一步：验证汉明距离函数是否正确（题目要求必须通过此验证）
    test_str1 = b"this is a test"
    test_str2 = b"wokka wokka!!!"
    expected_distance = 37
    actual_distance = hamming_distance(test_str1, test_str2)
    print(f"汉明距离验证: 预期={expected_distance}, 实际={actual_distance}")
    print(f"验证结果: {'✅ 通过' if actual_distance == expected_distance else '❌ 失败'}\n")

    if actual_distance != expected_distance:
        print("汉明距离函数错误，无法继续破解！")
        exit(1)

    # 第二步：从Cryptopals官网下载并解码密文
    url = "https://cryptopals.com/static/challenge-data/6.txt"
    response = requests.get(url)
    base64_ciphertext = response.text.replace('\n', '')
    ciphertext = base64.b64decode(base64_ciphertext)

    # 第三步：破解重复密钥XOR
    key, plaintext = break_repeating_key_xor(ciphertext)

    # 输出结果
    print(f"找到的密钥: {key.decode('utf-8')}")
    print(f"\n解密后的明文:\n{plaintext.decode('utf-8')}")