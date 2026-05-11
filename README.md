# Cryptology Experiment

这是一个用于密码学课程实验和基础密码分析练习的 Python 仓库。当前内容主要围绕编码转换、异或加密/破解、重复密钥 XOR 破解，以及基于键盘指纹线索的 SHA1 口令爆破实验。

> 本项目仅用于课程实验、学习和授权环境下的安全研究，不应用于未授权的口令破解或系统攻击。

## 仓库结构

```text
Cryptology_experiment/
├── .gitignore
├── README.md
└── experiment 1/
    ├── Challenge1/
    │   └── hex_to_base64.py
    ├── Challenge2/
    │   └── fixed_xor.py
    ├── Challenge3/
    │   └── single_byte_xor.py
    ├── Challenge4/
    │   ├── 4.txt
    │   └── detect_single_byte_xor.py
    ├── Challenge5/
    │   └── repeating_key_xor.py
    ├── Challenge6/
    │   └── break_repeating_key_xor.py
    └── SHA1/
        ├── crack_sha1_password.py
        ├── keyboard_fingerprints.png
        └── mtc3-kitrub-07-sha1crack-en.pdf
```

## 实验内容

| 目录 | 脚本 | 主要功能 |
| --- | --- | --- |
| `Challenge1` | `hex_to_base64.py` | 将十六进制字符串转换为 Base64 字符串 |
| `Challenge2` | `fixed_xor.py` | 对两个等长字节序列执行固定 XOR |
| `Challenge3` | `single_byte_xor.py` | 使用英文频率评分暴力破解单字节 XOR |
| `Challenge4` | `detect_single_byte_xor.py` | 在多行密文中检测被单字节 XOR 加密的一行 |
| `Challenge5` | `repeating_key_xor.py` | 使用重复密钥 XOR 进行加密/解密 |
| `Challenge6` | `break_repeating_key_xor.py` | 通过汉明距离猜测密钥长度并破解重复密钥 XOR |
| `SHA1` | `crack_sha1_password.py` | 根据键盘指纹候选字符枚举口令并匹配 SHA1 哈希 |

## 环境要求

- Python 3.10 或更高版本
- 实验一Cryptopals的第 4、6 题默认从 Cryptopals 下载数据，需要 `requests`

安装依赖：
```bash
pip install requests
```