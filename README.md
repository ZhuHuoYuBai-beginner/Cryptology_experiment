# Cryptology Experiment

用于密码学课程实验与基础密码分析练习的 Python 仓库，当前内容覆盖两部分：

- `experiment 1`：Cryptopals Set 1 风格的编码、XOR 与 SHA1 口令破解实验
- `experiment 2`：围绕 AES-128、PKCS#7、ECB/CBC 模式与典型攻击场景的实验

> 本仓库仅用于课程实验、学习和授权环境下的安全研究，请勿用于未授权的口令破解或系统攻击。



## 仓库结构

```text
Cryptology experiment/
|-- README.md
|-- .gitignore
|-- experiment 1/
|   |-- Challenge1/
|   |   `-- hex_to_base64.py
|   |-- Challenge2/
|   |   `-- fixed_xor.py
|   |-- Challenge3/
|   |   `-- single_byte_xor.py
|   |-- Challenge4/
|   |   |-- 4.txt
|   |   `-- detect_single_byte_xor.py
|   |-- Challenge5/
|   |   `-- repeating_key_xor.py
|   |-- Challenge6/
|   |   `-- break_repeating_key_xor.py
|   `-- SHA1/
|       |-- crack_sha1_password.py
|       |-- keyboard_fingerprints.png
|       `-- mtc3-kitrub-07-sha1crack-en.pdf
`-- experiment 2/
    |-- AES for Challenges/
    |   `-- aes_utils.py
    |-- AES KEY/
    |   |-- aes_bac_solution.py
    |   `-- mtc3-hick-01-BAC-en.pdf
    |-- Challenge1/
    |   `-- pkcs7_padding.py
    |-- Challenge2/
    |   `-- cbc_mode.py
    |-- Challenge3/
    |   `-- ecb_cbc_detection_oracle.py
    |-- Challenge4/
    |   `-- byte_at_a_time_ecb_simple.py
    |-- Challenge5/
    |   `-- ecb_cut_and_paste.py
    |-- Challenge6/
    |   `-- byte_at_a_time_ecb_harder.py
    |-- Challenge7/
    |   `-- pkcs7_padding_validation.py
    `-- Challenge8/
        `-- cbc_bit_flipping_attacks.py

```

## 实验一说明

`experiment 1` 主要对应基础编码与异或分析练习：

| 目录 | 脚本 | 作用 |
| --- | --- | --- |
| `Challenge1` | `hex_to_base64.py` | 将十六进制字符串转换为 Base64 |
| `Challenge2` | `fixed_xor.py` | 对等长字节串执行固定异或 |
| `Challenge3` | `single_byte_xor.py` | 用英文频率评分暴力破解单字节 XOR |
| `Challenge4` | `detect_single_byte_xor.py` | 在多行密文中检测被单字节 XOR 加密的一行 |
| `Challenge5` | `repeating_key_xor.py` | 实现重复密钥 XOR |
| `Challenge6` | `break_repeating_key_xor.py` | 通过汉明距离估计密钥长度并破解重复密钥 XOR |
| `SHA1` | `crack_sha1_password.py` | 基于键盘指纹候选集匹配 SHA1 哈希 |

## 实验二说明

`experiment 2` 主要围绕 AES-128 及其常见工作模式和攻击方式展开。

### 公共工具

| 目录 | 脚本 | 作用 |
| --- | --- | --- |
| `AES for Challenges` | `aes_utils.py` | 提供 AES-128、ECB/CBC、PKCS#7、分块分析等公共函数 |

### 挑战脚本

| 目录 | 脚本 | 作用 |
| --- | --- | --- |
| `Challenge1` | `pkcs7_padding.py` | 演示 PKCS#7 填充 |
| `Challenge2` | `cbc_mode.py` | 实现 AES-CBC 加解密；若缺少 `10.txt`，自动执行自测 |
| `Challenge3` | `ecb_cbc_detection_oracle.py` | 构造随机 ECB/CBC 预言机并检测加密模式 |
| `Challenge4` | `byte_at_a_time_ecb_simple.py` | 实现简单场景下的逐字节 ECB 后缀恢复 |
| `Challenge5` | `ecb_cut_and_paste.py` | 演示 ECB cut-and-paste 伪造管理员资料 |
| `Challenge6` | `byte_at_a_time_ecb_harder.py` | 在带固定随机前缀的情况下恢复 ECB 后缀 |
| `Challenge7` | `pkcs7_padding_validation.py` | 验证 PKCS#7 填充是否合法 |
| `Challenge8` | `cbc_bit_flipping_attacks.py` | 演示 CBC bit-flipping 攻击构造管理员权限 |
| `AES KEY` | `aes_bac_solution.py` | 根据 BAC/MRZ 信息推导密钥并解出题目中的 AES-CBC 密文 |

## 环境要求

- Python 3.10 或更高版本
- `experiment 1` 中部分脚本可能依赖 `requests`
- `experiment 2` 当前脚本均可使用标准库运行

安装依赖：

```bash
pip install requests
```

## 运行方式

在仓库根目录下执行：

```bash
python "experiment 1/Challenge1/hex_to_base64.py"
python "experiment 1/Challenge6/break_repeating_key_xor.py"
python "experiment 2/Challenge3/ecb_cbc_detection_oracle.py"
python "experiment 2/AES KEY/aes_bac_solution.py"
```