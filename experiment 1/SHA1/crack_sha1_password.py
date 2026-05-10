#!/usr/bin/env python3
"""
Assumptions from the PDF:
- Target SHA1: 67ae1a64661ac8b4494666f58c4822408dd0a3e4
- Fingerprints are on these main keyboard keys: Q, W, 5, 8, 0, I, +, N
- The PDF says to use the German keyboard layout.

- Shift+5 -> %
- Shift+8 -> (
- Shift+0 -> =
- Shift++ -> *
"""

from __future__ import annotations

import hashlib
import itertools
import math
import re
from pathlib import Path
from typing import Iterator


PDF_FILE = Path("mtc3-kitrub-07-sha1crack-en.pdf")
DEFAULT_TARGET_SHA1 = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

GERMAN_KEYBOARD_CANDIDATES: tuple[tuple[str, str], ...] = (
    ("q", "Q"),
    ("w", "W"),
    ("5", "%"),
    ("8", "("),
    ("0", "="),
    ("i", "I"),
    ("+", "*"),
    ("n", "N"),
)


def sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def extract_target_sha1_from_pdf(pdf_path: Path) -> str | None:
    if not pdf_path.exists():
        return None

    try:
        from pypdf import PdfReader
    except ImportError:
        return None

    reader = PdfReader(str(pdf_path))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    match = re.search(r"\b[a-fA-F0-9]{40}\b", text)
    return match.group(0).lower() if match else None


def candidate_passwords(
    keyboard_candidates: tuple[tuple[str, str], ...],
) -> Iterator[str]:
    for key_order in itertools.permutations(keyboard_candidates):
        for chars in itertools.product(*key_order):
            yield "".join(chars)


def crack_sha1(
    target_sha1: str,
    keyboard_candidates: tuple[tuple[str, str], ...] = GERMAN_KEYBOARD_CANDIDATES,
) -> tuple[str, int] | None:
    target_sha1 = target_sha1.lower()

    for checked_count, password in enumerate(candidate_passwords(keyboard_candidates), 1):
        if sha1_hex(password) == target_sha1:
            return password, checked_count

    return None


def main() -> None:
    target_sha1 = extract_target_sha1_from_pdf(PDF_FILE) or DEFAULT_TARGET_SHA1
    key_count = len(GERMAN_KEYBOARD_CANDIDATES)
    search_space = math.factorial(key_count) * 2**key_count

    print(f"Target SHA1: {target_sha1}")
    print(f"Search space: {search_space} candidates")

    result = crack_sha1(target_sha1)
    if result is None:
        print("Password not found.")
        return

    password, checked_count = result
    print(f"Password: {password}")
    print(f"Checked: {checked_count}")
    print(f"Verify: {sha1_hex(password)}")


if __name__ == "__main__":
    main()
