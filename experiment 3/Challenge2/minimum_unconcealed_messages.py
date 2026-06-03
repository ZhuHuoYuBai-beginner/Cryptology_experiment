from math import gcd
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "RSA for Challenges"))
from rsa_utils import unconcealed_message_count


P = 1009
Q = 3643
PHI = (P - 1) * (Q - 1)


def minimal_unconcealed_count(p: int, q: int) -> int:
    # For odd primes p and q, every legal e must be odd, so e - 1 is even.
    # Therefore gcd(e - 1, p - 1) >= 2 and gcd(e - 1, q - 1) >= 2.
    return (1 + 2) * (1 + 2)


def candidate_values() -> list[int]:
    target = minimal_unconcealed_count(P, Q)
    values: list[int] = []

    for e in range(3, PHI, 2):
        if gcd(e, PHI) != 1:
            continue
        if unconcealed_message_count(e, P, Q) == target:
            values.append(e)

    return values


def main() -> None:
    values = candidate_values()
    target = minimal_unconcealed_count(P, Q)

    print(f"p = {P}, q = {Q}")
    print(f"phi = {PHI}")
    print(f"minimal unconcealed message count = {target}")
    print(f"number of valid e values = {len(values)}")
    print(f"sum of all valid e values = {sum(values)}")
    print(f"first 20 values = {values[:20]}")


if __name__ == "__main__":
    main()
