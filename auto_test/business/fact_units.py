"""Recognize units without granting permission to invent their numeric values."""
import re


def supported_notation(token, evidence):
    token = token.casefold()
    if token in {"phr", "min"}:
        return True  # Unit labels, not a product identity or quantity.
    if token == "gf":
        return bool(re.search(r"玻纤|玻璃纤维|glass\s*fib(?:er|re)|\bgf\b", evidence, re.I))
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(min|kg|phr)", token)
    if not match:
        return False
    number, unit = match.groups()
    aliases = {"min": r"分钟|min", "kg": r"公斤|千克|kg", "phr": r"份|phr"}
    return bool(re.search(r"(?<![\d.])" + re.escape(number) + r"\s*(?:" + aliases[unit] + r")(?![a-z\d])", evidence, re.I))
