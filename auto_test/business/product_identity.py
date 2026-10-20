"""Small explicit alias vocabulary; no fuzzy substitution of product models."""
import re
import unicodedata


def normalized_product(text):
    text = unicodedata.normalize("NFKC", str(text)).casefold()
    for name, replacement in (("巴斯夫", "basf"), ("利安隆", "rianlon"), ("北京极易", "jiyi")):
        text = text.replace(name, replacement)
    return re.sub(r"[\W_]+", "", text)


def product_options(anchor):
    # '/' in a source denotes explicit alternative products, not a new model.
    return [part.strip() for part in re.split(r"\s+[/／]\s+", anchor) if part.strip()]


def product_mentioned(message, anchor):
    text = normalized_product(message)
    for option in product_options(anchor):
        key = normalized_product(option)
        variants = {key}
        if "basf" in key and "1076" in key:
            variants.update({"basf1076", "basfirganox1076", "irganox1076"})
        # Reject digit-prefix matches: 10760 must not satisfy 1076.
        if any(re.search(re.escape(v) + (r"(?!\d)" if v[-1:].isdigit() else ""), text) for v in variants):
            return True
    return False


def alias_support(anchor):
    if product_mentioned(anchor, "巴斯夫1076"):
        return " BASF Irganox 1076 巴斯夫1076 "
    return ""
