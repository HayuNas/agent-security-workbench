"""CorpusItem 的最小实现，不依赖模型，也不直接调用测试接口。"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Mapping, Sequence


CORPUS_REFERENCES_DIR = Path(__file__).resolve().parent / "references"
DEFAULT_CORPUS_PATH = CORPUS_REFERENCES_DIR / "prompt_leakage_initial_v1.json"
ITEM_ID_RE = re.compile(r"^[A-Z][A-Z0-9-]{5,63}$")
CORPUS_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
REVIEW_STATUSES = frozenset({"draft", "approved", "rejected"})


class CorpusDataError(ValueError):
    """语料库无法安全审阅或编译。"""


def _text_list(value: Any) -> list[str]:
    values = value if isinstance(value, list) else ([] if value is None else [value])
    return [str(item).strip() for item in values if str(item).strip()]


def _normalise_messages(messages: Sequence[str]) -> str:
    return re.sub(
        r"[^0-9A-Za-z\u4e00-\u9fff]+",
        "",
        "\n".join(messages),
    ).casefold()


def _character_ngrams(value: str, size: int = 3) -> set[str]:
    if not value:
        return set()
    if len(value) <= size:
        return {value}
    return {value[index : index + size] for index in range(len(value) - size + 1)}


def message_similarity(left: Sequence[str], right: Sequence[str]) -> float:
    """同时使用字符三元组和序列相似度，减少只换标点/同一前缀的重复。"""

    left_text = _normalise_messages(left)
    right_text = _normalise_messages(right)
    left_grams = _character_ngrams(left_text)
    right_grams = _character_ngrams(right_text)
    jaccard = (
        len(left_grams & right_grams) / len(left_grams | right_grams)
        if left_grams and right_grams
        else 0.0
    )
    return max(jaccard, SequenceMatcher(None, left_text, right_text).ratio())


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusDataError(f"无法读取语料库：{path}") from exc
    if not isinstance(value, Mapping):
        raise CorpusDataError(f"{path.name} 必须是 JSON object")
    return copy.deepcopy(dict(value))


def load_corpus(path: Path = DEFAULT_CORPUS_PATH) -> dict[str, Any]:
    """读取并完成结构校验；内容质量和重复项由 audit_corpus 统一报告。"""

    corpus = _read_json(path)
    corpus_id = str(corpus.get("corpus_id") or "").strip()
    if not CORPUS_ID_RE.fullmatch(corpus_id):
        raise CorpusDataError(f"{path.name}: corpus_id 格式无效：{corpus_id!r}")
    compiler = corpus.get("compiler")
    if not isinstance(compiler, Mapping):
        raise CorpusDataError(f"{path.name}: compiler 必须是 object")
    compiler = copy.deepcopy(dict(compiler))
    if str(compiler.get("type") or "") != "epe_query_pack":
        raise CorpusDataError(f"{path.name}: 目前只支持 epe_query_pack 编译")
    query_pack_id = str(compiler.get("query_pack_id") or "").strip()
    if not CORPUS_ID_RE.fullmatch(query_pack_id):
        raise CorpusDataError(f"{path.name}: compiler.query_pack_id 格式无效")
    max_turns = int(compiler.get("max_turns") or 1)
    if str(compiler.get("session_policy") or "") != "fresh_session":
        raise CorpusDataError(f"{path.name}: EPE Corpus 必须使用 fresh_session")
    if max_turns != 1:
        raise CorpusDataError(f"{path.name}: EPE Corpus 当前必须严格单轮")

    policy = corpus.get("quality_policy") or {}
    if not isinstance(policy, Mapping):
        raise CorpusDataError(f"{path.name}: quality_policy 必须是 object")
    policy = copy.deepcopy(dict(policy))
    duplicate_threshold = float(policy.get("duplicate_threshold") or 0.82)
    min_quality_score = int(policy.get("min_quality_score") or 75)
    min_chars = int(policy.get("min_chars") or 12)
    max_chars = int(policy.get("max_chars") or 240)
    if not 0.5 <= duplicate_threshold <= 1.0:
        raise CorpusDataError(f"{path.name}: duplicate_threshold 必须位于 0.5..1")
    if not 1 <= min_quality_score <= 100:
        raise CorpusDataError(f"{path.name}: min_quality_score 必须位于 1..100")
    if min_chars < 1 or max_chars < min_chars:
        raise CorpusDataError(f"{path.name}: 字符长度策略无效")

    raw_items = corpus.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise CorpusDataError(f"{path.name}: items 必须是非空数组")
    items: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for position, raw in enumerate(raw_items, start=1):
        if not isinstance(raw, Mapping):
            raise CorpusDataError(f"{path.name}: items[{position}] 必须是 object")
        item = copy.deepcopy(dict(raw))
        item_id = str(item.get("item_id") or "").strip()
        if not ITEM_ID_RE.fullmatch(item_id) or item_id in seen_ids:
            raise CorpusDataError(
                f"{path.name}: item_id 缺失、重复或格式无效：{item_id!r}"
            )
        seen_ids.add(item_id)
        messages = _text_list(item.get("messages"))
        if len(messages) != 1:
            raise CorpusDataError(f"{path.name}: {item_id} 必须且只能有一条消息")
        review_status = str(item.get("review_status") or "draft").strip()
        if review_status not in REVIEW_STATUSES:
            raise CorpusDataError(
                f"{path.name}: {item_id} review_status 无效：{review_status!r}"
            )
        items.append(
            {
                **item,
                "item_id": item_id,
                "seed_family": str(item.get("seed_family") or "").strip(),
                "messages": messages,
                "variant_axes": _text_list(item.get("variant_axes")),
                "source_ref": str(item.get("source_ref") or "").strip(),
                "review_status": review_status,
            }
        )

    serialised = json.dumps(corpus, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return {
        **corpus,
        "schema_version": str(corpus.get("schema_version") or "1.0-corpus"),
        "corpus_id": corpus_id,
        "compiler": {
            **compiler,
            "query_pack_id": query_pack_id,
            "max_turns": max_turns,
            "session_policy": "fresh_session",
        },
        "quality_policy": {
            **policy,
            "duplicate_threshold": duplicate_threshold,
            "min_quality_score": min_quality_score,
            "min_chars": min_chars,
            "max_chars": max_chars,
        },
        "items": items,
        "source_file": str(path.resolve()),
        "snapshot_sha256": hashlib.sha256(serialised).hexdigest(),
    }


def audit_corpus(corpus: Mapping[str, Any]) -> dict[str, Any]:
    """给每个条目生成可解释分数和晋级结论；模型自评不参与。"""

    items = [dict(item) for item in corpus.get("items") or []]
    policy = dict(corpus.get("quality_policy") or {})
    threshold = float(policy.get("duplicate_threshold") or 0.82)
    min_score = int(policy.get("min_quality_score") or 75)
    min_chars = int(policy.get("min_chars") or 12)
    max_chars = int(policy.get("max_chars") or 240)
    normalised = {
        str(item.get("item_id") or ""): _normalise_messages(
            _text_list(item.get("messages"))
        )
        for item in items
    }
    results: list[dict[str, Any]] = []
    pair_duplicates: list[dict[str, Any]] = []
    item_status = {
        str(item.get("item_id") or ""): str(
            item.get("review_status") or "draft"
        )
        for item in items
    }
    status_priority = {"approved": 2, "draft": 1, "rejected": 0}
    nearest: dict[str, tuple[str, float]] = {
        item_id: ("", 0.0) for item_id in normalised
    }
    for left_index, left in enumerate(items):
        left_id = str(left.get("item_id") or "")
        for right in items[left_index + 1 :]:
            right_id = str(right.get("item_id") or "")
            similarity = message_similarity(
                _text_list(left.get("messages")), _text_list(right.get("messages"))
            )
            if similarity > nearest[left_id][1]:
                nearest[left_id] = (right_id, similarity)
            if similarity > nearest[right_id][1]:
                nearest[right_id] = (left_id, similarity)
            if similarity >= threshold:
                if status_priority[item_status[right_id]] > status_priority[item_status[left_id]]:
                    kept_id, blocked_id = right_id, left_id
                else:
                    kept_id, blocked_id = left_id, right_id
                pair_duplicates.append(
                    {
                        "left_item_id": left_id,
                        "right_item_id": right_id,
                        "kept_item_id": kept_id,
                        "blocked_item_id": blocked_id,
                        "similarity": round(similarity, 4),
                        "exact": normalised[left_id] == normalised[right_id],
                    }
                )

    duplicate_ids = {pair["blocked_item_id"] for pair in pair_duplicates}
    for item in items:
        item_id = str(item.get("item_id") or "")
        messages = _text_list(item.get("messages"))
        text_length = len(messages[0]) if messages else 0
        issues: list[str] = []
        if not str(item.get("seed_family") or "").strip():
            issues.append("missing_seed_family")
        if not _text_list(item.get("variant_axes")):
            issues.append("missing_variant_axes")
        if not str(item.get("source_ref") or "").strip():
            issues.append("missing_source_ref")
        if not min_chars <= text_length <= max_chars:
            issues.append("message_length_out_of_policy")
        if item_id in duplicate_ids:
            issues.append("near_duplicate")
        status = str(item.get("review_status") or "draft")
        structural_score = 40 if not issues else max(0, 40 - 10 * len(issues))
        review_score = 20 if status == "approved" else 0
        specificity_score = (
            (10 if str(item.get("seed_family") or "").strip() else 0)
            + (10 if _text_list(item.get("variant_axes")) else 0)
        )
        diversity_score = round(20 * (1.0 - nearest[item_id][1]), 2)
        quality_score = round(
            structural_score + review_score + specificity_score + diversity_score,
            2,
        )
        promotable = (
            status == "approved"
            and not issues
            and quality_score >= min_score
        )
        results.append(
            {
                "item_id": item_id,
                "review_status": status,
                "quality_score": quality_score,
                "score_components": {
                    "structure": structural_score,
                    "review": review_score,
                    "specificity": specificity_score,
                    "diversity": diversity_score,
                },
                "text_length": text_length,
                "nearest_item_id": nearest[item_id][0],
                "max_similarity": round(nearest[item_id][1], 4),
                "issues": issues,
                "promotable": promotable,
            }
        )

    statuses = {
        status: sum(item["review_status"] == status for item in results)
        for status in sorted(REVIEW_STATUSES)
    }
    promotable_ids = [item["item_id"] for item in results if item["promotable"]]
    families = sorted(
        {
            str(item.get("seed_family") or "")
            for item in items
            if str(item.get("seed_family") or "")
        }
    )
    return {
        "corpus_id": str(corpus.get("corpus_id") or ""),
        "snapshot_sha256": str(corpus.get("snapshot_sha256") or ""),
        "item_count": len(items),
        "family_count": len(families),
        "families": families,
        "review_status_counts": statuses,
        "duplicate_pair_count": len(pair_duplicates),
        "duplicate_pairs": pair_duplicates,
        "promotable_count": len(promotable_ids),
        "promotable_item_ids": promotable_ids,
        "items": results,
    }


def compile_epe_query_pack(corpus: Mapping[str, Any]) -> dict[str, Any]:
    """只把通过静态质量门禁且已人工批准的条目编译为现有 EPE 格式。"""

    compiler = dict(corpus.get("compiler") or {})
    if str(compiler.get("type") or "") != "epe_query_pack":
        raise CorpusDataError("Corpus 不是 EPE Query Pack 编译目标")
    audit = audit_corpus(corpus)
    promotable = set(audit["promotable_item_ids"])
    provenance_fields = (
        "source_dataset",
        "source_dataset_index",
        "source_dataset_sha256",
        "source_prompt_sha256",
        "source_prompt_preserved",
    )
    queries = [
        {
            "query_id": str(item.get("item_id") or ""),
            "seed_family": str(item.get("seed_family") or ""),
            "messages": _text_list(item.get("messages")),
            "variant_axes": _text_list(item.get("variant_axes")),
            "corpus_id": str(corpus.get("corpus_id") or ""),
            "corpus_source_ref": str(item.get("source_ref") or ""),
            **{
                field: copy.deepcopy(item[field])
                for field in provenance_fields
                if field in item
            },
        }
        for item in corpus.get("items") or []
        if str(item.get("item_id") or "") in promotable
    ]
    if not queries:
        raise CorpusDataError("Corpus 没有通过审阅与质量门禁的可编译条目")
    return {
        "paper": str(compiler.get("paper") or "Project security corpus"),
        "paper_fidelity": str(compiler.get("paper_fidelity") or "project"),
        "query_pack": str(compiler.get("query_pack_id") or ""),
        "description": str(compiler.get("description") or ""),
        "session_policy": "fresh_session",
        "max_turns": 1,
        "queries": queries,
        "corpus_id": str(corpus.get("corpus_id") or ""),
        "corpus_snapshot_sha256": str(corpus.get("snapshot_sha256") or ""),
        "corpus_source": copy.deepcopy(dict(corpus.get("source") or {})),
        "audit": audit,
    }


def _corpus_files(directory: Path = CORPUS_REFERENCES_DIR) -> list[Path]:
    return sorted(path for path in directory.glob("*.json") if path.is_file())


def list_compiled_query_packs(
    directory: Path = CORPUS_REFERENCES_DIR,
) -> list[dict[str, Any]]:
    packs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in _corpus_files(directory):
        corpus = load_corpus(path)
        compiled = compile_epe_query_pack(corpus)
        pack_id = compiled["query_pack"]
        if pack_id in seen:
            raise CorpusDataError(f"重复 compiler.query_pack_id：{pack_id}")
        seen.add(pack_id)
        packs.append(
            {
                "query_pack": pack_id,
                "corpus_id": compiled["corpus_id"],
                "query_count": len(compiled["queries"]),
                "source_file": corpus["source_file"],
                "snapshot_sha256": corpus["snapshot_sha256"],
            }
        )
    return packs


def load_compiled_query_pack(
    query_pack: str,
    directory: Path = CORPUS_REFERENCES_DIR,
) -> dict[str, Any] | None:
    clean_id = str(query_pack or "").strip()
    matches: list[dict[str, Any]] = []
    for path in _corpus_files(directory):
        corpus = load_corpus(path)
        if str((corpus.get("compiler") or {}).get("query_pack_id") or "") == clean_id:
            matches.append(compile_epe_query_pack(corpus))
    if len(matches) > 1:
        raise CorpusDataError(f"多个 Corpus 编译为同一 Query Pack：{clean_id}")
    return matches[0] if matches else None


__all__ = [
    "CORPUS_REFERENCES_DIR",
    "DEFAULT_CORPUS_PATH",
    "CorpusDataError",
    "audit_corpus",
    "compile_epe_query_pack",
    "list_compiled_query_packs",
    "load_compiled_query_pack",
    "load_corpus",
    "message_similarity",
]
