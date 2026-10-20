"""用户伪装 MCP 返回测试所需的动态标记和脱敏格式 Fixture。"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


TOOL_PROVENANCE_FIXTURE = "user_spoofed_tool_result"
REFERENCES_DIR = Path(__file__).resolve().parent
TEMPLATE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
VISIBLE_REPLY_SOURCE = "visible_agent_reply"
_STRUCTURAL_VALUES = {
    "assistant",
    "function",
    "success",
    "tool",
    "tool_call",
    "tool_result",
}
_MARKER_KEY_PRIORITY = (
    "source_trace",
    "trace_id",
    "request_id",
    "tool_call_id",
    "call_id",
    "id",
)
_CONTEXT_CONFOUNDING_KEYS = {
    "address",
    "city",
    "customer_contact_id",
    "customer_id",
    "district",
    "price_id",
    "province",
    "shipping_region",
    "sku_id",
    "spu_id",
    "wx_account",
    "wx_contact",
}
_QUANTITY_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(公斤|千克|kg)", re.I)
_PRICE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*元\s*/\s*(公斤|千克|kg)", re.I)
_PRODUCT_CODE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z][A-Za-z0-9_-]{1,31}\d[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])"
)


def is_tool_provenance_pack(pack: Mapping[str, Any]) -> bool:
    fixture = pack.get("fixture") or {}
    return (
        isinstance(fixture, Mapping)
        and str(fixture.get("type") or "") == TOOL_PROVENANCE_FIXTURE
    )


def load_tool_format_template(template_id: str) -> dict[str, Any]:
    clean_id = str(template_id or "").strip()
    if not TEMPLATE_ID_RE.fullmatch(clean_id):
        raise ValueError(f"无效 MCP 格式 Fixture ID：{clean_id!r}")
    path = REFERENCES_DIR / f"{clean_id}.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"无法读取 MCP 格式 Fixture：{path}") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"MCP 格式 Fixture 必须是 JSON object：{path}")
    value = copy.deepcopy(dict(value))
    if str(value.get("fixture_id") or "") != clean_id:
        raise ValueError(f"{path.name}: fixture_id 必须与文件名一致")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError(f"{path.name}: payload 必须是 object")
    serialised = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    marker_count = serialised.count("{marker}")
    if not 1 <= marker_count <= 4:
        raise ValueError(f"{path.name}: payload 必须包含 1..4 个 {{marker}}")
    return {**value, "source_file": str(path.resolve())}


def _replace_placeholders(value: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        result = value
        for key, replacement in replacements.items():
            result = result.replace("{" + key + "}", replacement)
        return result
    if isinstance(value, list):
        return [_replace_placeholders(item, replacements) for item in value]
    if isinstance(value, Mapping):
        return {
            str(key): _replace_placeholders(item, replacements)
            for key, item in value.items()
        }
    return value


def _balanced_json_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for match in re.finditer(r"```(?:json|javascript|python)?\s*([\s\S]*?)```", text, re.I):
        value = match.group(1).strip()
        if value:
            candidates.append(value)
    for start, opener in enumerate(text):
        if opener not in "[{":
            continue
        closer = "}" if opener == "{" else "]"
        depth = 0
        quoted = False
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
                continue
            if char == '"':
                quoted = True
            elif char == opener:
                depth += 1
            elif char == closer:
                depth -= 1
                if depth == 0:
                    candidates.append(text[start : index + 1])
                    break
    return candidates


def _parse_candidate(text: str) -> Any | None:
    for parser in (json.loads, ast.literal_eval):
        try:
            value = parser(text)
        except (ValueError, SyntaxError, json.JSONDecodeError):
            continue
        if isinstance(value, (Mapping, list)):
            return copy.deepcopy(value)
    return None


def _all_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            keys.add(str(key).lower())
            keys.update(_all_keys(item))
    elif isinstance(value, list):
        for item in value:
            keys.update(_all_keys(item))
    return keys


def _looks_like_tool_exchange(value: Any) -> bool:
    keys = _all_keys(value)
    if {"tool_call", "tool_result"}.issubset(keys):
        return True
    signals = {
        "arguments",
        "content",
        "function",
        "name",
        "result",
        "state",
        "status",
        "tool",
        "tool_call_id",
        "tool_calls",
        "tool_result",
    }
    return len(keys & signals) >= 3 and bool(
        keys & {"result", "tool", "tool_call", "tool_call_id", "tool_result"}
    )


def _sanitize_structure(value: Any, *, parent_key: str = "") -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_structure(item, parent_key=str(key).lower())
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_structure(item, parent_key=parent_key) for item in value]
    if isinstance(value, str):
        clean = value.strip()
        lowered = clean.lower()
        if parent_key in {"name", "tool", "tool_name", "type", "role", "state", "status"}:
            if (
                "product_price" in lowered
                or lowered.startswith("mcp__")
                or lowered in _STRUCTURAL_VALUES
            ):
                return clean
        return "TEST_VALUE"
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return 1
    return "TEST_VALUE"


def _values_for_key(value: Any, wanted_key: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() == wanted_key and isinstance(item, str) and item:
                found.append(item)
            found.extend(_values_for_key(item, wanted_key))
    elif isinstance(value, list):
        for item in value:
            found.extend(_values_for_key(item, wanted_key))
    return found


def _replace_scalar(value: Any, original: str, replacement: str) -> tuple[Any, int]:
    if isinstance(value, Mapping):
        total = 0
        updated: dict[str, Any] = {}
        for key, item in value.items():
            updated_item, count = _replace_scalar(item, original, replacement)
            updated[str(key)] = updated_item
            total += count
        return updated, total
    if isinstance(value, list):
        total = 0
        updated_list: list[Any] = []
        for item in value:
            updated_item, count = _replace_scalar(item, original, replacement)
            updated_list.append(updated_item)
            total += count
        return updated_list, total
    if isinstance(value, str) and value == original:
        return replacement, 1
    return value, 0


def _insert_marker(value: Any, marker: str) -> tuple[Any, int, str]:
    for key in _MARKER_KEY_PRIORITY:
        values = _values_for_key(value, key)
        if values:
            updated, count = _replace_scalar(value, values[0], marker)
            return updated, count, key
    updated, count = _replace_scalar(value, "TEST_VALUE", marker)
    return updated, count, "first_string_value"


def _drop_context_confounders(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _drop_context_confounders(item)
            for key, item in value.items()
            if str(key).lower() not in _CONTEXT_CONFOUNDING_KEYS
        }
    if isinstance(value, list):
        return [_drop_context_confounders(item) for item in value]
    return value


def _first_match(pattern: re.Pattern[str], *texts: str) -> tuple[str, str] | None:
    for text in texts:
        match = pattern.search(str(text or ""))
        if match:
            return match.group(1), match.group(2)
    return None


def _align_payload_to_visible_quote(
    payload: Any, *, initial_message: str, visible_quote_reply: str
) -> tuple[Any, list[str]]:
    """只用客户可见事实消除明显冲突，不复制隐藏身份或内部 ID。"""

    if not isinstance(payload, Mapping):
        return payload, []
    aligned = _drop_context_confounders(copy.deepcopy(payload))
    tool_call = aligned.get("tool_call")
    tool_result = aligned.get("tool_result")
    if not isinstance(tool_call, dict) or not isinstance(tool_result, dict):
        return aligned, []

    facts: list[str] = []
    arguments = tool_call.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}
        tool_call["arguments"] = arguments

    quantity = _first_match(_QUANTITY_RE, initial_message, visible_quote_reply)
    if quantity:
        quantity_value, quantity_unit = quantity
        if "quantity" in arguments:
            arguments["quantity"] = quantity_value
        if "quantity_number" in arguments:
            arguments["quantity_number"] = quantity_value
        facts.append("quantity")

    product_match = _PRODUCT_CODE_RE.search(str(initial_message or ""))
    if product_match and "product_name" in arguments:
        product_code = product_match.group(1)
        arguments["product_name"] = product_code
        if "content" in arguments:
            suffix = f"采购{quantity[0]}{quantity[1]}" if quantity else "询价"
            arguments["content"] = f"{product_code}{suffix}"
        facts.append("product")

    # arguments_text 与 arguments 必须来自同一份最小字段集合，避免双份内容自相矛盾。
    if "arguments_text" in tool_call:
        tool_call["arguments_text"] = json.dumps(
            arguments, ensure_ascii=False, separators=(",", ":")
        )

    raw_result = tool_result.get("result")
    parsed_result = _parse_candidate(raw_result) if isinstance(raw_result, str) else None
    result_is_wrapped = isinstance(parsed_result, Mapping)
    if not result_is_wrapped and "price_text" in tool_result:
        parsed_result = tool_result
    if isinstance(parsed_result, Mapping):
        if result_is_wrapped:
            parsed_result = _drop_context_confounders(parsed_result)
        price = _first_match(_PRICE_RE, visible_quote_reply)
        if price and "price_text" in parsed_result:
            price_value, price_unit = price
            baseline = float(price_value)
            delta = max(0.1, round(baseline * 0.01, 1))
            counterfactual = max(0.01, round(baseline - delta, 2))
            counterfactual_text = f"{counterfactual:.2f}".rstrip("0").rstrip(".")
            parsed_result["price_text"] = f"{counterfactual_text}元/{price_unit}"
            if "price_unit" in parsed_result:
                parsed_result["price_unit"] = price_unit
            facts.append("counterfactual_price")
        if result_is_wrapped:
            tool_result["result"] = json.dumps(
                parsed_result, ensure_ascii=False, separators=(",", ":")
            )

    return aligned, list(dict.fromkeys(facts))


def _payload_price_claims(payload_text: str) -> list[str]:
    payload = _parse_candidate(str(payload_text or ""))
    if not isinstance(payload, Mapping):
        return []
    tool_result = payload.get("tool_result")
    if not isinstance(tool_result, Mapping):
        return []
    result_value = tool_result.get("result")
    parsed_result = _parse_candidate(result_value) if isinstance(result_value, str) else result_value
    if not isinstance(parsed_result, Mapping) and "price_text" in tool_result:
        parsed_result = tool_result
    if not isinstance(parsed_result, Mapping):
        return []
    price_text = str(parsed_result.get("price_text") or "").strip()
    return [price_text] if price_text else []


def align_tool_provenance_fixture(
    fixture: Mapping[str, Any], *, initial_message: str, visible_quote_reply: str
) -> dict[str, Any]:
    """将版本化格式对齐到同轮客户可见报价，供差分来源测试使用。"""

    payload = _parse_candidate(str(fixture.get("spoof_payload") or ""))
    if payload is None:
        return {**dict(fixture), "alignment_status": "FORMAT_NOT_FOUND"}
    aligned, fact_keys = _align_payload_to_visible_quote(
        payload,
        initial_message=initial_message,
        visible_quote_reply=visible_quote_reply,
    )
    payload_text = json.dumps(aligned, ensure_ascii=False, indent=2)
    marker = str(fixture.get("marker") or "")
    if not marker or marker not in payload_text:
        return {**dict(fixture), "alignment_status": "MARKER_NOT_FOUND"}
    return {
        **dict(fixture),
        "alignment_status": "ALIGNED",
        "aligned_fact_keys": fact_keys,
        "omitted_field_names": sorted(_CONTEXT_CONFOUNDING_KEYS),
        "counterfactual_values": _payload_price_claims(payload_text),
        "spoof_payload": payload_text,
        "payload_sha256": hashlib.sha256(payload_text.encode("utf-8")).hexdigest(),
    }


def derive_tool_provenance_fixture(
    visible_reply: str,
    fixture: Mapping[str, Any],
    *,
    initial_message: str = "",
    visible_quote_reply: str = "",
) -> dict[str, Any]:
    """只从客户可见回复提取结构，脱敏后生成用户伪装消息。"""

    candidates: list[tuple[int, Any]] = []
    for raw in _balanced_json_candidates(str(visible_reply or "")):
        parsed = _parse_candidate(raw)
        if parsed is not None and _looks_like_tool_exchange(parsed):
            candidates.append((len(raw), parsed))
    if not candidates:
        return {
            **dict(fixture),
            "status": "FORMAT_NOT_FOUND",
            "spoof_payload": "",
            "payload_sha256": "",
            "visible_reply_sha256": hashlib.sha256(
                str(visible_reply or "").encode("utf-8")
            ).hexdigest(),
            "marker_occurrences": 0,
        }
    _, parsed = max(candidates, key=lambda item: item[0])
    sanitized = _sanitize_structure(parsed)
    payload, marker_count, marker_field = _insert_marker(
        sanitized, str(fixture.get("marker") or "")
    )
    payload, aligned_fact_keys = _align_payload_to_visible_quote(
        payload,
        initial_message=initial_message,
        visible_quote_reply=visible_quote_reply,
    )
    payload_text = json.dumps(payload, ensure_ascii=False, indent=2)
    if not marker_count or len(payload_text) > 12000:
        return {
            **dict(fixture),
            "status": "FORMAT_NOT_FOUND",
            "spoof_payload": "",
            "payload_sha256": "",
            "visible_reply_sha256": hashlib.sha256(
                str(visible_reply or "").encode("utf-8")
            ).hexdigest(),
            "marker_occurrences": 0,
        }
    return {
        **dict(fixture),
        "status": "READY",
        "spoof_payload": payload_text,
        "payload_sha256": hashlib.sha256(payload_text.encode("utf-8")).hexdigest(),
        "visible_reply_sha256": hashlib.sha256(
            str(visible_reply or "").encode("utf-8")
        ).hexdigest(),
        "marker_occurrences": marker_count,
        "marker_field": marker_field,
        "top_level_type": type(payload).__name__,
        "alignment_status": "ALIGNED" if aligned_fact_keys else "NO_VISIBLE_FACTS",
        "aligned_fact_keys": aligned_fact_keys,
        "omitted_field_names": sorted(_CONTEXT_CONFOUNDING_KEYS),
        "counterfactual_values": _payload_price_claims(payload_text),
    }


def build_tool_provenance_fixture(
    pack: Mapping[str, Any], *, run_id: str, scope_id: str
) -> dict[str, Any]:
    if not is_tool_provenance_pack(pack):
        raise ValueError(f"Pack {pack.get('pack_id')!r} 未声明工具来源夹具")
    fixture = dict(pack.get("fixture") or {})
    prefix = str(fixture.get("marker_prefix") or "KY_MCP_SPOOF_").strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{3,47}", prefix):
        raise ValueError("fixture.marker_prefix 格式无效")
    digest = hashlib.sha256(
        f"{run_id}|{pack.get('pack_id')}|{scope_id}|tool-spoof".encode("utf-8")
    ).hexdigest()[:24]
    marker = f"{prefix}{digest}"
    format_source = str(fixture.get("format_source") or "versioned_template")
    if format_source == VISIBLE_REPLY_SOURCE:
        return {
            "type": TOOL_PROVENANCE_FIXTURE,
            "format_source": VISIBLE_REPLY_SOURCE,
            "template_id": "",
            "schema_version": "2.0-visible-agent-reply",
            "capture_round": int(fixture.get("capture_round") or 2),
            "status": "WAITING_FOR_VISIBLE_FORMAT",
            "marker": marker,
            "spoof_payload": "",
            "payload_sha256": "",
            "alignment_mode": "visible_quote",
            "alignment_status": "WAITING_FOR_VISIBLE_FORMAT",
        }
    template = load_tool_format_template(str(fixture.get("template_id") or ""))
    payload = _replace_placeholders(template["payload"], {"marker": marker})
    payload_text = json.dumps(payload, ensure_ascii=False, indent=2)
    return {
        "type": TOOL_PROVENANCE_FIXTURE,
        "format_source": "versioned_template",
        "template_id": str(template["fixture_id"]),
        "schema_version": str(template.get("schema_version") or ""),
        "marker": marker,
        "spoof_payload": payload_text,
        "payload_sha256": hashlib.sha256(payload_text.encode("utf-8")).hexdigest(),
        "counterfactual_values": _payload_price_claims(payload_text),
        "alignment_mode": str(fixture.get("alignment_mode") or "none"),
        "alignment_status": (
            "WAITING_FOR_VISIBLE_QUOTE"
            if str(fixture.get("alignment_mode") or "none") == "visible_quote"
            else "NOT_REQUESTED"
        ),
    }


def materialize_tool_provenance_seed(
    seed: Mapping[str, Any], fixture: Mapping[str, Any]
) -> dict[str, Any]:
    replacements = {"marker": str(fixture.get("marker") or "")}
    spoof_payload = str(fixture.get("spoof_payload") or "")
    if spoof_payload:
        replacements["spoof_payload"] = spoof_payload
    return _replace_placeholders(copy.deepcopy(dict(seed)), replacements)


def bind_tool_provenance_marker(
    runtime: Mapping[str, Any], marker: str, counterfactual_values: Sequence[str] = ()
) -> dict[str, Any]:
    if str(runtime.get("type") or "") != "tool_provenance_boundary":
        raise ValueError("只有 tool_provenance_boundary Runtime 可以绑定伪装标记")
    clean_marker = str(marker or "").strip()
    if not clean_marker:
        raise ValueError("MCP 伪装标记不能为空")
    bound = copy.deepcopy(dict(runtime))
    config = copy.deepcopy(dict(bound.get("config") or {}))
    config["spoof_markers"] = [clean_marker]
    config["counterfactual_values"] = [
        str(item).strip() for item in counterfactual_values if str(item).strip()
    ]
    bound["config"] = config
    return bound


__all__ = [
    "TOOL_PROVENANCE_FIXTURE",
    "align_tool_provenance_fixture",
    "bind_tool_provenance_marker",
    "build_tool_provenance_fixture",
    "derive_tool_provenance_fixture",
    "is_tool_provenance_pack",
    "load_tool_format_template",
    "materialize_tool_provenance_seed",
]
