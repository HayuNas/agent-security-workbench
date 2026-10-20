"""价格 Oracle 使用的 Tool Result 与价格抽取工具。"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, Sequence


FAILURE_MARKERS = (
    "error",
    "failed",
    "failure",
    "timeout",
    "exception",
    "cancelled",
    "canceled",
    "失败",
    "错误",
    "报错",
    "异常",
    "超时",
    "取消",
    "[服务端异常]",
)
PRICE_RE = re.compile(
    r"(?:¥|￥)\s*(\d+(?:\.\d+)?)"
    r"|(\d+(?:\.\d+)?)\s*(?:元|块钱|块|rmb)",
    re.IGNORECASE,
)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _json_text(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    return "" if value is None else str(value)


def short_tool_name(name: str) -> str:
    value = str(name or "").strip()
    return value.rsplit("__", 1)[-1] if "__" in value else value


def tool_matches(actual: str, expected: str) -> bool:
    actual_value = str(actual or "").strip().casefold()
    expected_value = str(expected or "").strip().casefold()
    if not actual_value or not expected_value:
        return False
    return actual_value == expected_value or short_tool_name(
        actual_value
    ) == short_tool_name(expected_value)


def tool_calls(trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in _as_list(trace.get("tool_calls"))
        if isinstance(item, dict)
    ]


def tool_results(trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in _as_list(trace.get("tool_results"))
        if isinstance(item, dict)
    ]


def result_for_call(
    call: Mapping[str, Any], results: Sequence[dict[str, Any]]
) -> dict[str, Any] | None:
    call_id = str(call.get("tool_call_id") or call.get("id") or "")
    if call_id:
        for result in results:
            result_id = str(result.get("tool_call_id") or result.get("id") or "")
            if result_id and result_id == call_id:
                return result
    name = str(call.get("name") or "")
    return next(
        (
            result
            for result in results
            if tool_matches(str(result.get("name") or ""), name)
        ),
        None,
    )


def _result_text(result: Mapping[str, Any] | None) -> str:
    if not result:
        return ""
    for key in ("result", "output", "content", "text", "message"):
        if key in result and result.get(key) is not None:
            return _json_text(result.get(key))
    return ""


def result_business_usable(result: Mapping[str, Any] | None) -> bool:
    if not result or result.get("isError") is True or result.get("is_error") is True:
        return False
    state = str(result.get("state") or result.get("status") or "").strip().casefold()
    raw = _result_text(result)
    if any(marker in state for marker in FAILURE_MARKERS):
        return False
    if any(marker in raw.strip().casefold()[:800] for marker in FAILURE_MARKERS):
        return False
    if not (state or raw.strip()):
        return False
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return True

    def quantity_validity(value: Any) -> list[Any]:
        found: list[Any] = []
        if isinstance(value, Mapping):
            for key, item in value.items():
                if str(key).casefold() == "is_ok_quantity":
                    found.append(item)
                else:
                    found.extend(quantity_validity(item))
        elif isinstance(value, list):
            for item in value:
                found.extend(quantity_validity(item))
        return found

    return not any(
        str(item).strip().casefold() in {"0", "false", "no"}
        for item in quantity_validity(payload)
    )


def _price_basis(value: float, unit: str) -> tuple[str, float]:
    unit_key = unit.casefold()
    if unit_key in {"公斤", "千克", "kg"}:
        return "mass_kg", value
    if unit_key in {"吨", "t"}:
        return "mass_kg", value / 1000.0
    if unit_key in {"克", "g"}:
        return "mass_kg", value * 1000.0
    return unit_key or "unspecified", value


def extract_price_points(
    text: Any, units: Sequence[str] | None = None
) -> list[dict[str, Any]]:
    raw = str(text or "")
    allowed_units = sorted(
        {str(unit) for unit in units or [] if str(unit)}, key=len, reverse=True
    )
    points: list[dict[str, Any]] = []
    for match in PRICE_RE.finditer(raw):
        try:
            parsed = float(match.group(1) or match.group(2))
        except (TypeError, ValueError):
            continue
        unit = ""
        if allowed_units:
            tail = raw[match.end() : match.end() + 12]
            head = raw[max(0, match.start() - 12) : match.start()]
            unit = next(
                (
                    candidate
                    for candidate in allowed_units
                    if candidate.casefold() in tail.casefold()
                ),
                "",
            )
            if not unit:
                unit = next(
                    (
                        candidate
                        for candidate in allowed_units
                        if f"每{candidate}".casefold() in head.casefold()
                        or f"/{candidate}".casefold() in head.casefold()
                        or f"一{candidate}".casefold() in head.casefold()
                    ),
                    "",
                )
            if not unit:
                continue
        basis, normalised = _price_basis(parsed, unit)
        points.append(
            {
                "value": parsed,
                "unit": unit,
                "basis": basis,
                "normalized_value": normalised,
                "matched_text": match.group(0),
            }
        )
    return points


def preferred_price_source(result: Mapping[str, Any] | None) -> str:
    raw = _result_text(result)
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw
    candidates: list[str] = []
    preferred_keys = {
        "price_text",
        "quote_text",
        "quotation_text",
        "shipping_price_text",
        "effective_price_text",
    }

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if str(key).casefold() in preferred_keys and isinstance(item, str):
                    candidates.append(item)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(parsed)
    usable = [item for item in candidates if PRICE_RE.search(item)]
    return "\n".join(usable) if usable else raw


__all__ = [
    "extract_price_points",
    "preferred_price_source",
    "result_business_usable",
    "result_for_call",
    "short_tool_name",
    "tool_calls",
    "tool_matches",
    "tool_results",
]
