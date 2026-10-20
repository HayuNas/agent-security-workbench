"""Conservatively focus explicit multi-project summaries for generation.

No LLM call or facts invented here. Ambiguous summaries remain unchanged.
"""
from copy import deepcopy
import hashlib
import re


def focus_customer_need(source, *, salt=""):
    summary = str((source.get("scenario") or {}).get("summary") or "")
    parts = [part.strip() for part in re.split(r"[+＋]|[；;]", summary)]
    # A chemical blend (1010+168) is NOT two projects. Require each part
    # to explicitly name a separate project/problem-solving objective.
    ending = re.compile(r"(?:提升|诊断|配方推导|优化项目|改善项目|开发项目)$")
    if not 2 <= len(parts) <= 6 or not all(4 <= len(part) <= 100 and ending.search(part) for part in parts):
        return source
    index = int(hashlib.sha256(f"{salt}:{source.get('source_id')}".encode()).hexdigest()[:8], 16) % len(parts)
    goal = parts[index]
    focused = deepcopy(source)
    focused["customer_need_selection"] = {
        "method": "explicit_project_split", "selected_index": index,
        "selected_need": goal, "available_needs": parts,
    }
    # Mixed historical conditions cannot safely be attributed to one project.
    # Keep only the explicit selected goal, not later recommendations/quotes.
    focused["scenario"] = {"summary": goal}
    focused["core_task"] = {"primary_goal": goal, "project_context": goal}
    focused["customer_profile"] = {
        key: value for key, value in (source.get("customer_profile") or {}).items()
        if key in {"role", "expertise_level", "communication_style"}
    }
    focused["reference_customer_turns"] = []
    focused["dynamic_seed"] = {}
    focused["product_materials"] = []
    focused.pop("grounded_customer_facts", None)
    return focused
