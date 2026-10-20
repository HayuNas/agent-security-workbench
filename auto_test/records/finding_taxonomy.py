"""Stable classification contract for remediation-oriented security Findings."""

from __future__ import annotations

from typing import Final


CLASSIFICATION_VERSION: Final = "finding-taxonomy-v1"

# How the attack induced the observed issue. A Finding may carry several tags.
TRIGGER_TYPES: Final = frozenset(
    {
        "DIRECT_REQUEST",
        "AUTHORITY_PRETEXT",
        "ROLE_PLAY",
        "TRANSFORMATION_REQUEST",
        "ENCODING_OBFUSCATION",
        "MULTI_TURN_ESCALATION",
        "TOOL_PROVENANCE_SPOOFING",
        "CROSS_CONTEXT_REFERENCE",
        "COMMERCIAL_PRESSURE",
        "OTHER",
    }
)

# The primary implementation boundary that owns the repair. This is the
# user-facing Finding type used to route a remediation task.
REMEDIATION_TYPES: Final = frozenset(
    {
        "AGENT_INSTRUCTION",
        "SKILL_BOUNDARY",
        "INPUT_GUARD",
        "CONTEXT_ASSEMBLY",
        "OUTPUT_GUARD",
        "TOOL_AUTHORIZATION",
        "SESSION_ISOLATION",
        "PLATFORM_CODE",
        "MIXED",
        "NEEDS_TRIAGE",
    }
)

REMEDIATION_SCOPES: Final = frozenset(
    {"AGENT_LOCAL", "PLATFORM_SHARED", "MIXED"}
)

# A deliberately small grouping vocabulary. It allows Findings from different
# test batches to be queried as the same issue family without reusing their IDs.
ROOT_CAUSE_FAMILIES: Final = frozenset(
    {
        "POLICY_GAP",
        "POLICY_PRECEDENCE_GAP",
        "INPUT_CLASSIFICATION_GAP",
        "CONTEXT_BOUNDARY_GAP",
        "OUTPUT_BOUNDARY_GAP",
        "TOOL_TRUST_GAP",
        "AUTHORIZATION_GAP",
        "SESSION_ISOLATION_GAP",
        "IMPLEMENTATION_PATH_GAP",
        "UNKNOWN",
    }
)

SEVERITY_VALUES: Final = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
    "低": 0,
    "中": 1,
    "高": 2,
    "严重": 3,
}


__all__ = [
    "CLASSIFICATION_VERSION",
    "REMEDIATION_SCOPES",
    "REMEDIATION_TYPES",
    "ROOT_CAUSE_FAMILIES",
    "SEVERITY_VALUES",
    "TRIGGER_TYPES",
]
