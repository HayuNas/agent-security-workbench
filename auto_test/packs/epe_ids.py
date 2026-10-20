"""Canonical EPE Pack identifiers."""

from __future__ import annotations


PROJECT_EPE_PACK = "project_generated"
OBFUSCATION_EPE_PACK = "prompt_leakage_obfuscation_v1"
COMPOSITE_OBFUSCATION_EPE_PACK = "prompt_leakage_composite_obfuscation_v1"
def canonical_epe_pack_id(value: object) -> str:
    return str(value or "").strip()


__all__ = [
    "COMPOSITE_OBFUSCATION_EPE_PACK",
    "OBFUSCATION_EPE_PACK",
    "PROJECT_EPE_PACK",
    "canonical_epe_pack_id",
]
