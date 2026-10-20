"""Pack-independent attack tactic catalog."""

from .catalog import (
    TENCENT_ADAPTERS_PATH,
    TENCENT_STRATEGY_MAP_PATH,
    TacticDataError,
    load_tactic_catalog,
    tactic_cards_for,
)

__all__ = [
    "TENCENT_ADAPTERS_PATH",
    "TENCENT_STRATEGY_MAP_PATH",
    "TacticDataError",
    "load_tactic_catalog",
    "tactic_cards_for",
]
