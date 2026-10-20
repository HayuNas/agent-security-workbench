"""一 Skill、多 Pack 的安全测试生成入口。"""

from .epe import build_epe_generation_messages, generate_epe_query_pack
from .cr import GenerationDataError, generate_seed_pack
from .profiles import (
    AUTOMATION_SKILL_DIR,
    load_automation_profiles,
    load_epe_generation_bundle,
    load_generation_bundle,
)
from .workflow import AUTOMATION_ENGINES, AUTOMATION_MODES, run_automation
from ..tactics import (
    TENCENT_ADAPTERS_PATH,
    TENCENT_STRATEGY_MAP_PATH,
    TacticDataError,
    load_tactic_catalog,
    tactic_cards_for,
)

__all__ = [
    "AUTOMATION_ENGINES",
    "AUTOMATION_MODES",
    "AUTOMATION_SKILL_DIR",
    "GenerationDataError",
    "TENCENT_ADAPTERS_PATH",
    "TENCENT_STRATEGY_MAP_PATH",
    "TacticDataError",
    "build_epe_generation_messages",
    "generate_epe_query_pack",
    "generate_seed_pack",
    "load_automation_profiles",
    "load_epe_generation_bundle",
    "load_generation_bundle",
    "load_tactic_catalog",
    "run_automation",
    "tactic_cards_for",
]
