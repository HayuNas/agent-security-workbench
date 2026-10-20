"""External model, target and trace clients."""

from .ai_web import AIWebClient, AIWebError
from .base import TargetClient
from .factory import TargetProfile, build_target_client, resolve_target_profile
from .model import ModelClientError, OpenAICompatibleClient, load_model_settings
from .smoke import require_ai_web_contract, run_target_smoke
from .target import KyAgentClient, SessionInfo, build_test_identity
from .trace import SSETraceBuilder, trusted_tool_exchanges

__all__ = [
    "AIWebClient",
    "AIWebError",
    "KyAgentClient",
    "ModelClientError",
    "OpenAICompatibleClient",
    "SSETraceBuilder",
    "SessionInfo",
    "TargetClient",
    "TargetProfile",
    "build_target_client",
    "build_test_identity",
    "load_model_settings",
    "resolve_target_profile",
    "require_ai_web_contract",
    "run_target_smoke",
    "trusted_tool_exchanges",
]
