"""Per-Agent input profiles and output protection policies."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .assets import ProtectedAsset
from .engine import RiskEngine


@dataclass(frozen=True)
class AgentPolicy:
    agent_id: str
    prompt_fingerprints: tuple[str, ...] = ()
    protected_assets: tuple[ProtectedAsset, ...] = ()
    input_profile: str = "sales"

    def __post_init__(self):
        if not isinstance(self.input_profile, str) or self.input_profile not in {"sales", "internal"}:
            raise ValueError("input_profile must be sales or internal")


class PolicyRegistry:
    """Immutable registry loaded once at service startup."""

    def __init__(
        self,
        policies: dict[str, AgentPolicy] | None = None,
        version: str = "unversioned",
    ) -> None:
        self._policies = dict(policies or {})
        self.version = version

    @classmethod
    def from_file(cls, path: str) -> "PolicyRegistry":
        if not path:
            return cls()

        policy_path = Path(path).expanduser().resolve()
        payload = json.loads(policy_path.read_text(encoding="utf-8"))
        return cls.from_payload(payload)

    @classmethod
    def from_payload(cls, payload: dict) -> "PolicyRegistry":
        """文件与管理接口共用策略校验。"""
        if not isinstance(payload, dict):
            raise ValueError("risk guard policy file must contain a JSON object")

        raw_agents = payload.get("agents", {})
        if not isinstance(raw_agents, dict):
            raise ValueError("risk guard policy field 'agents' must be an object")

        policies: dict[str, AgentPolicy] = {}
        for agent_id, raw_policy in raw_agents.items():
            if not isinstance(agent_id, str) or not isinstance(raw_policy, dict):
                raise ValueError("each risk guard policy must be an object")

            fingerprints = raw_policy.get("prompt_fingerprints", [])
            if not isinstance(fingerprints, list) or not all(
                isinstance(item, str) for item in fingerprints
            ):
                raise ValueError(
                    f"policy {agent_id!r} prompt_fingerprints must be strings"
                )

            system_prompt = raw_policy.get("system_prompt", "")
            if system_prompt and not isinstance(system_prompt, str):
                raise ValueError(f"policy {agent_id!r} system_prompt must be text")

            raw_assets = raw_policy.get("protected_assets", [])
            if not isinstance(raw_assets, list):
                raise ValueError(
                    f"policy {agent_id!r} protected_assets must be a list"
                )
            protected_assets: list[ProtectedAsset] = []
            for index, raw_asset in enumerate(raw_assets, start=1):
                if not isinstance(raw_asset, dict):
                    raise ValueError(
                        f"policy {agent_id!r} protected asset #{index} must be an object"
                    )
                modes = raw_asset.get("match_modes", ["winnowing", "fuzzy"])
                if not isinstance(modes, list) or not all(
                    isinstance(mode, str) for mode in modes
                ):
                    raise ValueError(
                        f"policy {agent_id!r} protected asset #{index} "
                        "match_modes must be strings"
                    )
                content = raw_asset.get("content", "")
                if not isinstance(content, str):
                    raise ValueError(
                        f"policy {agent_id!r} protected asset #{index} "
                        "content must be text"
                    )
                protected_assets.append(
                    ProtectedAsset(
                        asset_id=str(
                            raw_asset.get("asset_id") or f"asset-{index}"
                        ),
                        asset_type=str(raw_asset.get("asset_type") or "custom"),
                        content=content,
                        match_modes=tuple(modes),
                        fuzzy_threshold=float(
                            raw_asset.get("fuzzy_threshold", 92.0)
                        ),
                        min_match_chars=int(
                            raw_asset.get("min_match_chars", 24)
                        ),
                    )
                )

            if system_prompt:
                protected_assets.append(
                    ProtectedAsset(
                        asset_id="system-prompt",
                        asset_type="system_prompt",
                        content=system_prompt,
                    )
                )

            asset_ids = [asset.asset_id for asset in protected_assets]
            if len(asset_ids) != len(set(asset_ids)):
                raise ValueError(
                    f"policy {agent_id!r} protected asset_id values must be unique"
                )

            extracted = RiskEngine.extract_prompt_fingerprints(system_prompt)
            merged = tuple(dict.fromkeys([*fingerprints, *extracted]))
            policies[agent_id] = AgentPolicy(
                agent_id=agent_id,
                prompt_fingerprints=merged,
                protected_assets=tuple(protected_assets),
                input_profile=raw_policy.get("input_profile", "sales"),
            )

        return cls(
            policies=policies,
            version=str(payload.get("version", "unversioned")),
        )

    def get(self, agent_id: str) -> AgentPolicy:
        return self._policies.get(agent_id, AgentPolicy(agent_id=agent_id))

    def overlay(self, payload: dict, version: str):
        managed = self.from_payload({'agents': payload})
        return PolicyRegistry({**self._policies, **managed._policies}, version)

    @property
    def agent_count(self) -> int:
        return len(self._policies)
