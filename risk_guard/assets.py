"""Protected-asset matching for model output.

The matcher keeps policy decisions outside the detection algorithm: only content
explicitly registered as a protected asset is indexed.  Winnowing detects
partial near-verbatim copies, while RapidFuzz covers small textual mutations.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable

from rapidfuzz import fuzz


DEFAULT_K_GRAM = 9
DEFAULT_WINDOW = 5
DEFAULT_MIN_MATCH_CHARS = 24
DEFAULT_FUZZY_THRESHOLD = 92.0
_MAX_FUZZY_SEGMENT_CHARS = 96
_FUZZY_SEGMENT_OVERLAP = 24
_SEGMENT_SPLIT_RE = re.compile(r"[\n\r。！？!?；;]+")


def normalize_asset_text(text: str) -> str:
    """Normalize harmless presentation changes without changing word meaning."""
    normalized = unicodedata.normalize("NFKC", text or "").casefold()
    return "".join(char for char in normalized if char.isalnum())


def _stable_hash(value: str) -> int:
    digest = hashlib.blake2b(value.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


def winnowing_fingerprints(
    text: str,
    *,
    k_gram: int = DEFAULT_K_GRAM,
    window: int = DEFAULT_WINDOW,
) -> tuple[tuple[int, int], ...]:
    """Return ``(hash, position)`` pairs selected by rightmost-min winnowing."""
    if k_gram < 1 or window < 1:
        raise ValueError("k_gram and window must be positive")
    if len(text) < k_gram:
        return ()

    hashes = [
        _stable_hash(text[index : index + k_gram])
        for index in range(len(text) - k_gram + 1)
    ]
    effective_window = min(window, len(hashes))
    selected: list[tuple[int, int]] = []
    last_position = -1
    for start in range(len(hashes) - effective_window + 1):
        values = hashes[start : start + effective_window]
        minimum = min(values)
        relative_position = max(
            index for index, value in enumerate(values) if value == minimum
        )
        position = start + relative_position
        if position != last_position:
            selected.append((minimum, position))
            last_position = position
    return tuple(selected)


def _chunk_segment(segment: str) -> Iterable[str]:
    if len(segment) <= _MAX_FUZZY_SEGMENT_CHARS:
        yield segment
        return
    step = _MAX_FUZZY_SEGMENT_CHARS - _FUZZY_SEGMENT_OVERLAP
    for start in range(0, len(segment), step):
        chunk = segment[start : start + _MAX_FUZZY_SEGMENT_CHARS]
        if chunk:
            yield chunk
        if start + _MAX_FUZZY_SEGMENT_CHARS >= len(segment):
            break


def _fuzzy_segments(content: str, min_match_chars: int) -> tuple[str, ...]:
    normalized = normalize_asset_text(content)
    if len(normalized) == min_match_chars:
        return (normalized,)
    segments: list[str] = []
    for raw_segment in _SEGMENT_SPLIT_RE.split(content):
        normalized = normalize_asset_text(raw_segment)
        if len(normalized) < min_match_chars:
            continue
        segments.extend(_chunk_segment(normalized))
    return tuple(dict.fromkeys(segments))


@dataclass(frozen=True)
class ProtectedAsset:
    asset_id: str
    content: str = field(repr=False)
    asset_type: str = "custom"
    match_modes: tuple[str, ...] = ("winnowing", "fuzzy")
    fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD
    min_match_chars: int = DEFAULT_MIN_MATCH_CHARS
    normalized: str = field(init=False, repr=False)
    fingerprints: tuple[tuple[int, int], ...] = field(init=False, repr=False)
    fuzzy_segments: tuple[str, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        asset_id = self.asset_id.strip()
        if not asset_id:
            raise ValueError("protected asset_id must not be empty")
        if not self.content.strip():
            raise ValueError(f"protected asset {asset_id!r} content must not be empty")
        modes = tuple(dict.fromkeys(mode.strip().lower() for mode in self.match_modes))
        invalid_modes = set(modes) - {"winnowing", "fuzzy"}
        if invalid_modes:
            raise ValueError(
                f"protected asset {asset_id!r} has unsupported match modes: "
                + ", ".join(sorted(invalid_modes))
            )
        if not 0 < float(self.fuzzy_threshold) <= 100:
            raise ValueError("fuzzy_threshold must be in (0, 100]")
        if int(self.min_match_chars) < DEFAULT_K_GRAM:
            raise ValueError(
                f"min_match_chars must be at least {DEFAULT_K_GRAM}"
            )

        normalized = normalize_asset_text(self.content)
        if len(normalized) < int(self.min_match_chars):
            raise ValueError(
                f"protected asset {asset_id!r} is shorter than min_match_chars"
            )
        object.__setattr__(self, "asset_id", asset_id)
        object.__setattr__(self, "match_modes", modes)
        object.__setattr__(self, "normalized", normalized)
        object.__setattr__(
            self,
            "fingerprints",
            winnowing_fingerprints(normalized),
        )
        object.__setattr__(
            self,
            "fuzzy_segments",
            _fuzzy_segments(self.content, int(self.min_match_chars)),
        )


@dataclass(frozen=True)
class ProtectedAssetMatch:
    asset_id: str
    asset_type: str
    detector: str
    score: float
    matched_chars: int


def configured_asset_detectors(
    assets: Iterable[ProtectedAsset],
) -> tuple[str, ...]:
    modes = {mode for asset in assets for mode in asset.match_modes}
    detectors: list[str] = []
    if "winnowing" in modes:
        detectors.append("protected_asset_winnowing")
    if "fuzzy" in modes:
        detectors.append("protected_asset_fuzzy")
    return tuple(detectors)


def _winnowing_match(
    output: str,
    output_fingerprints: tuple[tuple[int, int], ...],
    asset: ProtectedAsset,
) -> ProtectedAssetMatch | None:
    if "winnowing" not in asset.match_modes:
        return None

    # Short copied passages can have only one selected fingerprint.  Verify the
    # normalized substring directly to avoid relying on a hash collision.
    if (
        len(output) >= asset.min_match_chars
        and len(output) <= len(asset.normalized)
        and output in asset.normalized
    ):
        return ProtectedAssetMatch(
            asset_id=asset.asset_id,
            asset_type=asset.asset_type,
            detector="protected_asset_winnowing",
            score=1.0,
            matched_chars=len(output),
        )

    asset_positions: dict[int, list[int]] = {}
    for hash_value, position in asset.fingerprints:
        asset_positions.setdefault(hash_value, []).append(position)

    diagonals: dict[int, list[int]] = {}
    for hash_value, output_position in output_fingerprints:
        for asset_position in asset_positions.get(hash_value, ()):
            diagonals.setdefault(asset_position - output_position, []).append(
                output_position
            )

    best_span = 0
    for positions in diagonals.values():
        unique_positions = sorted(set(positions))
        if len(unique_positions) < 2:
            continue
        span = unique_positions[-1] - unique_positions[0] + DEFAULT_K_GRAM
        if span > best_span:
            best_span = span

    if best_span < asset.min_match_chars:
        return None
    return ProtectedAssetMatch(
        asset_id=asset.asset_id,
        asset_type=asset.asset_type,
        detector="protected_asset_winnowing",
        score=min(1.0, best_span / max(1, len(output))),
        matched_chars=best_span,
    )


def _fuzzy_match(output: str, asset: ProtectedAsset) -> ProtectedAssetMatch | None:
    if "fuzzy" not in asset.match_modes or len(output) < asset.min_match_chars:
        return None

    best_score = 0.0
    best_chars = 0
    for segment in asset.fuzzy_segments:
        comparable_chars = min(len(segment), len(output))
        if comparable_chars < asset.min_match_chars:
            continue
        score = float(
            fuzz.partial_ratio(
                segment,
                output,
                score_cutoff=float(asset.fuzzy_threshold),
            )
        )
        if score > best_score:
            best_score = score
            best_chars = comparable_chars
    if best_score < asset.fuzzy_threshold:
        return None
    return ProtectedAssetMatch(
        asset_id=asset.asset_id,
        asset_type=asset.asset_type,
        detector="protected_asset_fuzzy",
        score=best_score / 100.0,
        matched_chars=best_chars,
    )


def match_protected_assets(
    text: str,
    assets: Iterable[ProtectedAsset],
) -> ProtectedAssetMatch | None:
    """Return the strongest deterministic match without exposing asset content."""
    normalized_output = normalize_asset_text(text)
    assets_tuple = tuple(assets)
    if not normalized_output or not assets_tuple:
        return None

    output_fingerprints = winnowing_fingerprints(normalized_output)
    for asset in assets_tuple:
        match = _winnowing_match(normalized_output, output_fingerprints, asset)
        if match is not None:
            return match
    for asset in assets_tuple:
        match = _fuzzy_match(normalized_output, asset)
        if match is not None:
            return match
    return None


__all__ = [
    "ProtectedAsset",
    "ProtectedAssetMatch",
    "configured_asset_detectors",
    "match_protected_assets",
    "normalize_asset_text",
    "winnowing_fingerprints",
]
