"""Bounded ZIP extraction for uploaded, untrusted Skill projects."""

from __future__ import annotations

import stat
import zipfile
import zlib
from pathlib import Path
from typing import BinaryIO

from .skill_settings import SkillScanSettings


class InvalidArchive(ValueError):
    pass


def scan_root(root: Path) -> Path:
    """Unwrap directory-only packaging without dropping any sibling files."""
    current = root
    while not (current / "SKILL.md").is_file():
        children = list(current.iterdir())
        if len(children) != 1 or not children[0].is_dir():
            break
        current = children[0]
    return current


def member_parts(name: str) -> tuple[str, ...]:
    # Reject ambiguous Windows/POSIX paths before joining them to a local root.
    path = name.replace("\\", "/").removesuffix("/")
    parts = tuple(path.split("/"))
    if not path or len(path) > 220 or len(parts) > 24:
        raise InvalidArchive("ZIP path is empty, too long or too deep")
    for part in parts:
        if part in {"", ".", ".."} or part.endswith((".", " ")):
            raise InvalidArchive("ZIP contains an unsafe path")
        if any(ord(c) < 32 or ord(c) == 127 or c in ':<>"|?*' for c in part):
            raise InvalidArchive("ZIP contains an unsafe filename")
        stem = part.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL"} or (
            len(stem) == 4 and stem[:3] in {"COM", "LPT"}
            and stem[3] in "123456789¹²³"
        ):
            raise InvalidArchive("ZIP contains a reserved filename")
    return parts


def extract_archive(source: BinaryIO, root: Path, settings: SkillScanSettings) -> int:
    """Preflight all entries, then write regular files only into a fresh root."""
    try:
        source.seek(0)
        with zipfile.ZipFile(source) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > settings.max_entries:
                raise InvalidArchive("ZIP is empty or contains too many entries")
            paths: dict[tuple[str, ...], bool] = {}
            prepared = []
            declared_size = 0
            file_count = 0
            for entry in entries:
                # Python also normalizes Windows separators in filename. A
                # changed name is not proof of NUL truncation; inspect the raw
                # name, then apply our cross-platform path validation.
                if "\x00" in entry.orig_filename:
                    raise InvalidArchive("ZIP filename contains NUL")
                parts = member_parts(entry.orig_filename)
                is_directory = entry.orig_filename.endswith(("/", "\\"))
                key = tuple(p.casefold() for p in parts)
                if key in paths:
                    raise InvalidArchive("ZIP contains duplicate or case-colliding paths")
                kind = stat.S_IFMT(entry.external_attr >> 16)
                expected = stat.S_IFDIR if is_directory else stat.S_IFREG
                if kind not in {0, expected}:
                    raise InvalidArchive("ZIP links and special files are not supported")
                if entry.flag_bits & 1:
                    raise InvalidArchive("Encrypted ZIP is not supported")
                if entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise InvalidArchive("Only stored/deflated ZIP entries are supported")
                paths[key] = is_directory
                prepared.append((entry, parts, is_directory))
                declared_size += entry.file_size
                file_count += not is_directory
                if declared_size > settings.max_extracted_bytes:
                    raise InvalidArchive("ZIP exceeds the extracted size limit")
            if not file_count:
                raise InvalidArchive("ZIP contains no files")
            for key in paths:
                for depth in range(1, len(key)):
                    if paths.get(key[:depth]) is False:
                        raise InvalidArchive("ZIP contains a file/directory collision")
            written = 0
            for entry, parts, is_directory in prepared:
                target = root.joinpath(*parts)
                if not target.resolve().is_relative_to(root.resolve()):
                    raise InvalidArchive("ZIP path escapes extraction directory")
                if is_directory:
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as src, target.open("xb") as dst:
                    while chunk := src.read(65536):
                        written += len(chunk)
                        if written > settings.max_extracted_bytes:
                            raise InvalidArchive("ZIP exceeds the extracted size limit")
                        dst.write(chunk)
            return file_count
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError,
            EOFError, UnicodeError, zlib.error) as exc:
        raise InvalidArchive("Invalid or unreadable ZIP archive") from exc
