"""Resolve reported filenames before the temporary scan directory is removed."""

from pathlib import Path, PureWindowsPath


def public_file_name(value: str, extracted_root: Path, scanned_root: Path) -> str | None:
    value = value.strip().replace("\\", "/")
    if not value or value.startswith("//") or any(ord(char) < 32 for char in value) or ".." in value.split("/"):
        return None
    path = Path(value)
    root = extracted_root.resolve()
    try:
        if path.is_absolute():
            # Windows TEMP may use an 8.3 alias while resolve() expands it.
            if not (path.is_relative_to(extracted_root.absolute()) or path.is_relative_to(root)):
                return None
            target = path.resolve()
            if target.is_relative_to(root) and target.is_file():
                return target.relative_to(root).as_posix()
            return None
        # Reject foreign absolute paths, drive-relative paths and URI schemes.
        if PureWindowsPath(value).drive or ":" in value:
            return None
        matches = set()
        for base in (root, scanned_root.resolve()):
            target = (base / path).resolve()
            if target.is_relative_to(root) and target.is_file():
                matches.add(target)
        # Use the actual ZIP layout for both absolute and relative model output.
        # Existing Skill directories are retained; flat ZIPs gain no invented name.
        return next(iter(matches)).relative_to(root).as_posix() if len(matches) == 1 else None
    except (OSError, ValueError, RuntimeError):
        return None
