"""
judge/batch_files.py
─────────────────────
Where a batch's files are. A manifest has to keep working after its folder is
moved, downloaded as a CI artifact, or read on another machine, so:

  • transcripts are recorded relative to the batch folder (`PI-001.json`);
  • the library is recorded repo-relative when it is in the repo, and its exact
    bytes are kept beside the manifest (`library.yaml`, with their sha256), so
    the cases a batch ran can always be read back, even where the path cannot.

Older manifests recorded absolute paths. They still resolve where they were
written, and anywhere else by file name inside the batch folder.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
LIBRARY_SNAPSHOT = "library.yaml"


def recorded_name(recorded: str) -> str:
    # A path written on Windows read on Linux, or the other way round: the last
    # component by either convention.
    return PureWindowsPath(recorded).name if "\\" in recorded else PurePosixPath(recorded).name


def transcript_path(batch_dir: Path, recorded: Optional[str]) -> Optional[Path]:
    """The transcript a manifest entry names, or None if it is nowhere to be found."""
    if not recorded:
        return None
    path = Path(recorded)
    if not path.is_absolute():
        path = batch_dir / path
    if path.is_file():
        return path
    moved = batch_dir / recorded_name(recorded)
    return moved if moved.is_file() else None


def recorded_library(library: Path) -> str:
    """How a manifest names `library`: repo-relative (POSIX) inside the repo, else absolute."""
    resolved = library.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def file_sha256(path: Path) -> str:
    """
    sha256 of a library, line endings normalised: a checkout's CRLF (Windows,
    core.autocrlf) means nothing to YAML, so a batch run in Linux CI and resumed
    on Windows must not read as "the library changed".
    """
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def library_path(manifest: Dict[str, Any], batch_dir: Path) -> Tuple[Path, str]:
    """
    (path, source) of the library a manifest names: the recorded path while it
    exists ("recorded": re-scoring after editing a case is a normal thing to
    do), else the batch's own snapshot ("snapshot"). Raises FileNotFoundError.
    """
    recorded = str(manifest.get("library") or "")
    if recorded:
        path = Path(recorded)
        path = path if path.is_absolute() else ROOT / path
        if path.is_file():
            return path, "recorded"
    snapshot = manifest.get("library_snapshot")
    if snapshot:
        path = (batch_dir / str(snapshot)).resolve()
        # The manifest is data: its snapshot may not point outside its batch.
        if path.parent == batch_dir.resolve() and path.is_file():
            return path, "snapshot"
    raise FileNotFoundError(f"Library {recorded or snapshot!r} named by the manifest no longer exists"
                            + ("" if snapshot else ", and the batch keeps no snapshot of it") + ".")


def library_drift(manifest: Dict[str, Any], library: Path) -> Optional[str]:
    """Why `library` is not the library the batch ran, or None (also for batches that recorded no sha256)."""
    expected = manifest.get("library_sha256")
    if not expected or file_sha256(library) == expected:
        return None
    return (f"{library} has changed since the batch ran (sha256 {str(expected)[:12]}… then, "
            f"{file_sha256(library)[:12]}… now)")


def git_source(root: Path = ROOT) -> Optional[Dict[str, Any]]:
    """The commit the harness ran from, and whether tracked files differed from it. None outside git."""
    def git(*args: str) -> Optional[str]:
        try:
            proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                                  timeout=10, encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return None
        return proc.stdout if proc.returncode == 0 else None

    commit = (git("rev-parse", "HEAD") or "").strip()
    if not commit:
        return None
    status = git("status", "--porcelain", "--untracked-files=no")
    return {"git_commit": commit, "dirty": None if status is None else bool(status.strip())}
