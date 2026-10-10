"""Resolve the read-only installation location without embedding a local path."""

from __future__ import annotations

import json
import os
from pathlib import Path


def load_game_root(project_root: Path | None = None) -> Path:
    """Read NFS_GAME_ROOT, or the ignored project config's game_root key."""
    project_root = (project_root or Path(__file__).resolve().parents[1]).resolve()
    value = os.environ.get("NFS_GAME_ROOT")
    if not value:
        config = project_root / "config.local.json"
        try:
            parsed = json.loads(config.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            raise ValueError(
                "Set NFS_GAME_ROOT or create ignored config.local.json "
                f"with a game_root path ({exc})."
            ) from exc
        value = parsed.get("game_root") if isinstance(parsed, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("game_root must be a nonempty directory path.")
    root = Path(value).expanduser()
    if not root.is_absolute():
        root = project_root / root
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"Cannot resolve game installation directory: {exc}") from exc
    if not root.is_dir():
        raise ValueError(f"Game installation is not a directory: {root}")
    return root


def require_external_output(output: Path, game_root: Path) -> Path:
    """Reject any generated output that would write into the installation."""
    output = output.resolve()
    if output == game_root.resolve() or game_root.resolve() in output.parents:
        raise ValueError("Refusing to write audit output inside the read-only installation.")
    return output
