#!/usr/bin/env python3
"""Read-only inventory of a local NFS Most Wanted 2005 installation.

Does not copy, modify, upload, or distribute game files.
"""
import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PINNED_SHA256 = "80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c"
REQUIRED_DIRS = ("CARS", "FRONTEND", "GLOBAL", "SOUND", "TRACKS")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(2 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(game_dir: Path, hash_all: bool = False) -> dict:
    if not game_dir.is_dir():
        raise FileNotFoundError(f"Game folder not found: {game_dir}")
    executable = game_dir / "speed.exe"
    if not executable.is_file():
        raise FileNotFoundError(f"Missing speed.exe in: {game_dir}")

    top_names = {x.name.upper(): x for x in game_dir.iterdir() if x.is_dir()}
    missing = [name for name in REQUIRED_DIRS if name not in top_names]
    exe_sha = sha256(executable)
    by_top = defaultdict(lambda: {"count": 0, "bytes": 0})
    by_ext = Counter()
    files = []
    for path in sorted(game_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(game_dir).as_posix()
        size = path.stat().st_size
        root = relative.split("/")[0]
        by_top[root]["count"] += 1
        by_top[root]["bytes"] += size
        ext = path.suffix.lower() or "(no extension)"
        by_ext[ext] += 1
        entry = {"relative_path": relative, "size_bytes": size}
        if hash_all:
            entry["sha256"] = sha256(path)
        files.append(entry)

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "game_directory": str(game_dir.resolve()),
        "note": "Read-only metadata inventory, not game files or reverse-engineered source code.",
        "executable": {
            "name": "speed.exe",
            "size_bytes": executable.stat().st_size,
            "sha256": exe_sha,
            "matches_nfsmw_recomp_pinned_version": exe_sha == PINNED_SHA256,
            "reference_sha256": PINNED_SHA256,
        },
        "required_game_directories_present": not missing,
        "missing_required_directories": missing,
        "file_count": len(files),
        "total_size_bytes": sum(item["size_bytes"] for item in files),
        "top_level_summary": dict(sorted(by_top.items())),
        "extension_counts": dict(sorted(by_ext.items(), key=lambda x: (-x[1], x[0]))),
        "files": files,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game-dir", type=Path, required=True, help="Original installed game folder")
    parser.add_argument("--out", type=Path, default=Path("nfsmw_inventory.json"), help="JSON report output")
    parser.add_argument("--hash-all", action="store_true", help="SHA256 all data files (slower)")
    args = parser.parse_args()
    report = inventory(args.game_dir, args.hash_all)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Scanned {report['file_count']} files; {report['total_size_bytes']:,} bytes")
    print(f"Executable matches recomp-kit reference: {report['executable']['matches_nfsmw_recomp_pinned_version']}")
    print(f"Missing required directories: {report['missing_required_directories'] or 'none'}")
    print(f"Inventory saved: {args.out.resolve()}")
    print("No game files were modified or copied.")


if __name__ == "__main__":
    main()
