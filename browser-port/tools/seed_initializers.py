"""Add at most 64 audited constructor-table slots after a matching startup fault.

Run ``python -m tools.seed_initializers --count 64`` from browser-port. Only
ignored JSON seeds/evidence are written; this command never compiles or runs code.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import tempfile

from translator.lift import PEImage
from tools.build_tests import EXE_SHA
from tools.game_config import load_game_root, require_external_output
from tools.toolchain import ROOT


TABLE_BEGIN = 0x8EA000
TABLE_END = 0x8EB164
SEEDS_RELATIVE = Path("generated/startup-seeds.json")
EVIDENCE_RELATIVE = Path("artifacts/initializer-seeds.json")


def validate_count(count):
    if type(count) is not int or not 1 <= count <= 64:
        raise ValueError("Constructor slot count must be an integer in 1..64")
    return count


def file_backed_bytes(image, address, size, executable=False):
    """Read audited PE section bytes without accepting zero-filled virtual tails."""
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0 or address + size > 2**32:
        raise ValueError("Invalid PE byte range")
    output = bytearray()
    while len(output) < size:
        rva = address + len(output) - image.base
        sections = [s for s in image.pe.sections
                    if s.VirtualAddress <= rva < s.VirtualAddress + min(s.Misc_VirtualSize, s.SizeOfRawData)]
        if len(sections) != 1:
            raise ValueError(f"Address {address + len(output):#x} has no unambiguous file-backed section")
        section = sections[0]
        if executable and not section.Characteristics & 0x20000000:
            raise ValueError(f"Constructor/seed target {address:#x} is not executable")
        available = section.VirtualAddress + min(section.Misc_VirtualSize, section.SizeOfRawData) - rva
        count = min(size - len(output), available)
        offset = section.PointerToRawData + rva - section.VirtualAddress
        if offset < 0 or offset + count > len(image.data):
            raise ValueError(f"PE file backing is truncated at {address + len(output):#x}")
        output.extend(image.data[offset:offset + count])
    return bytes(output)


def make_plan(image, trace, saved, count=32):
    validate_count(count)
    if image.sha256 != EXE_SHA:
        raise ValueError("Executable hash mismatch: repeat the audit before using the constructor table")
    if not isinstance(trace, dict) or not isinstance(saved, dict):
        raise ValueError("Startup evidence and saved seeds must be JSON objects")
    manifest = trace.get("manifest", {})
    if not isinstance(manifest, dict):
        raise ValueError("Startup evidence has no valid manifest")
    if manifest.get("schema") != 1 or manifest.get("kind") != "startup-probe":
        raise ValueError("Startup evidence must use the startup-probe manifest schema")
    provenance = manifest.get("provenance", {})
    if not isinstance(provenance, dict) or provenance.get("executable_sha256") != image.sha256:
        raise ValueError("Startup evidence executable hash mismatch")
    image_metadata = manifest.get("image", {})
    if not isinstance(image_metadata, dict) or provenance.get("entry") != image.entry or image_metadata.get("address") != image.base:
        raise ValueError("Startup evidence PE address/entry mismatch")
    if saved.get("input_sha256") != image.sha256:
        raise ValueError("Saved startup seeds belong to a different executable")
    existing = saved.get("seeds")
    if not isinstance(existing, list):
        raise ValueError("Saved startup seeds must be a list")
    for address in existing:
        file_backed_bytes(image, address, 1, executable=True)
    fault = trace.get("fault", {})
    if not isinstance(fault, dict) or type(fault.get("code")) is not int or fault["code"] != 3:
        raise ValueError("Constructor seeding requires fault code 3 (untranslated control-flow target)")
    eip = trace.get("eip")
    if type(eip) is not int or not 0 < eip < 2**32 or fault.get("address") != eip or trace.get("status") != 2:
        raise ValueError("Startup evidence must have a faulting EIP matching the untranslated target")
    table_bytes = file_backed_bytes(image, TABLE_BEGIN, TABLE_END - TABLE_BEGIN)
    targets = struct.unpack("<" + "I" * ((TABLE_END - TABLE_BEGIN) // 4), table_bytes)
    positions = [i for i, target in enumerate(targets) if target == eip]
    if not positions:
        raise ValueError(f"Fault EIP {eip:#x} is not an audited constructor-table target")
    if len(positions) != 1:
        slots = ", ".join(hex(TABLE_BEGIN + i * 4) for i in positions)
        raise ValueError(f"Fault EIP {eip:#x} is ambiguous at constructor slots {slots}; inspect the actual table pointer")
    start = positions[0]
    selected = []
    seeds = set(existing)
    for index in range(start, min(start + count, len(targets))):
        target = targets[index]
        if target:
            file_backed_bytes(image, target, 1, executable=True)
        selected.append({"index": index, "slot": TABLE_BEGIN + index * 4,
                         "target": target, "added": bool(target and target not in seeds)})
        if target:
            seeds.add(target)
    updated = {**saved, "seeds": sorted(seeds)}
    evidence = {"schema": 1, "input_sha256": image.sha256, "entry": image.entry,
                "table": {"begin": TABLE_BEGIN, "end": TABLE_END, "sha256": hashlib.sha256(table_bytes).hexdigest()},
                "observed": {"eip": eip, "fault_code": 3, "steps": trace.get("steps"),
                             "captured_at_utc": trace.get("captured_at_utc")},
                "requested_slots": count, "selected_slots": selected,
                "previous_seed_count": len(existing), "merged_seed_count": len(seeds),
                "added_seed_count": len(seeds - set(existing)),
                "scope": "Static constructor coverage seeds only; no compilation or execution"}
    return updated, evidence


def output_path(project, game_root, relative):
    project = Path(project).resolve()
    relative = Path(relative)
    if relative not in (SEEDS_RELATIVE, EVIDENCE_RELATIVE):
        raise ValueError("Output must be the designated ignored seeds/evidence JSON")
    expected = project / relative
    resolved = require_external_output(expected, game_root)
    if resolved != expected or project not in resolved.parents:
        raise ValueError("Output escapes its designated project location through a link")
    return resolved


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(value, indent=2) + "\n")
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def seed_initializers(count=32, project_root=ROOT):
    validate_count(count)
    project = Path(project_root).resolve()
    game_root = load_game_root(project)
    seeds_path = output_path(project, game_root, SEEDS_RELATIVE)
    evidence_path = output_path(project, game_root, EVIDENCE_RELATIVE)
    image = PEImage(game_root / "speed.exe")
    trace_path = project / "artifacts/startup-node.json"
    trace_bytes = trace_path.read_bytes()
    trace = json.loads(trace_bytes)
    seeds_bytes = seeds_path.read_bytes() if seeds_path.exists() else None
    saved = json.loads(seeds_bytes) if seeds_bytes is not None else {"input_sha256": image.sha256, "seeds": []}
    updated, evidence = make_plan(image, trace, saved, count)
    manifest_path = project / "build/startup.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest != trace["manifest"]:
        raise ValueError("Startup evidence does not match the current build manifest; rerun the startup probe")
    wasm_path = project / "build/startup.wasm"
    wasm_hash = hashlib.sha256(wasm_path.read_bytes()).hexdigest()
    artifact_hashes = manifest.get("artifact_sha256", {})
    if not isinstance(artifact_hashes, dict) or artifact_hashes.get("startup.wasm") != wasm_hash:
        raise ValueError("Startup evidence Wasm hash mismatch; rebuild/rerun the startup probe")
    image_path = project / "build/game-image.bin"
    mapped_hash = hashlib.sha256(image_path.read_bytes()).hexdigest()
    if manifest.get("image", {}).get("sha256") != mapped_hash:
        raise ValueError("Startup evidence mapped-image hash mismatch; rebuild/rerun the startup probe")
    evidence.update(captured_at_utc=datetime.now(timezone.utc).isoformat(),
                    command=f"python -m tools.seed_initializers --count {count}",
                    trace_sha256=hashlib.sha256(trace_bytes).hexdigest(),
                    manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
                    startup_wasm_sha256=wasm_hash, mapped_image_sha256=mapped_hash,
                    previous_seeds_sha256=hashlib.sha256(seeds_bytes).hexdigest() if seeds_bytes is not None else None)
    # Refuse a detectable concurrent rebuild/update instead of overwriting progress.
    if trace_path.read_bytes() != trace_bytes or manifest_path.read_bytes() != manifest_bytes:
        raise ValueError("Startup evidence/build changed during seeding; retry after the build finishes")
    if (seeds_path.read_bytes() if seeds_path.exists() else None) != seeds_bytes:
        raise ValueError("Startup seeds changed during seeding; retry to preserve the new progress")
    output_path(project, game_root, SEEDS_RELATIVE)
    output_path(project, game_root, EVIDENCE_RELATIVE)
    atomic_json(seeds_path, updated)
    atomic_json(evidence_path, evidence)
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=32, help="Number of table slots to inspect, 1..64 (default: 32)")
    args = parser.parse_args(argv)
    try:
        evidence = seed_initializers(args.count)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Initializer seeding failed: {exc}\n")
    print(json.dumps({"status": "seeded", "selected_slots": len(evidence["selected_slots"]),
                      "added_seeds": evidence["added_seed_count"], "total_seeds": evidence["merged_seed_count"],
                      "evidence": str(ROOT / EVIDENCE_RELATIVE)}, indent=2))


if __name__ == "__main__":
    main()
