"""Read-only input inventory and PE evidence export for the local reconstruction."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

import pefile

ROOT = Path(__file__).resolve().parents[1]
GAME = ROOT.parent
BINARIES = ("speed.exe", "server.dll", "nfsmwres.exe", "safemode_inst.exe", "shell_inst.exe")


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def text(value):
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def json_file(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def inventory():
    # Walk only the original installation. Never include our output/tool downloads.
    pending = [GAME]
    result = []
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            if path == ROOT:
                continue
            if path.is_symlink() or path.stat().st_file_attributes & 0x400:
                raise ValueError(f"Refusing reparse point: {path}")
            if path.is_dir():
                pending.append(path)
            elif path.is_file():
                before = path.stat()
                digest = sha256(path)
                after = path.stat()
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise ValueError(f"Input changed while hashing: {path}")
                result.append({"path": path.relative_to(GAME).as_posix(), "bytes": before.st_size,
                               "mtime_ns": before.st_mtime_ns, "sha256": digest})
    return sorted(result, key=lambda item: item["path"])


def export_pe(name):
    source = GAME / name
    output = ROOT / "evidence" / name
    output.mkdir(parents=True, exist_ok=True)
    raw = source.read_bytes()
    with pefile.PE(data=raw) as pe:
        base = pe.OPTIONAL_HEADER.ImageBase
        imports = [{"dll": text(group.dll), "symbols": [
            {"name": text(item.name) if item.name else None, "ordinal": item.ordinal,
             "iat_va": hex(item.address)} for item in group.imports]}
            for group in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        sections = []
        for index, section in enumerate(pe.sections):
            file = f"section_{index:02d}.bin"
            data = section.get_data()
            (output / file).write_bytes(data)
            sections.append({"name": text(section.Name.rstrip(b"\0")), "va": hex(base + section.VirtualAddress),
                "raw_file_offset": section.PointerToRawData, "virtual_bytes": section.Misc_VirtualSize,
                "raw_bytes": section.SizeOfRawData, "characteristics": hex(section.Characteristics),
                "file": file, "sha256": hashlib.sha256(data).hexdigest()})
        resources = []
        directory = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        for kind in getattr(directory, "entries", []):
            for resource in getattr(getattr(kind, "directory", None), "entries", []):
                for language in getattr(getattr(resource, "directory", None), "entries", []):
                    if not hasattr(language, "data"):
                        continue
                    entry = language.data.struct
                    data = pe.get_data(entry.OffsetToData, entry.Size)
                    if len(data) != entry.Size:
                        raise ValueError("Truncated PE resource")
                    file = f"resource_{len(resources):04d}.bin"
                    (output / file).write_bytes(data)
                    resources.append({"type": str(kind.name) if kind.name else kind.id,
                        "name": str(resource.name) if resource.name else resource.id,
                        "language": language.id, "rva": hex(entry.OffsetToData), "bytes": entry.Size,
                        "file": file, "sha256": hashlib.sha256(data).hexdigest()})
        debug = []
        for item in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            entry = {"type": item.struct.Type, "bytes": item.struct.SizeOfData}
            if item.struct.Type == 2:
                offset = item.struct.PointerToRawData
                data = raw[offset:offset + item.struct.SizeOfData]
                entry["signature"] = text(data[:4])
                if data.startswith(b"RSDS"):
                    entry["pdb_reference"] = text(data[24:].split(b"\0", 1)[0])
            debug.append(entry)
        exports = [{"name": text(item.name) if item.name else None, "ordinal": item.ordinal,
                    "va": hex(base + item.address)}
                   for item in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])]
        metadata = {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "machine": hex(pe.FILE_HEADER.Machine), "image_base": hex(base),
            "entry_va": hex(base + pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "coff_symbols": pe.FILE_HEADER.NumberOfSymbols, "debug": debug,
            "imports": imports, "exports": exports, "sections": sections, "resources": resources,
            "parser_warnings": pe.get_warnings()}
        json_file(output / "pe.json", metadata)
    with (output / "strings.tsv").open("w", encoding="utf-8", newline="\n") as stream:
        stream.write("file_offset\tencoding\ttext\n")
        for encoding, pattern in (("ascii", rb"[\x20-\x7e]{5,}"), ("utf-16le", rb"(?:[\x20-\x7e]\x00){5,}")):
            for match in re.finditer(pattern, raw):
                stream.write(f"{match.start():08x}\t{encoding}\t{match.group().decode(encoding)}\n")
    return metadata


def main():
    evidence = ROOT / "evidence"
    evidence.mkdir(exist_ok=True)
    snapshot = inventory()
    inventory_path = evidence / "input_inventory.json"
    if inventory_path.exists():
        prior = json.loads(inventory_path.read_text(encoding="utf-8"))
        if prior["files"] != snapshot:
            raise ValueError("Original installation changed since the recorded inventory")
    else:
        json_file(inventory_path, {"created_utc": datetime.now(timezone.utc).isoformat(),
                                  "files": snapshot})
    metadata = [export_pe(name) for name in BINARIES]
    report = {"created_utc": datetime.now(timezone.utc).isoformat(), "files": len(snapshot),
              "bytes": sum(item["bytes"] for item in snapshot),
              "extensions": dict(Counter(Path(item["path"]).suffix.lower() for item in snapshot)),
              "debug_files": [item["path"] for item in snapshot if Path(item["path"]).suffix.lower() in (".pdb", ".map", ".dbg")],
              "binaries": [{"file": item["file"], "sha256": item["sha256"]} for item in metadata]}
    json_file(evidence / "inventory_summary.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
