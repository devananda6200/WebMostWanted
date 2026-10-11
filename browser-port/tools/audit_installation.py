"""Inventory a local game installation and parse its PE files; never execute them.

Detailed output may contain executable-derived metadata and belongs in artifacts/.
All input handles are opened read-only. File timestamps, installers and embedded
version labels are evidence, never proof of provenance or instructions to run.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM
import pefile

try:
    from .game_config import load_game_root, require_external_output
except ImportError:
    from game_config import load_game_root, require_external_output


def text(value: bytes | str | None) -> str | None:
    if value is None:
        return None
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def import_table(pe: pefile.PE, attribute: str) -> list[dict]:
    return [
        {
            "dll": text(group.dll),
            "symbols": [
                {
                    "name": text(entry.name),
                    "ordinal": entry.ordinal,
                    "iat_address": entry.address,
                    "hint": getattr(entry, "hint", None),
                }
                for entry in group.imports
            ],
        }
        for group in getattr(pe, attribute, [])
    ]


def resource_types(pe: pefile.PE) -> list[dict]:
    directory = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if not directory:
        return []
    return [
        {
            "id": entry.id,
            "name": str(entry.name) if entry.name is not None else pefile.RESOURCE_TYPE.get(entry.id),
            "entries": len(getattr(getattr(entry, "directory", None), "entries", [])),
        }
        for entry in directory.entries
    ]


def resource_entries(pe: pefile.PE) -> list[dict]:
    result = []
    directory = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    for kind in getattr(directory, "entries", []):
        for name in getattr(getattr(kind, "directory", None), "entries", []):
            for language in getattr(getattr(name, "directory", None), "entries", []):
                data = getattr(language, "data", None)
                if data:
                    result.append({
                        "type_id": kind.id,
                        "type_name": str(kind.name) if kind.name is not None else pefile.RESOURCE_TYPE.get(kind.id),
                        "name": str(name.name) if name.name is not None else name.id,
                        "language_id": language.id,
                        "rva": data.struct.OffsetToData,
                        "size": data.struct.Size,
                    })
    return result


def version_strings(pe: pefile.PE) -> dict:
    values = {}
    for block in getattr(pe, "FileInfo", []):
        for item in block:
            for table in getattr(item, "StringTable", []):
                values.update({text(key): text(value) for key, value in table.entries.items()})
    return values


def tls_information(pe: pefile.PE) -> dict | None:
    directory = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if directory is None:
        return None
    structure = directory.struct
    callbacks = []
    callback_error = None
    pointer_size = 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
    rva = structure.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
    if structure.AddressOfCallBacks:
        try:
            for index in range(256):
                raw = pe.get_data(rva + index * pointer_size, pointer_size)
                if len(raw) != pointer_size:
                    raise ValueError("TLS callback table is truncated")
                callback = int.from_bytes(raw, "little")
                if not callback:
                    break
                callbacks.append(callback)
            else:
                callback_error = "TLS callback list exceeds audit bound of 256"
        except (ValueError, pefile.PEFormatError) as exc:
            callback_error = str(exc)
    return {
        "raw_data_start_va": structure.StartAddressOfRawData,
        "raw_data_end_va": structure.EndAddressOfRawData,
        "index_va": structure.AddressOfIndex,
        "callbacks_va": structure.AddressOfCallBacks,
        "zero_fill_bytes": structure.SizeOfZeroFill,
        "callbacks": callbacks,
        "callback_error": callback_error,
    }


def debug_information(pe: pefile.PE) -> list[dict]:
    entries = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        info = {
            "type": entry.struct.Type,
            "type_name": pefile.DEBUG_TYPE.get(entry.struct.Type),
            "size": entry.struct.SizeOfData,
        }
        data = pe.get_data(entry.struct.AddressOfRawData, entry.struct.SizeOfData)
        if data.startswith(b"RSDS") and len(data) >= 24:
            info["codeview_signature"] = "RSDS"
            info["pdb_path"] = text(data[24:].split(b"\0", 1)[0])
        elif data.startswith(b"NB10") and len(data) >= 16:
            info["codeview_signature"] = "NB10"
            info["pdb_path"] = text(data[16:].split(b"\0", 1)[0])
        entries.append(info)
    return entries


INTERFACE_TERMS = {
    "graphics": ("d3d", "direct3d", "ddraw", "opengl", "gdi32", "dxgi"),
    "audio": ("dsound", "directsound", "winmm", "waveout", "miles", "bink", "eax"),
    "input": ("dinput", "directinput", "xinput", "getkeystate", "getasynckeystate", "joystick"),
    "filesystem": ("createfile", "readfile", "writefile", "setfilepointer", "findfirstfile", "getfile", "deletefile"),
    "dynamic_code_or_loading": ("loadlibrary", "getprocaddress", "virtualprotect", "virtualalloc"),
    "threading": ("createthread", "criticalsection", "mutex", "event", "waitfor"),
    "registry": ("regopen", "regquery", "regcreate", "regset"),
    "network": ("wsock", "ws2_", "wininet", "netapi", "tapi32"),
}


def interface_evidence(imports: list[dict]) -> dict[str, list[str]]:
    result = defaultdict(set)
    for group in imports:
        dll = group["dll"] or ""
        for symbol in group["symbols"]:
            label = f"{dll}!{symbol['name'] or ('ordinal:' + str(symbol['ordinal']))}"
            lowered = label.lower()
            for category, terms in INTERFACE_TERMS.items():
                if any(term in lowered for term in terms):
                    result[category].add(label)
            if (symbol["name"] or "").startswith("Tls"):
                result["threading"].add(label)
    return {key: sorted(values) for key, values in sorted(result.items())}


def inspect_pe(path: Path) -> dict:
    """Return evidence, including heuristic indicators explicitly labelled as such."""
    identity = {"sha256": sha256_file(path), "size": path.stat().st_size}
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except (OSError, pefile.PEFormatError) as exc:
        return {**identity, "parse_error": str(exc)}
    try:
        sections = []
        indicators = []
        for section in pe.sections:
            characteristics = section.Characteristics
            entry = {
                "name": text(section.Name.rstrip(b"\0")),
                "rva": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_offset": section.PointerToRawData,
                "raw_size": section.SizeOfRawData,
                "characteristics": characteristics,
                "readable": bool(characteristics & 0x40000000),
                "writable": bool(characteristics & 0x80000000),
                "executable": bool(characteristics & 0x20000000),
                "entropy": round(section.get_entropy(), 4),
            }
            sections.append(entry)
            if entry["executable"] and entry["writable"]:
                indicators.append(f"section {entry['name']} is writable and executable")
            if entry["raw_size"] >= 4096 and entry["entropy"] > 7.2:
                indicators.append(f"section {entry['name']} has high entropy ({entry['entropy']}); compression/encryption is unproven")
            if entry["executable"] and entry["virtual_size"] > max(4096, entry["raw_size"] * 2):
                indicators.append(f"executable section {entry['name']} has substantially more virtual than raw data")
        imports = import_table(pe, "DIRECTORY_ENTRY_IMPORT")
        delay_imports = import_table(pe, "DIRECTORY_ENTRY_DELAY_IMPORT")
        exports = []
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if directory:
            exports = [
                {"name": text(symbol.name), "ordinal": symbol.ordinal, "rva": symbol.address, "forwarder": text(symbol.forwarder)}
                for symbol in directory.symbols
            ]
        relocation_types = Counter(
            entry.type
            for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", [])
            for entry in block.entries
        )
        overlay_start = pe.get_overlay_data_start_offset()
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_section = next((section["name"] for section in sections if section["rva"] <= entry_rva < section["rva"] + max(section["virtual_size"], section["raw_size"])), None)
        signature = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        return {
            **identity,
            "machine": pe.FILE_HEADER.Machine,
            "machine_name": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine),
            "pe_kind": "PE32+" if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else "PE32",
            "timestamp_header_untrusted": pe.FILE_HEADER.TimeDateStamp,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "image_size": pe.OPTIONAL_HEADER.SizeOfImage,
            "entry_point_rva": entry_rva,
            "entry_point_va": pe.OPTIONAL_HEADER.ImageBase + entry_rva,
            "entry_point_section": entry_section,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "linker_version": f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
            "file_characteristics": pe.FILE_HEADER.Characteristics,
            "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "stack_reserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
            "stack_commit": pe.OPTIONAL_HEADER.SizeOfStackCommit,
            "heap_reserve": pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            "heap_commit": pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            "coff_symbol_count": pe.FILE_HEADER.NumberOfSymbols,
            "sections": sections,
            "imports": imports,
            "delay_imports": delay_imports,
            "exports": exports,
            "debug": debug_information(pe),
            "version_strings_untrusted": version_strings(pe),
            "resource_types": resource_types(pe),
            "resource_entries": resource_entries(pe),
            "tls": tls_information(pe),
            "relocation_type_counts": {str(key): value for key, value in sorted(relocation_types.items())},
            "certificate_table_present_not_validated": bool(signature.VirtualAddress and signature.Size),
            "overlay_bytes": 0 if overlay_start is None else path.stat().st_size - overlay_start,
            "interface_import_evidence": interface_evidence(imports + delay_imports),
            "heuristic_obstacles_not_proof_of_packing": indicators,
            "parser_warnings": pe.get_warnings(),
        }
    finally:
        pe.close()


def inventory(root: Path) -> tuple[list[dict], list[str]]:
    files = []
    skipped = []
    # Do not traverse junctions/symlinks out of the explicitly selected installation.
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            stat = path.lstat()
            if path.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & 0x400):
                skipped.append(path.relative_to(root).as_posix())
            elif path.is_dir():
                pending.append(path)
            elif path.is_file():
                files.append({
                    "path": path.relative_to(root).as_posix(),
                    "size": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "extension": path.suffix.lower() or "<none>",
                })
    return sorted(files, key=lambda item: item["path"].lower()), sorted(skipped)


def audit(root: Path) -> dict:
    files, skipped = inventory(root)
    extension_counts = Counter(item["extension"] for item in files)
    extension_bytes = Counter()
    directories = defaultdict(lambda: {"files": 0, "bytes": 0})
    pe_files = {}
    asset_samples = defaultdict(list)
    for item in files:
        path = root / item["path"]
        extension_bytes[item["extension"]] += item["size"]
        for parent in Path(item["path"]).parents:
            key = parent.as_posix()
            directories[key]["files"] += 1
            directories[key]["bytes"] += item["size"]
        if item["extension"] in {".exe", ".dll"}:
            pe_files[item["path"]] = inspect_pe(path)
        elif len(asset_samples[item["extension"]]) < 3:
            with path.open("rb") as stream:
                header = stream.read(16)
            asset_samples[item["extension"]].append({"path": item["path"], "header_hex": header.hex()})
    after, skipped_after = inventory(root)
    # This detects size/mtime changes during the audit, not every possible external modification.
    unchanged = files == after and skipped == skipped_after
    local_dlls = {Path(name).name.casefold(): name for name in pe_files if name.lower().endswith(".dll")}
    dependencies = {}
    for name, entry in pe_files.items():
        dependencies[name] = [
            {"dll": group["dll"], "local_match": local_dlls.get((group["dll"] or "").casefold()), "resolution": "bundled candidate; loader search order unverified" if (group["dll"] or "").casefold() in local_dlls else "not bundled; platform resolution unverified"}
            for group in entry.get("imports", []) + entry.get("delay_imports", [])
        ]
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone(timedelta(hours=5, minutes=30))).isoformat(),
        "audit_tool": {"python": sys.version.split()[0], "pefile": pefile.__version__},
        "installation_root": str(root),
        "file_count": len(files),
        "total_bytes": sum(item["size"] for item in files),
        "read_only_observation": {"size_mtime_inventory_unchanged": unchanged, "executed_original_files": False},
        "files": files,
        "directories": dict(sorted(directories.items())),
        "extensions": {key: {"files": extension_counts[key], "bytes": extension_bytes[key]} for key in sorted(extension_counts)},
        "skipped_reparse_points": skipped,
        "zero_length_files": [item["path"] for item in files if item["size"] == 0],
        "pe_files": pe_files,
        "static_dependency_resolution": dependencies,
        "asset_header_samples": dict(sorted(asset_samples.items())),
        "symbols_and_configs": [item["path"] for item in files if item["extension"] in {".pdb", ".map", ".dbg", ".ini", ".cfg", ".sav", ".reg"}],
        "limitations": [
            "Static audit only: no original executable, DLL, installer or bundled script was run.",
            "Version-resource text and linker timestamps are not authenticated provenance.",
            "Import lists do not prove which code paths execute, and omit unresolved runtime loads.",
            "Section entropy and permissions are indicators only, not proof of packing or self-modification.",
            "No user profile/save directory outside the selected installation was inspected.",
            "Asset extensions and sampled headers are evidence, not validated format specifications.",
        ],
    }


def bounded_function_analysis(pe: pefile.PE, start: int, max_instructions: int = 512) -> dict:
    """Follow direct intraprocedural edges, not calls; this is not a full CFG recovery."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    iat = {
        symbol.address: f"{text(group.dll)}!{text(symbol.name) or ('ordinal:' + str(symbol.ordinal))}"
        for group in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for symbol in group.imports
    }
    base = pe.OPTIONAL_HEADER.ImageBase
    pending = [start]
    decoded = {}
    stops = []
    while pending and len(decoded) < max_instructions:
        address = pending.pop()
        if address in decoded:
            continue
        if not start <= address < start + 8192:
            stops.append({"address": address, "reason": "branch leaves bounded 8192-byte region; possible tail call"})
            continue
        section = pe.get_section_by_rva(address - base)
        if section is None or not section.Characteristics & 0x20000000:
            stops.append({"address": address, "reason": "target is not in an executable section"})
            continue
        instruction = next(decoder.disasm(pe.get_data(address - base, 15), address, count=1), None)
        if instruction is None:
            stops.append({"address": address, "reason": "instruction decode failed"})
            continue
        entry = {"address": address, "size": instruction.size, "mnemonic": instruction.mnemonic, "operands": instruction.op_str}
        decoded[address] = entry
        operands = instruction.operands
        if instruction.group(capstone.CS_GRP_CALL):
            if operands and operands[0].type == X86_OP_IMM:
                entry["direct_call_target"] = operands[0].imm & 0xFFFFFFFF
            elif operands and operands[0].type == X86_OP_MEM and not operands[0].mem.base and not operands[0].mem.index:
                entry["indirect_call_slot"] = operands[0].mem.disp & 0xFFFFFFFF
                entry["import_name"] = iat.get(entry["indirect_call_slot"])
            else:
                entry["unresolved_indirect_call"] = True
        if instruction.group(capstone.CS_GRP_RET) or instruction.mnemonic == "int3":
            continue
        if instruction.group(capstone.CS_GRP_JUMP):
            if operands and operands[0].type == X86_OP_IMM:
                pending.append(operands[0].imm & 0xFFFFFFFF)
            else:
                stops.append({"address": address, "reason": "indirect jump target unresolved"})
            if instruction.mnemonic == "jmp":
                continue
        pending.append(address + instruction.size)
    return {
        "start_va": start,
        "instruction_limit": max_instructions,
        "limit_reached": bool(pending),
        "instructions": [decoded[key] for key in sorted(decoded)],
        "stops": stops,
        "limitations": "Static reachable direct branches within an 8192-byte region; calls not followed, runtime execution not established, exception handlers and indirect destinations unresolved.",
    }


def analyze_startup(path: Path, extra_functions: list[int], pointer_tables: list[tuple[int, int]] | None = None) -> dict:
    with pefile.PE(str(path)) as pe:
        if pe.FILE_HEADER.Machine != 0x14C:
            raise ValueError("Bounded startup analysis currently supports i386 only.")
        entry = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        first = bounded_function_analysis(pe, entry)
        direct = sorted({item["direct_call_target"] for item in first["instructions"] if "direct_call_target" in item})
        functions = {hex(entry): first}
        for address in sorted(set(direct[:32] + extra_functions)):
            functions[hex(address)] = bounded_function_analysis(pe, address)
        tables = []
        for start, end in pointer_tables or []:
            base = pe.OPTIONAL_HEADER.ImageBase
            if not (base <= start < end <= base + pe.OPTIONAL_HEADER.SizeOfImage) or (end - start) % 4 or end - start > 16384:
                raise ValueError("Pointer-table range must be inside the image, DWORD-sized, and at most 16384 bytes.")
            raw = pe.get_data(start - base, end - start)
            if len(raw) != end - start:
                raise ValueError("Pointer-table range is not fully backed by file data.")
            targets = [int.from_bytes(raw[index:index + 4], "little") for index in range(0, len(raw), 4)]
            tables.append({
                "start_va": start,
                "end_va_exclusive": end,
                "slot_count": len(targets),
                "nonzero_count": sum(bool(target) for target in targets),
                "entries": [{"slot_va": start + index * 4, "initial_target_va": target} for index, target in enumerate(targets)],
                "limitation": "Initial DWORD contents only. Executability, runtime mutation and call reachability require validation.",
            })
        return {
            "sha256": sha256_file(path),
            "filename": path.name,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "entry_point_va": entry,
            "capstone_version": capstone.__version__,
            "scope": "Entry function, up to 32 direct callees, and explicitly selected extra functions; maximum 512 instructions per function.",
            "functions": functions,
            "selected_pointer_tables": tables,
        }


def parse_table_range(value: str) -> tuple[int, int]:
    try:
        start, end = value.split(":")
        return int(start, 0), int(end, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use a start:end VA range, for example 0x401000:0x401010.") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "artifacts" / "audit.json")
    parser.add_argument("--startup-output", type=Path, help="Also write ignored bounded static entry/callee analysis for speed.exe.")
    parser.add_argument("--function", action="append", type=lambda value: int(value, 0), default=[], help="Additional verified VA to analyze with --startup-output; repeatable.")
    parser.add_argument("--pointer-table", action="append", type=parse_table_range, default=[], help="Selected start:end VA range of initial DWORD callback pointers; repeatable.")
    arguments = parser.parse_args()
    try:
        root = load_game_root()
        output = require_external_output(arguments.output, root)
        result = audit(root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if arguments.startup_output:
            startup_output = require_external_output(arguments.startup_output, root)
            startup = analyze_startup(root / "speed.exe", arguments.function, arguments.pointer_table)
            startup_output.parent.mkdir(parents=True, exist_ok=True)
            startup_output.write_text(json.dumps(startup, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, pefile.PEFormatError) as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 1
    print(f"Audited {result['file_count']} files ({result['total_bytes']} bytes), {len(result['pe_files'])} PE candidates.")
    print(f"Detailed local report: {output}")
    if not result["read_only_observation"]["size_mtime_inventory_unchanged"]:
        print("Installation changed during audit; repeat after other file activity stops.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
