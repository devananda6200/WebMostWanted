"""Read-only, repeatable PE and asset-header evidence for the private installation."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from assets import PINNED_SHA256

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-dir', type=Path, required=True)
    args = parser.parse_args()
    data = (args.game_dir / 'speed.exe').read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != PINNED_SHA256:
        raise ValueError('Executable mismatch; do not reuse upstream addresses')
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    imports = [{"dll": i.dll.decode(), "symbols": [s.name.decode() if s.name else f'ordinal:{s.ordinal}'
                for s in i.imports]} for i in pe.DIRECTORY_ENTRY_IMPORT]
    resources = []
    for typ in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for name in typ.directory.entries:
            for lang in name.directory.entries:
                item = lang.data.struct
                resources.append(dict(type=typ.id, name=str(name.name or name.id), bytes=item.Size,
                    magic=pe.get_data(item.OffsetToData, min(16,item.Size)).hex()))
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    vtables = []
    for slot, expected in [(0x008abca0, 0x00690100), (0x008f7df0, 0x004497b0), (0x00895964, 0x00498dc0)]:
        target = struct.unpack('<I', pe.get_data(slot-base,4))[0]
        if target != expected:
            raise ValueError(f'Vtable mismatch at {slot:08x}')
        ins = list(decoder.disasm(pe.get_data(target-base,24), target))
        vtables.append(dict(slot=f'{slot:08x}', target=f'{target:08x}',
                           instructions=[f'{i.address:08x} {i.mnemonic} {i.op_str}' for i in ins]))
    report = dict(sha256=sha, size=len(data), machine=hex(pe.FILE_HEADER.Machine),
        pe_magic=hex(pe.OPTIONAL_HEADER.Magic), linker=f'{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}',
        timestamp_utc=datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp,timezone.utc).isoformat(),
        image_base=hex(base), entry_point=hex(base+pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        sections=[dict(name=s.Name.decode().rstrip('\x00'),va=hex(base+s.VirtualAddress),
                       virtual_size=s.Misc_VirtualSize, raw_size=s.SizeOfRawData) for s in pe.sections],
        imports=imports, resources=resources, verified_vtable_slots=vtables,
        version_resource_present=any(r['type']==16 for r in resources))
    artifacts = ROOT / 'artifacts'
    (artifacts/'pe-audit.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    inventory = json.loads((artifacts/'inventory.json').read_text(encoding='utf-8'))
    originals = [f for f in inventory['files'] if not f['relative_path'].startswith('source_code/')]
    samples = defaultdict(list)
    for f in originals:
        ext = Path(f['relative_path']).suffix.lower()
        if len(samples[ext]) < 3:
            with (args.game_dir / f['relative_path']).open('rb') as stream:
                samples[ext].append(dict(path=f['relative_path'], magic=stream.read(16).hex()))
    (artifacts/'asset-headers.json').write_text(json.dumps(samples,indent=2),encoding='utf-8')
    docs = ROOT / 'docs'; docs.mkdir(exist_ok=True)
    text = '# File inventory\n\nRead-only inventory of the supplied installation, 2026-10-11.\n\n'
    text += f"All files including prior development output: {inventory['file_count']:,}, {inventory['total_size_bytes']:,} bytes.\n\n"
    text += f"Original installation excluding `source_code/`: {len(originals):,} files, {sum(f['size_bytes'] for f in originals):,} bytes.\n\n"
    text += 'Private runtime allowlist: 1,356 files, 3,024,656,547 bytes. `source_code/`, helper executables, DLLs, icon, filelist and server config are excluded. Original installation and saves remain read-only.\n\n'
    text += '| Directory/file | Files | Bytes |\n|---|---:|---:|\n'
    for name, row in inventory['top_level_summary'].items():
        text += f"| `{name}` | {row['count']:,} | {row['bytes']:,} |\n"
    text += '\n## Original-file extension counts\n\n| Extension | Files |\n|---|---:|\n'
    for ext,count in Counter(Path(f['relative_path']).suffix.lower() for f in originals).most_common():
        text += f'| `{ext}` | {count} |\n'
    text += '\nEvery relative path and size is in ignored `artifacts/inventory.json`. Runtime full-file and 4 MiB chunk SHA-256 checksums are in `artifacts/asset-manifest.json`; sampled raw signatures are in `artifacts/asset-headers.json`. Extensions alone are not used as proof of format.\n'
    (docs/'file-inventory.md').write_text(text,encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('sha256','machine','pe_magic','linker','timestamp_utc','entry_point','version_resource_present')},indent=2))
    print(f'{sum(len(x["symbols"]) for x in imports)} imports across {len(imports)} DLLs; {len(resources)} resources; 3 verified vtable slots')


if __name__ == '__main__':
    main()
