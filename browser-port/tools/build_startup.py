"""Lift a bounded path from the audited executable's actual PE entry point."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import time
from datetime import datetime, timezone

from translator.lift import PEImage, lift
from tools.game_config import load_game_root, require_external_output
from tools.toolchain import ROOT
from tools.build_tests import EXE_SHA, STACK, SP, STOP, dwords, write_json, wasm

TEB=0x02500000
IMPORT_BASE=0x03100000
SEEDS_RELATIVE=Path('generated/startup-seeds.json')
SNAPSHOTS_RELATIVE=Path('artifacts/startup-seeds')
BUILD_OUTPUTS=('build/game-image.bin','generated/startup.cpp','generated/startup.json',
               'build/startup.js','build/startup.wasm','build/startup.json','artifacts/startup-build.json')


def unique_json_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError(f'Duplicate JSON field: {key}')
        result[key]=value
    return result


def validate_seeds(image, seeds, description='Startup seeds'):
    """Validate actual bytes, including malformed/overlapping PE section maps."""
    if not isinstance(seeds, list):
        raise ValueError(f'{description} must be a JSON list of integer guest addresses')
    for address in seeds:
        if type(address) is not int or not 0 <= address < 2**32:
            raise ValueError(f'{description} contains an invalid uint32 address: {address!r}')
        rva=address-image.base
        sections=[s for s in image.pe.sections
                  if s.VirtualAddress<=rva<s.VirtualAddress+min(s.Misc_VirtualSize,s.SizeOfRawData)]
        if len(sections)!=1 or not sections[0].Characteristics&0x20000000:
            raise ValueError(f'{description} address {address:#x} has no unambiguous file-backed executable section')
        offset=sections[0].PointerToRawData+rva-sections[0].VirtualAddress
        if not 0<=offset<len(image.data):
            raise ValueError(f'{description} address {address:#x} has truncated executable backing')
    return sorted(set(seeds))


def seed_file_path(path, project):
    path=Path(path).expanduser()
    expected=path if path.is_absolute() else Path(project)/path
    # Reject linked parents/files even when they point back inside the project.
    # Seed inputs are immutable; this also makes identity comparisons explicit.
    resolved=expected.resolve()
    if resolved!=expected.absolute():
        raise ValueError(f'Seed input must not be redirected through links: {expected}')
    return resolved


def output_path(project, game_root, relative):
    project=Path(project).resolve()
    relative=Path(relative)
    if relative.is_absolute() or '..' in relative.parts or not relative.parts or relative.parts[0] not in ('build','generated','artifacts'):
        raise ValueError('Startup output must stay in its designated ignored project directory')
    expected=project/relative
    resolved=require_external_output(expected,game_root)
    if resolved!=expected or project not in resolved.parents:
        raise ValueError(f'Startup output is redirected through a link: {expected}')
    if expected.exists() and expected.is_file() and expected.stat().st_nlink>1:
        raise ValueError(f'Startup output has multiple hard links: {expected}')
    return resolved


def load_seeds(image, project, seed_file=None):
    path=seed_file_path(SEEDS_RELATIVE if seed_file is None else seed_file,project)
    original=path.read_bytes() if path.exists() else None
    if original is None and seed_file is not None:
        raise ValueError(f'Seed file does not exist: {path}')
    if path.parent==Path(project).resolve()/SNAPSHOTS_RELATIVE:
        if not re.fullmatch(r'[0-9a-f]{64}\.json',path.name) or original is None or hashlib.sha256(original).hexdigest()!=path.stem:
            raise ValueError(f'Seed snapshot content does not match its SHA-256 filename: {path}')
    try:
        saved=json.loads(original,object_pairs_hook=unique_json_object) if original is not None else {'input_sha256':image.sha256,'seeds':[]}
    except (ValueError,UnicodeError) as exc:
        raise ValueError(f'Malformed startup seed JSON in {path}: {exc}') from exc
    if not isinstance(saved,dict) or saved.get('input_sha256')!=image.sha256:
        raise ValueError(f'Startup seed file belongs to a different executable or has no input_sha256: {path}')
    seeds=validate_seeds(image,saved.get('seeds'),f'Seed file {path}')
    return seeds,{'path':path,'original':original,'saved':saved,'update_default':seed_file is None}


def check_seed_input(source, project):
    path=seed_file_path(source['path'],project)
    current=path.read_bytes() if path.exists() else None
    if current!=source['original']:
        raise ValueError('Startup seed input changed during compilation; rebuild to preserve current progress')


def check_build_outputs(project, game_root, source):
    outputs=list(BUILD_OUTPUTS)
    if source['update_default']:outputs.append(str(SEEDS_RELATIVE))
    for relative in outputs:
        output=output_path(project,game_root,relative)
        if relative==str(SEEDS_RELATIVE) and source['update_default']:continue
        if output==source['path'] or (output.exists() and source['path'].exists() and output.samefile(source['path'])):
            raise ValueError(f'Seed input aliases a build output and would be overwritten: {output}')


def save_seed_snapshot(image, seeds, project, game_root):
    canonical={'input_sha256':image.sha256,'seeds':validate_seeds(image,seeds)}
    data=(json.dumps(canonical,indent=2)+'\n').encode('utf-8')
    digest=hashlib.sha256(data).hexdigest()
    relative=SNAPSHOTS_RELATIVE/(digest+'.json')
    path=output_path(project,game_root,relative)
    path.parent.mkdir(parents=True,exist_ok=True)
    output_path(project,game_root,relative)
    # Exclusive creation cannot overwrite a supplied snapshot or follow a newly
    # substituted file link. Existing content must match its address exactly.
    try:
        with path.open('xb') as stream:stream.write(data)
    except FileExistsError:
        output_path(project,game_root,relative)
        if path.read_bytes()!=data:
            raise ValueError(f'Seed snapshot content does not match its SHA-256 filename: {path}')
    return {'path':relative.as_posix(),'sha256':digest,'count':len(canonical['seeds'])}


def save_default_seeds(source, seeds, project, game_root):
    if not source['update_default']:return
    check_seed_input(source,project)
    path=output_path(project,game_root,SEEDS_RELATIVE)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',newline='\n',dir=path.parent,
                                         prefix=path.name+'.',suffix='.tmp',delete=False) as stream:
            temporary=Path(stream.name)
            stream.write(json.dumps({**source['saved'],'seeds':seeds},indent=2)+'\n')
        output_path(project,game_root,SEEDS_RELATIVE)
        check_seed_input(source,project)
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()


def prepare(limit=24000, extra_seeds=(), from_trace=False, max_steps=2000000, seed_file=None):
    started=time.perf_counter()
    if not 1<=max_steps<=10000000: raise ValueError('Startup max_steps must be in 1..10000000')
    sources=('translator/lift.py','runtime/guest.hpp','runtime/win32.hpp','tools/build_startup.py','tools/build_tests.py','tools/toolchain.py')
    source_hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources}
    game_root=load_game_root()
    image=PEImage(game_root/'speed.exe')
    if image.sha256!=EXE_SHA:
        raise ValueError('Executable changed: repeat audit and validate mappings before startup')
    if getattr(image.pe,'DIRECTORY_ENTRY_TLS',None):
        raise ValueError('TLS directory initialization is not implemented')
    if image.base+image.size>64*1024*1024:
        raise ValueError('PE does not fit bounded guest memory')
    seeds,seed_source=load_seeds(image,ROOT,seed_file)
    seeds=sorted(set(seeds)|set(validate_seeds(image,list(extra_seeds),'Extra seeds')))
    if from_trace:
        previous=json.loads((ROOT/'artifacts/startup-node.json').read_text())
        previous_manifest=previous.get('manifest') if isinstance(previous,dict) else None
        provenance=previous_manifest.get('provenance') if isinstance(previous_manifest,dict) else None
        if not isinstance(provenance,dict) or provenance.get('executable_sha256')!=image.sha256:
            raise ValueError('Execution trace belongs to a different executable')
        if not isinstance(previous.get('trace'),list) or any(type(a) is not int or not 0<=a<2**32 for a in previous['trace']):
            raise ValueError('Execution trace addresses must be uint32 integers')
        observed=[a for a in previous['trace'] if image.executable(a)]
        seeds=sorted(set(seeds)|set(observed))
    seeds=validate_seeds(image,seeds)
    check_build_outputs(ROOT,game_root,seed_source)
    mapped=bytearray(image.pe.get_memory_mapped_image())
    imports={}
    iat=[]
    for dll in image.pe.DIRECTORY_ENTRY_IMPORT:
        for entry in dll.imports:
            address=IMPORT_BASE+len(imports)*16
            name=dll.dll.decode('ascii')+'!'+(entry.name.decode('ascii') if entry.name else '#'+str(entry.ordinal))
            imports[address]=name
            struct.pack_into('<I',mapped,entry.address-image.base,address)
            iat.append({'iat':entry.address,'gateway':address,'name':name})
    # These names are observed in the audited CRT's GetProcAddress requests
    # (0x7ddc88 and 0x7cda33). Gateways provide replacement APIs, not game code.
    for name in ('KERNEL32.dll!InitializeCriticalSectionAndSpinCount',
                 'KERNEL32.dll!IsProcessorFeaturePresent'):
        if name not in imports.values():
            address=IMPORT_BASE+len(imports)*16
            imports[address]=name
            iat.append({'iat':None,'gateway':address,'name':name,'dynamic':True})
    (ROOT/'build').mkdir(exist_ok=True)
    (ROOT/'build/game-image.bin').write_bytes(mapped)
    report=lift(image,[image.entry,*seeds],ROOT/'generated/startup.cpp',limit,imports=imports)
    # The large diagnostic dispatch function makes LLVM optimization expensive.
    # Use O0 during coverage discovery; this is not a gameplay performance build.
    wasm(ROOT/'generated/startup.cpp','startup',optimization='-O0')
    if any(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest for name,digest in source_hashes.items()):
        raise RuntimeError('Translation/runtime sources changed during compilation; rebuild to obtain consistent provenance')
    check_seed_input(seed_source,ROOT)
    check_build_outputs(ROOT,game_root,seed_source)
    seed_snapshot=save_seed_snapshot(image,seeds,ROOT,game_root)
    regions=[*image.regions(),{'address':STACK,'size':0x10000,'permissions':3},
             {'address':TEB,'size':0x1000,'permissions':3},
             {'address':STOP,'size':0x1000,'permissions':5},
             {'address':IMPORT_BASE,'size':((len(imports)*16+4095)//4096)*4096,'permissions':5}]
    c={'id':'actual-pe-entry','entry':image.entry,'stop':STOP,'maxSteps':max_steps,
       'regions':regions,'registers':[0,0,0,0,SP,0,0,0],'eflags':0x202,'fsBase':TEB,
       'writes':[{'address':SP,'bytes':dwords(STOP)},
                 {'address':TEB,'bytes':dwords(0xffffffff,STACK+0x10000,STACK)},
                 {'address':TEB+0x18,'bytes':dwords(TEB)}],
       'xmm':[[0]*4 for _ in range(8)]}
    manifest={'schema':1,'kind':'startup-probe','module':'startup.js','case':c,
              'image':{'url':'game-image.bin','address':image.base,'sha256':hashlib.sha256(mapped).hexdigest()},
              'built_at_utc':datetime.now(timezone.utc).isoformat(),
              'provenance':{'executable_sha256':image.sha256,'entry':image.entry,
                            'cpu_profile':'Unicorn 2.1.4 UC_CPU_X86_PENTIUM3 CPUID leaves 0/1; OS-enabled SSE',
                            'fpu_control_profile':'Native authored AMD-host readback: (cw & 0x1f3f) | 0x40; reserved bits not universally specified',
                            'optimization':'-O0','build_elapsed_seconds':time.perf_counter()-started,
                            'instruction_count':report['instruction_count'],'instruction_limit':limit,'seeds':seeds,
                            'seed_snapshot':seed_snapshot,
                            'source_sha256':source_hashes},
              'artifact_sha256':{'startup.wasm':hashlib.sha256((ROOT/'build/startup.wasm').read_bytes()).hexdigest()},
              'imports':iat,
              'scope':'Bounded original entry execution. Required unimplemented imports fault. No menu/race claim.'}
    write_json(ROOT/'build/startup.json',manifest)
    write_json(ROOT/'artifacts/startup-build.json',report)
    save_default_seeds(seed_source,seeds,ROOT,game_root)
    print(json.dumps({'instructions':report['instruction_count'],'unsupported_sites':len(report['unsupported']),
                      'untranslated_targets':len(report['untranslated_targets']),
                      'import_gateways':len(imports),'entry':hex(image.entry)},indent=2))
    return manifest


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit',type=int,default=24000)
    parser.add_argument('--seed',type=lambda x:int(x,0),action='append',default=[])
    parser.add_argument('--seed-file',type=Path,help='Read-only hash-bound seed JSON; replaces default generated/startup-seeds.json input without overwriting either file')
    parser.add_argument('--from-trace',action='store_true',help='Prioritize original instruction addresses from the matching last local execution trace')
    parser.add_argument('--max-steps',type=int,default=2000000)
    args=parser.parse_args()
    try:
        prepare(args.limit,args.seed,args.from_trace,args.max_steps,args.seed_file)
    except (OSError,ValueError) as exc:
        parser.exit(2,f'Startup build failed: {exc}\n')
