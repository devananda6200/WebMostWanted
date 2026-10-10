"""Lift a bounded path from the audited executable's actual PE entry point."""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
import time
from datetime import datetime, timezone

from translator.lift import PEImage, lift
from tools.game_config import load_game_root
from tools.toolchain import ROOT
from tools.build_tests import EXE_SHA, STACK, SP, STOP, dwords, write_json, wasm

TEB=0x02500000
IMPORT_BASE=0x03100000


def prepare(limit=8000, extra_seeds=(), from_trace=False, max_steps=2000000):
    started=time.perf_counter()
    if not 1<=max_steps<=10000000: raise ValueError('Startup max_steps must be in 1..10000000')
    sources=('translator/lift.py','runtime/guest.hpp','runtime/win32.hpp','tools/build_startup.py','tools/build_tests.py','tools/toolchain.py')
    source_hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources}
    image=PEImage(load_game_root()/'speed.exe')
    if image.sha256!=EXE_SHA:
        raise ValueError('Executable changed: repeat audit and validate mappings before startup')
    if getattr(image.pe,'DIRECTORY_ENTRY_TLS',None):
        raise ValueError('TLS directory initialization is not implemented')
    if image.base+image.size>64*1024*1024:
        raise ValueError('PE does not fit bounded guest memory')
    seeds_path=ROOT/'generated/startup-seeds.json'
    saved=json.loads(seeds_path.read_text()) if seeds_path.exists() else {'input_sha256':image.sha256,'seeds':[]}
    if saved['input_sha256']!=image.sha256: raise ValueError('Saved startup seeds belong to a different executable')
    seeds=sorted(set(saved['seeds'])|set(extra_seeds))
    if from_trace:
        previous=json.loads((ROOT/'artifacts/startup-node.json').read_text())
        if previous['manifest']['provenance']['executable_sha256']!=image.sha256:
            raise ValueError('Execution trace belongs to a different executable')
        observed=[a for a in previous['trace'] if image.executable(a)]
        seeds=sorted(set(seeds)|set(observed))
    for address in seeds:
        if not image.executable(address):raise ValueError(f'Extra seed has no executable backing: {address:#x}')
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
    write_json(seeds_path,{'input_sha256':image.sha256,'seeds':seeds})
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
                            'optimization':'-O0','build_elapsed_seconds':time.perf_counter()-started,
                            'instruction_count':report['instruction_count'],'instruction_limit':limit,'seeds':seeds,
                            'source_sha256':source_hashes},
              'artifact_sha256':{'startup.wasm':hashlib.sha256((ROOT/'build/startup.wasm').read_bytes()).hexdigest()},
              'imports':iat,
              'scope':'Bounded original entry execution. Required unimplemented imports fault. No menu/race claim.'}
    write_json(ROOT/'build/startup.json',manifest)
    write_json(ROOT/'artifacts/startup-build.json',report)
    print(json.dumps({'instructions':report['instruction_count'],'unsupported_sites':len(report['unsupported']),
                      'untranslated_targets':len(report['untranslated_targets']),
                      'import_gateways':len(imports),'entry':hex(image.entry)},indent=2))
    return manifest


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit',type=int,default=8000)
    parser.add_argument('--seed',type=lambda x:int(x,0),action='append',default=[])
    parser.add_argument('--from-trace',action='store_true',help='Prioritize original instruction addresses from the matching last local execution trace')
    parser.add_argument('--max-steps',type=int,default=2000000)
    args=parser.parse_args()
    prepare(args.limit,args.seed,args.from_trace,args.max_steps)
