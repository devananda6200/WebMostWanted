"""Lift a bounded path from the audited executable's actual PE entry point."""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from datetime import datetime, timezone

from translator.lift import PEImage, lift
from tools.game_config import load_game_root
from tools.toolchain import ROOT
from tools.build_tests import EXE_SHA, STACK, SP, STOP, dwords, write_json, wasm

TEB=0x02500000
IMPORT_BASE=0x03100000


def prepare(limit=3000, extra_seeds=()):
    image=PEImage(load_game_root()/'speed.exe')
    if image.sha256!=EXE_SHA:
        raise ValueError('Executable changed: repeat audit and validate mappings before startup')
    if getattr(image.pe,'DIRECTORY_ENTRY_TLS',None):
        raise ValueError('TLS directory initialization is not implemented')
    if image.base+image.size>64*1024*1024:
        raise ValueError('PE does not fit bounded guest memory')
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
    (ROOT/'build').mkdir(exist_ok=True)
    (ROOT/'build/game-image.bin').write_bytes(mapped)
    report=lift(image,[image.entry,*extra_seeds],ROOT/'generated/startup.cpp',limit,imports=imports)
    wasm(ROOT/'generated/startup.cpp','startup')
    regions=[*image.regions(),{'address':STACK,'size':0x10000,'permissions':3},
             {'address':TEB,'size':0x1000,'permissions':3},
             {'address':STOP,'size':0x1000,'permissions':5},
             {'address':IMPORT_BASE,'size':((len(imports)*16+4095)//4096)*4096,'permissions':5}]
    c={'id':'actual-pe-entry','entry':image.entry,'stop':STOP,'maxSteps':1000000,
       'regions':regions,'registers':[0,0,0,0,SP,0,0,0],'eflags':0x202,'fsBase':TEB,
       'writes':[{'address':SP,'bytes':dwords(STOP)},
                 {'address':TEB,'bytes':dwords(0xffffffff,STACK+0x10000,STACK)},
                 {'address':TEB+0x18,'bytes':dwords(TEB)}],
       'xmm':[[0]*4 for _ in range(8)]}
    manifest={'schema':1,'kind':'startup-probe','module':'startup.js','case':c,
              'image':{'url':'game-image.bin','address':image.base,'sha256':hashlib.sha256(mapped).hexdigest()},
              'built_at_utc':datetime.now(timezone.utc).isoformat(),
              'provenance':{'executable_sha256':image.sha256,'entry':image.entry,
                            'instruction_count':report['instruction_count']},
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
    parser.add_argument('--limit',type=int,default=3000)
    parser.add_argument('--seed',type=lambda x:int(x,0),action='append',default=[])
    args=parser.parse_args()
    prepare(args.limit,args.seed)
