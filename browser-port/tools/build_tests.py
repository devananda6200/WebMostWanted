"""Compile an x86 PE fixture, lift binaries, build Wasm, generate CPU references."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn import x86_const as x86
from translator.lift import PEImage, lift
from tools.game_config import load_game_root
from tools.toolchain import ROOT, SDK_VERSION, clang_path, linker_command, compile_wasm

REG_IDS=[getattr(x86,'UC_X86_REG_'+n) for n in 'EAX ECX EDX EBX ESP EBP ESI EDI'.split()]
XMM_IDS=[getattr(x86,'UC_X86_REG_XMM'+str(i)) for i in range(8)]
STACK=0x02000000
SP=STACK+0x8000
DATA=0x02200000
STOP=0x03000000
FLAGS=0x8d5
EXE_SHA='80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c'
ROUTINE=0x460bf0
ROUTINE_SIZE=33
ROUTINE_SHA='c5798f0490c6fc265ff0ebd063a7c536e8281fb2789eb4434900ebb3d3896808'


def write_json(path, value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def dwords(*values):
    return list(struct.pack('<'+'I'*len(values),*(v&0xffffffff for v in values)))


def compile_fixture():
    source=ROOT/'tests/fixture.S'
    obj=ROOT/'build/fixture.obj'
    exe=ROOT/'build/fixture.exe'
    subprocess.run([str(clang_path()),'--target=i686-pc-windows-msvc','-c',str(source),'-o',str(obj)],check=True)
    names=['arithmetic','branch','memory','calls','callee','simd','x87_load_store',
           'add_flags','sub_flags','adc_flags','sbb_flags','byte_flags','shifts','copy',
           'unmapped','unsupported','code_write','indirect_missing','xchg_alias','partial_simd_store','stdcall_call','stdcall_callee',
           'sse_movsd_unsupported','popfd_reserved','popfd_control_unsupported']
    command=[*linker_command(),'/machine:x86','/subsystem:console','/entry:arithmetic',
             '/nodefaultlib','/fixed','/base:0x1000000','/timestamp:0','/safeseh:no',
             f'/out:{exe}',*(f'/export:{name}' for name in names),str(obj)]
    subprocess.run(command,check=True)
    return PEImage(exe)


def wasm(source, name, optimization='-O1'):
    compile_wasm(source, ROOT/'build'/f'{name}.js', [
        '-I'+str(ROOT),'-std=c++17',optimization,'--no-entry',
        '-sMODULARIZE=1','-sEXPORT_ES6=1','-sENVIRONMENT=web,worker,node',
        '-sALLOW_MEMORY_GROWTH=0','-sINITIAL_MEMORY=83886080','-sSTACK_SIZE=1048576',
        '-sASSERTIONS=2','-sEXPORTED_RUNTIME_METHODS=["UTF8ToString","HEAPU8"]',
        '-ffp-contract=off','-fno-fast-math'])


def code_writes(image, full=False):
    if full:
        return [{"address":image.base,"bytes":list(image.pe.get_memory_mapped_image())}]
    result=[]
    for s in image.pe.sections:
        if s.Characteristics & 0x20000000:
            result.append({"address":image.base+s.VirtualAddress,"bytes":list(s.get_data())})
    return result


def case(image, name, args=(), flags=0x202, writes=(), code=None, regions=None, watches=None):
    registers=[0x11223344,0x55667788,0x99aabbcc,0x1234abcd,SP,0x13579bdf,0x2468ace0,0xfedcba98]
    return {'id':name,'entry':image.exports.get(name.split('/')[0],ROUTINE),'stop':STOP,
            'regions':regions or [*image.regions(),{'address':STACK,'size':0x10000,'permissions':3},
                                  {'address':DATA,'size':0x10000,'permissions':3},
                                  {'address':STOP,'size':4096,'permissions':5}],
            'writes':[*((code_writes(image) if code is None else code)),
                      {'address':SP,'bytes':dwords(STOP,*args)},*writes],
            'registers':registers,'eflags':flags,
            'xmm':[[0x3f800000+j+i for j in range(4)] for i in range(8)],
            'watches':watches or [{'address':DATA,'size':512},{'address':SP-256,'size':512}],
            'flagsMask':FLAGS,'maxSteps':100000}


def reference(c):
    """Isolated CPU emulator: mapped test bytes only; no Windows/syscalls/network."""
    u=Uc(UC_ARCH_X86,UC_MODE_32)
    for reg in c['regions']:
        u.mem_map(reg['address'],reg['size'],reg['permissions'])
    for w in c['writes']:
        u.mem_write(w['address'],bytes(w['bytes']))
    for reg,value in zip(REG_IDS,c['registers']): u.reg_write(reg,value)
    for reg,lanes in zip(XMM_IDS,c['xmm']): u.reg_write(reg,sum(v<<(32*i) for i,v in enumerate(lanes)))
    u.reg_write(x86.UC_X86_REG_EFLAGS,c['eflags'])
    count=0
    def tick(_u,address,size,user):
        nonlocal count
        count+=1
    u.hook_add(UC_HOOK_CODE,tick)
    u.emu_start(c['entry'],c['stop'],timeout=2_000_000,count=c['maxSteps'])
    if u.reg_read(x86.UC_X86_REG_EIP)!=c['stop']:
        raise RuntimeError(f"Reference did not return: {c['id']}")
    c['expected']={'registers':[u.reg_read(r) for r in REG_IDS],
                   'eflags':u.reg_read(x86.UC_X86_REG_EFLAGS),'flagsMask':c.pop('flagsMask'),
                   'xmm':[[int(u.reg_read(r)>>(32*i))&0xffffffff for i in range(4)] for r in XMM_IDS],
                   'memory':[{'address':w['address'],'bytes':list(u.mem_read(w['address'],w['size']))} for w in c.pop('watches')],
                   'referenceSteps':count}
    return c


def synthetic_cases(image):
    cases=[]
    rng=random.Random(2005)
    boundary=[0,1,0x7fffffff,0x80000000,0xffffffff,0x80,0xff,0xffff]
    for name in ('add_flags','sub_flags','adc_flags','sbb_flags','byte_flags','arithmetic','branch'):
        pairs=[(a,b) for a in boundary for b in boundary]
        pairs += [(rng.getrandbits(32),rng.getrandbits(32)) for _ in range(16)]
        for index,(a,b) in enumerate(pairs):
            c=case(image,f'{name}/{index}',[a,b],flags=0x202|(index%2))
            if name=='arithmetic': c['flagsMask']=FLAGS & ~0x10 # final XOR leaves AF undefined
            cases.append(reference(c))
    for index,(a,count) in enumerate((a,n) for a in boundary for n in (0,1,7,16,31,32,33)):
        c=case(image,f'shifts/{index}',[a,count]);c['flagsMask']=FLAGS&~0x10
        cases.append(reference(c))
    for name in ('memory','copy'):
        c=case(image,name,[DATA+128,DATA],writes=[{'address':DATA,'bytes':dwords(*range(8))}])
        cases.append(reference(c))
    for i,v in enumerate(boundary): cases.append(reference(case(image,f'calls/{i}',[v])))
    cases.append(reference(case(image,'xchg_alias',[DATA],writes=[{'address':DATA,'bytes':dwords(0x12345678)}])))
    cases.append(reference(case(image,'stdcall_call',[DATA])))
    cases.append(reference(case(image,'popfd_reserved',[0x20a])))
    # Finite, exactly representable SIMD operands avoid making a claim about
    # NaN payloads, MXCSR exceptions, or x87 extended arithmetic.
    values=[1.5,-2.0,3.25,0.125,2.0,4.0,-0.5,8.0,7.75]
    c=case(image,'simd',[DATA,DATA+128],writes=[{'address':DATA,'bytes':list(struct.pack('<9f',*values))}])
    cases.append(reference(c))
    for i,v in enumerate([0.0,-0.0,1.5,-123.75,2**-100]):
        c=case(image,f'x87_load_store/{i}',[DATA,DATA+128],writes=[{'address':DATA,'bytes':list(struct.pack('<f',v))}])
        cases.append(reference(c))
    return cases


def real_cases(image):
    if image.sha256!=EXE_SHA:
        raise ValueError('Unrecognized executable hash: audit and select routine again')
    data=image.read(ROUTINE,ROUTINE_SIZE)
    if hashlib.sha256(data).hexdigest()!=ROUTINE_SHA: raise ValueError('Routine bytes changed')
    regions=[{'address':ROUTINE&~4095,'size':4096,'permissions':5},
             {'address':STACK,'size':0x10000,'permissions':3},
             {'address':DATA,'size':0x10000,'permissions':3},
             {'address':STOP,'size':4096,'permissions':5}]
    rng=random.Random(0x460bf0)
    strings=[b'',b'A',b'MOSTWANTED',bytes(range(1,256)),b'a\0ignored',b'z'*4096]
    strings += [bytes(rng.randrange(1,256) for _ in range(rng.randrange(1,256))) for _ in range(32)]
    cases=[]
    for i,data_in in enumerate(strings):
        c=case(image,f'real_hash/{i}',[DATA],regions=regions,
               code=[{'address':ROUTINE,'bytes':list(data)}],
               writes=[{'address':DATA,'bytes':list(data_in+b'\0')}],
               watches=[{'address':DATA,'size':len(data_in)+1},{'address':SP-32,'size':64}])
        c['flagsMask']=FLAGS&~0x10
        result=reference(c)
        expected=0xffffffff
        for b in data_in.split(b'\0')[0]: expected=(expected*33+b)&0xffffffff
        if result['expected']['registers'][0]!=expected: raise AssertionError('Hash hypothesis disproved')
        cases.append(result)
    return cases


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-only',action='store_true')
    args=parser.parse_args()
    (ROOT/'build').mkdir(exist_ok=True)
    (ROOT/'generated').mkdir(exist_ok=True)
    # Make .js unambiguously ES modules for both pinned Node and browsers.
    write_json(ROOT/'build/package.json',{'type':'module'})
    fixture=compile_fixture()
    report=lift(fixture,list(fixture.exports.values()),ROOT/'generated/synthetic.cpp')
    wasm(ROOT/'generated/synthetic.cpp','synthetic')
    cases=synthetic_cases(fixture)
    write_json(ROOT/'build/synthetic-cases.json',{'schema':1,'input_sha256':fixture.sha256,'cases':cases})
    # Fail-closed cases are tested by Node separately from successful references.
    faults=[]
    for name,code in [('unmapped',1),('unsupported',2),('code_write',4),('indirect_missing',3),('sse_movsd_unsupported',2),('popfd_control_unsupported',2)]:
        c=case(fixture,name,[STOP+128]);c['expectedFault']=code
        if name=='code_write':
            for region in c['regions']:
                if region['permissions'] & 4: region['permissions'] |= 2
        faults.append(c)
    c=case(fixture,'partial_simd_store',[DATA+4096-8],writes=[{'address':DATA+4096-8,'bytes':[0xa5]*8}])
    for region in c['regions']:
        if region['address']==DATA: region['size']=4096
    c['expectedFault']=1
    c['unchangedOnFault']=[{'address':DATA+4096-8,'bytes':[0xa5]*8}]
    faults.append(c)
    write_json(ROOT/'build/fault-cases.json',{'schema':1,'cases':faults})
    suites=[{'id':'synthetic','module':'synthetic.js','cases':'synthetic-cases.json','faultCases':'fault-cases.json','input_sha256':fixture.sha256}]
    reports={'synthetic':report}
    if not args.synthetic_only:
        game=PEImage(load_game_root()/'speed.exe')
        cases=real_cases(game)
        reports['real']=lift(game,[ROUTINE],ROOT/'generated/real.cpp')
        wasm(ROOT/'generated/real.cpp','real')
        write_json(ROOT/'build/real-cases.json',{'schema':1,'input_sha256':game.sha256,'routine':ROUTINE,'cases':cases})
        suites.append({'id':'real-routine','module':'real.js','cases':'real-cases.json','input_sha256':game.sha256})
    manifest={'schema':1,'kind':'differential-tests','built_at_utc':datetime.now(timezone.utc).isoformat(),
              'toolchain':SDK_VERSION,'reference':'Unicorn 2.1.4 isolated x86 CPU; no native game execution',
              'suites':suites,
              'artifact_sha256':{s['module'].replace('.js','.wasm'):hashlib.sha256((ROOT/'build'/s['module'].replace('.js','.wasm')).read_bytes()).hexdigest() for s in suites}}
    write_json(ROOT/'build/manifest.json',manifest)
    write_json(ROOT/'artifacts/translation-build.json',{'manifest':manifest,'reports':reports})
    print(json.dumps({'suites':suites,'status':'built; run tests/run_wasm.mjs and browser tests'},indent=2))


if __name__=='__main__': main()
