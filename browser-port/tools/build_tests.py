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
import capstone as cs

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_INTR
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
           'sse_movsd_unsupported','popfd_reserved','popfd_control_unsupported',
           'x87_control','x87_clear','x87_init','x87_wait','x87_rounded_store','cpuid_detect','cpu_features',
           'idiv32_ecx','idiv32_eax','idiv32_edx','idiv32_mem','idiv32_pointer',
           'div32_ecx','div32_eax','div32_edx','div32_mem','div32_pointer',
           'idiv16_unsupported','div8_unsupported',
           'shld32_cl','shld32_imm','shld32_mem','shld32_alias',
           'shrd32_cl','shrd32_imm','shrd32_mem','shrd32_alias','shld16_unsupported',
           'x87_abs','x87_abs_compare','x87_compare64','x87_compare_empty','x87_abs_empty']
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
            'registers':registers,'eflags':flags,'fpuControl':0x037f,'fpuStatus':0,
            'xmm':[[0x3f800000+j+i for j in range(4)] for i in range(8)],
            'watches':watches or [{'address':DATA,'size':512},{'address':SP-256,'size':512}],
            'flagsMask':FLAGS,'maxSteps':100000}


def configure_reference_cpu(u):
    """Pinned CPU identity plus explicit OS-enabled x87/SSE reference state."""
    u.ctl_set_cpu_model(x86.UC_CPU_X86_PENTIUM3)
    # Selecting a model clears Unicorn's default CR4 SSE setup. A PE process
    # starts after its OS enabled SSE; otherwise valid MOVUPS fixtures #UD.
    # NE is required for native #MF delivery in protected mode; without it,
    # Unicorn's legacy IRQ path can silently run past an unmasked FWAIT.
    u.reg_write(x86.UC_X86_REG_CR0,(u.reg_read(x86.UC_X86_REG_CR0)|0x22)&~0xc)
    u.reg_write(x86.UC_X86_REG_CR4,u.reg_read(x86.UC_X86_REG_CR4)|0x600)
    u.reg_write(x86.UC_X86_REG_FPCW,0x037f)
    u.reg_write(x86.UC_X86_REG_FPSW,0)


def reference_cpu(c):
    """Isolated CPU emulator: mapped test bytes only; no Windows/syscalls/network."""
    u=Uc(UC_ARCH_X86,UC_MODE_32)
    configure_reference_cpu(u)
    for reg in c['regions']:
        u.mem_map(reg['address'],reg['size'],reg['permissions'])
    for w in c['writes']:
        u.mem_write(w['address'],bytes(w['bytes']))
    for reg,value in zip(REG_IDS,c['registers']): u.reg_write(reg,value)
    for reg,lanes in zip(XMM_IDS,c['xmm']): u.reg_write(reg,sum(v<<(32*i) for i,v in enumerate(lanes)))
    u.reg_write(x86.UC_X86_REG_EFLAGS,c['eflags'])
    u.reg_write(x86.UC_X86_REG_FPCW,c.get('fpuControl',0x037f))
    u.reg_write(x86.UC_X86_REG_FPSW,c.get('fpuStatus',0))
    return u


def reference(c):
    u=reference_cpu(c)
    count=0
    def tick(_u,address,size,user):
        nonlocal count
        count+=1
    u.hook_add(UC_HOOK_CODE,tick)
    if 'testCheckpoint' in c:
        checkpoint=c['testCheckpoint']
        u.emu_start(c['entry'],checkpoint['eip'],timeout=2_000_000,count=100)
        if u.reg_read(x86.UC_X86_REG_EIP)!=checkpoint['eip']:
            raise AssertionError('Authored fixture did not reach its controlled-state checkpoint')
        u.reg_write(x86.UC_X86_REG_FPSW,checkpoint['fpuStatus'])
    start=c.get('testCheckpoint',{}).get('eip',c['entry'])
    u.emu_start(start,c['stop'],timeout=2_000_000,count=c['maxSteps'])
    if u.reg_read(x86.UC_X86_REG_EIP)!=c['stop']:
        raise RuntimeError(f"Reference did not return: {c['id']}")
    c['expected']={'registers':[u.reg_read(r) for r in REG_IDS],
                   'eflags':u.reg_read(x86.UC_X86_REG_EFLAGS),'flagsMask':c.pop('flagsMask'),
                   'xmm':[[int(u.reg_read(r)>>(32*i))&0xffffffff for i in range(4)] for r in XMM_IDS],
                   'fpuControl':u.reg_read(x86.UC_X86_REG_FPCW),
                   'fpuStatus':u.reg_read(x86.UC_X86_REG_FPSW),
                   'memory':[{'address':w['address'],'bytes':list(u.mem_read(w['address'],w['size']))} for w in c.pop('watches')],
                   'referenceSteps':count}
    return c


def division_case(image,name,dividend,divisor):
    c=case(image,name,[divisor],flags=0x200ed7)
    c['registers'][0]=dividend&0xffffffff
    c['registers'][1]=divisor&0xffffffff
    c['registers'][2]=(dividend>>32)&0xffffffff
    # Only the six arithmetic bits are undefined. Compare control bits too.
    c['flagsMask']=0xffffffff^FLAGS
    return c


def division_cases(image):
    rng=random.Random(0x464f34)
    signed=[(0,1),(12,16),(7,3),(-7,3),(7,-3),(-7,-3),(-1,2),
            (0x7fffffff,1),(-0x80000000,1),(0x80000000,-1),
            (0x100000000,3),(-0x100000000,3),(0x7fffffff*0x7fffffff,0x7fffffff),
            ((1<<62)+0x7fffffff,-0x80000000)]
    unsigned=[(0,1),(12,16),(7,3),(0xffffffff,1),(0x100000000,2),
              (0xffffffff*0xffffffff+0xfffffffe,0xffffffff)]
    for pairs,is_signed in ((signed,True),(unsigned,False)):
        for _ in range(32):
            divisor=rng.randrange(-0x80000000,0x80000000) if is_signed else rng.randrange(1,0x100000000)
            if not divisor: divisor=1
            quotient=rng.randrange(-0x80000000,0x80000000) if is_signed else rng.getrandbits(32)
            dividend=quotient*divisor
            remainder=rng.randrange(abs(divisor))
            dividend+=-remainder if dividend<0 else remainder
            pairs.append((dividend,divisor))
    cases=[]
    for prefix,pairs in (('idiv32',signed),('div32',unsigned)):
        for suffix in ('ecx','mem'):
            for i,(dividend,divisor) in enumerate(pairs):
                cases.append(reference(division_case(image,f'{prefix}_{suffix}/{i}',dividend,divisor)))
        # Read aliased register/address operands before writing EAX or EDX.
        aliases=(7,0xfffffffe,0x80000001) if prefix=='idiv32' else (7,0xfffffffe,0x180000001)
        for i,dividend in enumerate(aliases):
            cases.append(reference(division_case(image,f'{prefix}_eax/{i}',dividend,123)))
        c=division_case(image,f'{prefix}_pointer',DATA,3)
        c['writes'].append({'address':DATA,'bytes':dwords(3)})
        cases.append(reference(c))
    # IDIV EDX can succeed with a negative high half; DIV EDX always overflows
    # for nonzero EDX and is checked with the faults below.
    cases.append(reference(division_case(image,'idiv32_edx',-7,123)))
    return cases


def division_faults(image):
    faults=[]
    for prefix,pairs in (
        ('idiv32',[(7,0),(0x80000000,1),(-0x80000001,1),(-0x80000000,-1),(0x7fffffffffffffff,1)]),
        ('div32',[(7,0),(0x100000000,1),(0xffffffffffffffff,0xffffffff)])):
        for suffix in ('ecx','mem'):
            for i,(dividend,divisor) in enumerate(pairs):
                c=division_case(image,f'{prefix}_{suffix}/exception-{i}',dividend,divisor)
                u=reference_cpu(c);interrupts=[]
                def interrupt(cpu,number,_):
                    interrupts.append(number);cpu.emu_stop()
                u.hook_add(UC_HOOK_INTR,interrupt)
                u.emu_start(c['entry'],c['stop'],timeout=2_000_000,count=10)
                if interrupts!=[0] or u.reg_read(x86.UC_X86_REG_EIP)!=c['entry']:
                    raise AssertionError(f"Expected #DE at original instruction: {c['id']}")
                c['expectedFault']=2;c['expectedEipOnFault']=c['entry']
                c['expectedFlagsOnFault']=u.reg_read(x86.UC_X86_REG_EFLAGS)
                c['expectedRegistersOnFault']=[u.reg_read(r) for r in REG_IDS]
                c['unchangedOnFault']=[{'address':w['address'],'bytes':list(u.mem_read(w['address'],w['size']))} for w in c.pop('watches')]
                c['referenceException']={'vector':0,'engine':'Unicorn 2.1.4'}
                faults.append(c)
    # Pinned Unicorn's native signed division crashes its process on this pair.
    # Intel specifies #DE. Never send it to the in-process development oracle.
    c=division_case(image,'idiv32_ecx/int64-min-minus-one',-(1<<63),-1)
    c['expectedFault']=2;c['expectedEipOnFault']=c['entry']
    c['expectedRegistersOnFault']=c['registers'].copy();c['expectedFlagsOnFault']=c['eflags']
    c['referenceException']={'vector':0,'engine':'Intel specification; Unicorn host overflow excluded'}
    faults.append(c)
    for name in ('idiv32_pointer','div32_pointer'):
        c=division_case(image,name+'/unreadable',0x03fff000,0)
        c['expectedFault']=1;c['expectedEipOnFault']=c['entry']
        c['expectedRegistersOnFault']=c['registers'].copy();faults.append(c)
    c=division_case(image,'div32_edx/overflow',0x100000007,0)
    c['expectedFault']=2;c['expectedEipOnFault']=c['entry']
    c['expectedRegistersOnFault']=c['registers'].copy();faults.append(c)
    return faults


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
    for flag in (0x202,0x200202):
        c=case(image,f'cpuid_detect/{flag:x}',flags=flag);c['flagsMask']=FLAGS|0x200000
        cases.append(reference(c))
    for leaf in (0,1):
        for subleaf in (0,0x202,0x6c65746e,0xffffffff):
            cases.append(reference(case(image,f'cpu_features/{leaf}/{subleaf:x}',[leaf,subleaf])))
    # Finite, exactly representable SIMD operands avoid making a claim about
    # NaN payloads, MXCSR exceptions, or x87 extended arithmetic.
    values=[1.5,-2.0,3.25,0.125,2.0,4.0,-0.5,8.0,7.75]
    c=case(image,'simd',[DATA,DATA+128],writes=[{'address':DATA,'bytes':list(struct.pack('<9f',*values))}])
    cases.append(reference(c))
    for i,v in enumerate([0.0,-0.0,1.5,-123.75,2**-100]):
        c=case(image,f'x87_load_store/{i}',[DATA,DATA+128],writes=[{'address':DATA,'bytes':list(struct.pack('<f',v))}])
        cases.append(reference(c))
    for control in (0x037f,0x023f,0x027f,0x007f,0x003f,0x073f,0x0b3f,0x0f3f,0x037e):
        c=case(image,f'x87_control/{control:x}',[DATA,DATA+128],
               writes=[{'address':DATA,'bytes':list(struct.pack('<H',control))}])
        cases.append(reference(c))
    for status in (0x80ff,0xf5ff,0x017f):
        c=case(image,f'x87_clear/{status:x}',[DATA]);c['fpuStatus']=status
        cases.append(reference(c))
    c=case(image,'x87_init',[DATA]);c['fpuStatus']=0x80ff;c['fpuControl']=0x037e
    cases.append(reference(c))
    for control in (0x023f,0x073f,0x0b3f,0x0f3f):
        c=case(image,f'x87_load_store/control-{control:x}',[DATA,DATA+128],
               writes=[{'address':DATA,'bytes':list(struct.pack('<f',1.5))}])
        c['fpuControl']=control;cases.append(reference(c))
    for name in ('shld32','shrd32'):
        for i,(dest,count) in enumerate((a,n) for a in boundary for n in (0,1,9,31,32,33,255,256,257)):
            for form in ('cl','mem','alias'):
                c=case(image,f'{name}_{form}/{i}',flags=0x200ed7 if i%2 else 0x202)
                c['registers'][0]=dest;c['registers'][2]=boundary[-1-i%len(boundary)]
                c['registers'][1]=count;c['registers'][6]=DATA
                c['writes'].append({'address':DATA,'bytes':dwords(dest)})
                shift=count&31
                c['flagsMask']=0xffffffff if shift==0 else 0xffffffff&~(0x10|(0x800 if shift!=1 else 0))
                cases.append(reference(c))
        for i,dest in enumerate(boundary):
            c=case(image,f'{name}_imm/{i}');c['registers'][0]=dest;c['registers'][2]=~dest&0xffffffff
            c['flagsMask']=0xffffffff&~(0x10|0x800);cases.append(reference(c))
    float_pairs=[(-0.0,0.0),(0.0,-0.0),(1.0,2.0),(-1.0,2.0),(-3.0,2.0),
                 (3.0,3.0),(-2.0**-100,2.0**-100),(-2.0**-100,0.0),(-2.0**100,2.0**100)]
    for i,(value,other) in enumerate(float_pairs):
        for name in ('x87_abs','x87_abs_compare','x87_compare64'):
            c=case(image,f'{name}/{i}',[DATA,DATA+128],writes=[
                {'address':DATA,'bytes':list(struct.pack('<d',value))},
                {'address':DATA+128,'bytes':list(struct.pack('<d' if name=='x87_compare64' else '<f',other))}])
            c['fpuControl']=0x023f;c['fpuStatus']=0x4700
            result=reference(c)
            # Unicorn 2.1.4 incorrectly retains C1 through these instructions.
            # Keep its raw result as evidence, and independently assert Intel's
            # defined C1=0 (also visible through the fixture's FNSTSW AX).
            expected=result['expected']
            result['oracle_adjustment']={
                'reason':'Intel-defined C1=0; pinned Unicorn preserves the seeded C1 bit',
                'source':'https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf',
                'raw_fpu_status':expected['fpuStatus'],'raw_eax':expected['registers'][0],
                'corrected_mask':0x0200}
            expected['fpuStatus']&=~0x0200;expected['registers'][0]&=~0x0200
            cases.append(result)
    # Seed C1 after FLD, so that each new instruction must clear it itself.
    for name,mnemonic in (('x87_abs','fabs'),('x87_abs_compare','fcomp'),('x87_compare64','fcom')):
        c=case(image,name+'/c1-after-load',[DATA,DATA+128],writes=[
            {'address':DATA,'bytes':list(struct.pack('<d',-1.5))},
            {'address':DATA+128,'bytes':list(struct.pack('<d' if mnemonic=='fcom' else '<f',2.0))}])
        decoder=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32)
        point=next(i.address for i in decoder.disasm(image.read(c['entry'],64),c['entry']) if i.mnemonic==mnemonic)
        c['testCheckpoint']={'eip':point,'fpuStatus':0x7f00,'fpuDepth':1}
        result=reference(c);expected=result['expected']
        result['oracle_adjustment']={'reason':'Intel-defined C1=0; seeded after FLD to isolate '+mnemonic,
            'source':'https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf',
            'raw_fpu_status':expected['fpuStatus'],'raw_eax':expected['registers'][0],'corrected_mask':0x0200}
        expected['fpuStatus']&=~0x0200;expected['registers'][0]&=~0x0200
        cases.append(result)
    return cases+division_cases(image)


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
    for name,code in [('unmapped',1),('unsupported',2),('code_write',4),('indirect_missing',3),('sse_movsd_unsupported',2),('popfd_control_unsupported',2),('idiv16_unsupported',2),('div8_unsupported',2),('shld16_unsupported',2)]:
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
    c=case(fixture,'x87_wait');c['fpuControl']=0x037e;c['fpuStatus']=0x81;c['expectedFault']=2
    c['expectedFpuOnFault']={'control':0x037e,'status':0x81,'depth':0};faults.append(c)
    c=case(fixture,'x87_rounded_store',[DATA,DATA+128],writes=[
        {'address':DATA,'bytes':list(struct.pack('<d',1/3))},{'address':DATA+128,'bytes':[0xa5]*4}])
    c['fpuControl']=0x0b3f;c['expectedFault']=2
    c['expectedFpuOnFault']={'control':0x0b3f,'status':0x3800,'depth':1}
    c['unchangedOnFault']=[{'address':DATA+128,'bytes':[0xa5]*4}];faults.append(c)
    c=case(fixture,'x87_load_store/denormal',[DATA,DATA+128],writes=[{'address':DATA,'bytes':[1,0,0,0]}])
    c['expectedFault']=2;c['expectedFpuOnFault']={'control':0x037f,'status':0,'depth':0};faults.append(c)
    c=case(fixture,'cpu_features/unknown',[2,0]);c['expectedFault']=2
    c['expectedRegistersOnFault']=[2,0,*c['registers'][2:]];faults.append(c)
    faults.extend(division_faults(fixture))
    c=case(fixture,'x87_compare_empty');c['registers'][6]=DATA;c['expectedFault']=2
    c['expectedEipOnFault']=c['entry'];c['expectedRegistersOnFault']=c['registers'].copy()
    c['expectedFpuOnFault']={'control':0x037f,'status':0,'depth':0};faults.append(c)
    c=case(fixture,'x87_abs_empty');c['expectedFault']=2
    c['expectedEipOnFault']=c['entry'];c['expectedRegistersOnFault']=c['registers'].copy()
    c['expectedFaultText']='x87 stack underflow';faults.append(c)
    for name in ('x87_abs_empty','x87_compare_empty'):
        c=case(fixture,name+'/pending-exception');c['registers'][6]=DATA
        c['fpuControl']=0x037e;c['fpuStatus']=0x81;c['expectedFault']=2
        c['expectedEipOnFault']=c['entry'];c['expectedRegistersOnFault']=c['registers'].copy()
        c['expectedFpuOnFault']={'control':0x037e,'status':0x81,'depth':0}
        c['expectedFaultText']='pending unmasked x87 exception'
        c['referenceException']={'engine':'Intel specification; Unicorn only raises pending #MF on explicit WAIT'}
        faults.append(c)
    for name in ('shld32_mem','shrd32_mem'):
        for count in (0,32):
            for mode in ('unmapped','readonly'):
                c=case(fixture,f'{name}/{mode}-{count}',flags=0x200ed7,
                       writes=[{'address':DATA,'bytes':[0xa5]*4}])
                c['registers'][1]=count;c['registers'][6]=DATA if mode=='readonly' else 0x03fff000
                if mode=='readonly':
                    for region in c['regions']:
                        if region['address']==DATA:region['permissions']=1
                c['expectedFault']=1;c['expectedEipOnFault']=c['entry']
                c['expectedFlagsOnFault']=c['eflags'];c['expectedRegistersOnFault']=c['registers'].copy()
                c['unchangedOnFault']=[{'address':DATA,'bytes':[0xa5]*4}];faults.append(c)
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
              'toolchain':SDK_VERSION,'reference':'Unicorn 2.1.4 UC_CPU_X86_PENTIUM3 isolated x86 CPU; no native game execution',
              'suites':suites,
              'artifact_sha256':{s['module'].replace('.js','.wasm'):hashlib.sha256((ROOT/'build'/s['module'].replace('.js','.wasm')).read_bytes()).hexdigest() for s in suites}}
    write_json(ROOT/'build/manifest.json',manifest)
    write_json(ROOT/'artifacts/translation-build.json',{'manifest':manifest,'reports':reports})
    print(json.dumps({'suites':suites,'status':'built; run tests/run_wasm.mjs and browser tests'},indent=2))


if __name__=='__main__': main()
