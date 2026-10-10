"""Differential oracle for the original entry -> first Win32 call boundary."""
import json
import struct
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn import x86_const as x86
from tools.toolchain import ROOT
from tools.build_tests import REG_IDS, XMM_IDS, write_json


def main():
    manifest=json.loads((ROOT/'build/startup.json').read_text())
    c=manifest['case']
    stop=next(i['gateway'] for i in manifest['imports'] if i['name']=='KERNEL32.dll!GetVersionExA')
    u=Uc(UC_ARCH_X86,UC_MODE_32)
    for region in c['regions']: u.mem_map(region['address'],region['size'],region['permissions'])
    u.mem_write(manifest['image']['address'],(ROOT/'build'/manifest['image']['url']).read_bytes())
    for w in c['writes']: u.mem_write(w['address'],bytes(w['bytes']))
    for reg,val in zip(REG_IDS,c['registers']): u.reg_write(reg,val)
    for reg in XMM_IDS: u.reg_write(reg,0)
    u.reg_write(x86.UC_X86_REG_EFLAGS,c['eflags'])
    # Real protected-mode FS descriptor in the isolated CPU reference. This does
    # not assume FS_BASE writes work in 32-bit Unicorn (they do not).
    gdt=0x02400000
    u.mem_map(gdt,4096,3)
    base=c['fsBase'];limit=4095
    descriptor=struct.pack('<HHBBBB',limit&65535,base&65535,(base>>16)&255,0x93,0x40|((limit>>16)&15),(base>>24)&255)
    u.mem_write(gdt+8,descriptor)
    # Installing a GDT invalidates Unicorn's implicit flat segment assumptions.
    # Explicit D/B=1 data/code descriptors keep stack addressing 32-bit.
    u.mem_write(gdt+16,struct.pack('<HHBBBB',65535,0,0,0x93,0xcf,0))
    u.mem_write(gdt+24,struct.pack('<HHBBBB',65535,0,0,0x9b,0xcf,0))
    u.reg_write(x86.UC_X86_REG_GDTR,(0,gdt,4095,0))
    u.reg_write(x86.UC_X86_REG_SS,16)
    u.reg_write(x86.UC_X86_REG_DS,16)
    u.reg_write(x86.UC_X86_REG_ES,16)
    u.reg_write(x86.UC_X86_REG_CS,24)
    u.reg_write(x86.UC_X86_REG_FS,8)
    trace=[]
    u.hook_add(UC_HOOK_CODE,lambda _u,a,s,_d:trace.append(a))
    def invalid(_u,kind,address,size,value,_data):
        print(json.dumps({'reference_fault':{'kind':kind,'address':hex(address),'size':size,
              'eip':hex(_u.reg_read(x86.UC_X86_REG_EIP)),'esp':hex(_u.reg_read(x86.UC_X86_REG_ESP)),
              'trace_tail':[hex(a) for a in trace[-8:]]}}))
        return False
    u.hook_add(UC_HOOK_MEM_INVALID,invalid)
    u.emu_start(c['entry'],stop,timeout=2_000_000,count=10000)
    if u.reg_read(x86.UC_X86_REG_EIP)!=stop:raise RuntimeError('Reference did not reach first import')
    watches=[(c['registers'][4]-4096,8192),(c['fsBase'],4096)]
    expected={'registers':[u.reg_read(reg) for reg in REG_IDS],
              'eflags':u.reg_read(x86.UC_X86_REG_EFLAGS),'flagsMask':0x8c5,
              'xmm':[[0]*4 for _ in range(8)],
              'memory':[{'address':a,'bytes':list(u.mem_read(a,s))} for a,s in watches]}
    result={'schema':1,'scope':'Original entry prefix before first platform call; no Win32 effects simulated',
            'stop':stop,'expected':expected,'trace':trace,'input_sha256':manifest['provenance']['executable_sha256']}
    write_json(ROOT/'build/startup-reference.json',result)
    write_json(ROOT/'artifacts/startup-reference.json',result)
    test={**c,'id':'entry-to-first-import','stop':stop,'expected':expected}
    write_json(ROOT/'build/startup-prefix-cases.json',{'schema':1,'cases':[test]})
    suites_path=ROOT/'build/manifest.json'
    suites=json.loads(suites_path.read_text()) if suites_path.exists() else {'schema':1,'kind':'differential-tests','suites':[],'artifact_sha256':{}}
    suites['suites']=[s for s in suites['suites'] if s['id']!='startup-prefix']
    suites['suites'].append({'id':'startup-prefix','module':'startup.js','cases':'startup-prefix-cases.json',
                            'image':manifest['image'],'input_sha256':result['input_sha256']})
    suites['artifact_sha256'].update(manifest['artifact_sha256'])
    write_json(suites_path,suites)
    print(json.dumps({'reference_instructions':len(trace),'stop':hex(stop),'scope':result['scope']}))


if __name__=='__main__': main()
