"""Decode a bounded reachable x86 CFG and emit checked C++ semantics.

Input is always a PE binary. This is a deliberately incomplete AOT translator,
not decompiled-source compilation and not a runtime instruction decoder.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path

import capstone as cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

REGS = {name: (i, 32, 0) for i, name in enumerate("eax ecx edx ebx esp ebp esi edi".split())}
REGS.update({name: (i, 16, 0) for i, name in enumerate("ax cx dx bx sp bp si di".split())})
REGS.update({name: (i, 8, 0) for i, name in enumerate("al cl dl bl".split())})
REGS.update({name: (i, 8, 8) for i, name in enumerate("ah ch dh bh".split())})
CONDS = {name: i for i, name in enumerate("o no b ae e ne be a s ns p np l ge le g".split())}


class Unsupported(ValueError):
    pass


class PEImage:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.pe = pefile.PE(data=self.data)
        if self.pe.FILE_HEADER.Machine != 0x14C or self.pe.OPTIONAL_HEADER.Magic != 0x10B:
            raise ValueError("Translator accepts only verified i386 PE32 images")
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry = self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.exports = {}
        for symbol in getattr(getattr(self.pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
            if symbol.name and not symbol.forwarder:
                self.exports[symbol.name.decode("ascii")] = self.base + symbol.address

    def executable(self, address):
        rva = address - self.base
        return any(s.VirtualAddress <= rva < s.VirtualAddress + min(s.Misc_VirtualSize, s.SizeOfRawData)
                   and s.Characteristics & 0x20000000 for s in self.pe.sections)

    def read(self, address, count):
        rva=address-self.base
        for section in self.pe.sections:
            end=section.VirtualAddress+min(section.Misc_VirtualSize,section.SizeOfRawData)
            if section.Characteristics & 0x20000000 and section.VirtualAddress<=rva<end:
                # Adjacent executable virtual sections need not be adjacent on
                # disk. Never decode an instruction using the next raw bytes.
                offset=section.PointerToRawData+rva-section.VirtualAddress
                return self.data[offset:offset+min(count,end-rva)]
        raise ValueError(f"Address {address:#x} has no file-backed executable section")

    def regions(self):
        result = [{"address": self.base, "size": ((self.pe.OPTIONAL_HEADER.SizeOfHeaders + 4095)//4096)*4096, "permissions": 1}]
        for section in self.pe.sections:
            size = (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095)//4096*4096
            if size:
                chars = section.Characteristics
                result.append({"address": self.base + section.VirtualAddress, "size": size,
                               "permissions": int(bool(chars & 0x40000000)) | (2 if chars & 0x80000000 else 0) | (4 if chars & 0x20000000 else 0)})
        return result


class Emitter:
    def __init__(self, insn):
        self.insn = insn
        self.ops = insn.operands

    def reg(self, op):
        name = self.insn.reg_name(op.reg)
        if name not in REGS:
            raise Unsupported(f"register {name}")
        return REGS[name]

    def address(self, op, segment=True):
        m = op.mem
        terms = [f"0x{m.disp & 0xffffffff:x}u"]
        for reg, scale in [(m.base, 1), (m.index, m.scale)]:
            if reg:
                name = self.insn.reg_name(reg)
                if name not in REGS or REGS[name][1] != 32:
                    raise Unsupported(f"address register {name}")
                terms.append(f"r[{REGS[name][0]}]*{scale}u")
        if segment and m.segment:
            seg = self.insn.reg_name(m.segment)
            if seg == "fs":
                terms.append("fsbase")
            elif seg not in ("ds", "es", "ss"):
                raise Unsupported(f"segment {seg}")
        return "(" + "+".join(terms) + ")"

    def read(self, op):
        if op.type == X86_OP_IMM:
            return f"0x{op.imm & 0xffffffff:x}u"
        if op.type == X86_OP_REG:
            i, bits, shift = self.reg(op)
            return f"read_reg({i},{bits},{shift})"
        if op.type == X86_OP_MEM and op.size in (1, 2, 4):
            return f"rd({self.address(op)},{op.size * 8})"
        raise Unsupported("operand read")

    def write(self, op, value):
        if op.type == X86_OP_REG:
            i, bits, shift = self.reg(op)
            return f"write_reg({i},{bits},{shift},{value});"
        if op.type == X86_OP_MEM and op.size in (1, 2, 4):
            return f"wr({self.address(op)},{value},{op.size * 8});"
        raise Unsupported("operand write")

    def lane(self, op, lane):
        if op.type == X86_OP_REG:
            name = self.insn.reg_name(op.reg)
            if name.startswith("xmm") and int(name[3:]) < 8:
                return f"xmm[{int(name[3:])}][{lane}]"
        if op.type == X86_OP_MEM:
            return f"rd({self.address(op)}+{lane * 4}u,32)"
        raise Unsupported("SIMD operand")

    def write_lane(self, op, lane, value):
        if op.type == X86_OP_REG:
            return f"{self.lane(op, lane)}={value};"
        if op.type == X86_OP_MEM:
            return f"wr({self.address(op)}+{lane * 4}u,{value},32);"
        raise Unsupported("SIMD operand write")

    def emit(self):
        m, o = self.insn.mnemonic, self.ops
        nxt = self.insn.address + self.insn.size
        if self.insn.addr_size != 4:
            raise Unsupported('16-bit address-size override')
        if 0x66 in self.insn.prefix and (self.insn.group(cs.CS_GRP_JUMP) or m in ('call','ret','leave','jmp','pushfd','popfd','loop','jecxz')):
            raise Unsupported('16-bit control/stack operand-size override')
        if m == "nop":
            return ""
        if m == "cpuid":
            return "cpuid();"
        if m == "mov":
            return self.write(o[0], self.read(o[1]))
        if m in ("movzx", "movsx"):
            expr = self.read(o[1])
            if m == "movsx": expr = f"uint32_t(sign({expr},{o[1].size * 8}))"
            return self.write(o[0], expr)
        if m == "lea":
            return self.write(o[0], self.address(o[1], segment=False))
        if m == "xchg":
            code=''
            for i,op in enumerate(o):
                if op.type==X86_OP_MEM: code+=f'uint32_t p{i}={self.address(op)};'
            code+=f"uint32_t a={self.read(o[0])},b={self.read(o[1])};"
            for i,value in enumerate(('b','a')):
                code+=f'wr(p{i},{value},{o[i].size*8});' if o[i].type==X86_OP_MEM else self.write(o[i],value)
            return code
        if m == "push":
            if o[0].size != 4: raise Unsupported("16-bit stack operation")
            return f"push({self.read(o[0])});"
        if m == "pop":
            if o[0].size != 4: raise Unsupported("16-bit stack operation")
            return "uint32_t v=pop();" + self.write(o[0], "v")
        if m in ("pushfd", "popfd"):
            return "push(flags&~0x30000u);" if m == "pushfd" else "pop_flags();"
        if m == "leave":
            return "r[4]=r[5];r[5]=pop();"
        if m == "call":
            return f"uint32_t target={self.read(o[0])};push(0x{nxt:x}u);next=target;"
        if m == "jmp":
            return f"next={self.read(o[0])};"
        if m == "ret":
            return "next=pop();" + (f"r[4]+={o[0].imm}u;" if o else "")
        if m.startswith("j") and m[1:] in CONDS:
            return f"if(condition({CONDS[m[1:]]})) next={self.read(o[0])};"
        if m == "jecxz":
            return f"if(r[1]==0) next={self.read(o[0])};"
        if m == "loop":
            return f"if(--r[1]) next={self.read(o[0])};"
        if m.startswith("set") and m[3:] in CONDS:
            return self.write(o[0], f"uint32_t(condition({CONDS[m[3:]]}))")
        if m.startswith("cmov") and m[4:] in CONDS:
            # Source memory is read even when condition is false.
            return f"uint32_t v={self.read(o[1])};if(condition({CONDS[m[4:]]})){{{self.write(o[0], 'v')}}}"
        if m in ("add", "adc", "sub", "sbb", "cmp", "and", "or", "xor", "test"):
            a, b, bits = self.read(o[0]), self.read(o[1]), o[0].size * 8
            if m in ("add", "adc", "sub", "sbb", "cmp"):
                func = "add" if m in ("add", "adc") else "sub"
                expr = f"{func}({a},{b},{bits},{'flags&CF' if m in ('adc','sbb') else '0'})"
            else:
                operator = {"and": "&", "test": "&", "or": "|", "xor": "^"}[m]
                expr = f"logic({a}{operator}{b},{bits})"
            return f"(void){expr};" if m in ("cmp", "test") else self.write(o[0], expr)
        if m in ("inc", "dec"):
            func = "add" if m == "inc" else "sub"
            return "uint32_t carry=flags&CF;" + self.write(o[0], f"{func}({self.read(o[0])},1,{o[0].size * 8})") + "flags=(flags&~CF)|carry;"
        if m in ("neg", "not"):
            expr = f"sub(0,{self.read(o[0])},{o[0].size * 8})" if m == "neg" else f"~{self.read(o[0])}"
            return self.write(o[0], expr)
        if m in ("shl", "sal", "shr", "sar"):
            kind = {"shl": 0, "sal": 0, "shr": 1, "sar": 2}[m]
            return self.write(o[0], f"shift({self.read(o[0])},{self.read(o[1])},{o[0].size * 8},{kind})")
        if m == "imul" and len(o) >= 2:
            a, b = (o[0], o[1]) if len(o) == 2 else (o[1], o[2])
            return self.write(o[0], f"multiply({self.read(a)},{self.read(b)},{o[0].size * 8})")
        if m in ("mul", "imul") and len(o) == 1 and o[0].size == 4:
            expr = f"uint64_t(r[0])*{self.read(o[0])}" if m == "mul" else f"uint64_t(sign(r[0],32)*sign({self.read(o[0])},32))"
            condition = "r[2]!=0" if m == "mul" else "r[2]!=(r[0]&0x80000000u?0xffffffffu:0u)"
            return f"uint64_t v={expr};r[0]=uint32_t(v);r[2]=uint32_t(v>>32);flags=(flags&~(CF|OF))|({condition}?CF|OF:0);"
        if m == "cdq":
            return "r[2]=(r[0]&0x80000000u)?0xffffffffu:0u;"
        if m in ("shld", "shrd") and len(o)==3 and o[0].size==4 and o[1].size==4:
            return self.write(o[0], f"double_shift32({self.read(o[0])},{self.read(o[1])},{self.read(o[2])},{'true' if m=='shrd' else 'false'})")
        if m in ("div", "idiv") and len(o) == 1 and o[0].size == 4:
            return f"divide32({self.read(o[0])},{'true' if m=='idiv' else 'false'});"
        if m == "cwde":
            return "r[0]=uint32_t(sign(r[0],16));"
        if m in ("cld", "std", "clc", "stc", "cmc"):
            return {"cld":"flags&=~DF;", "std":"flags|=DF;", "clc":"flags&=~CF;", "stc":"flags|=CF;", "cmc":"flags^=CF;"}[m]
        if m == "bswap":
            return self.write(o[0], f"__builtin_bswap32({self.read(o[0])})")
        if m in ("movss", "movups", "movaps", "movdqu", "movdqa"):
            if m in ("movaps", "movdqa"):
                for op in o:
                    if op.type == X86_OP_MEM:
                        align = f"if({self.address(op)}&15u){{fault(1,ip,\"unaligned SIMD operand\");break;}}"
                        break
                else: align = ""
            else: align = ""
            count = 1 if m == "movss" else 4
            code = align + "".join(f"uint32_t v{i}={self.lane(o[1],i)};" for i in range(count))
            code += "".join(self.write_lane(o[0],i,f"v{i}") for i in range(count))
            if m == "movss" and o[1].type == X86_OP_MEM and o[0].type == X86_OP_REG:
                code += "".join(self.write_lane(o[0],i,"0") for i in range(1,4))
            return code
        if m in ("addss", "subss", "mulss", "divss", "addps", "subps", "mulps", "xorps", "pxor"):
            count = 1 if m.endswith("ss") else 4
            op = {"add":"+", "sub":"-", "mul":"*", "div":"/", "xor":"^", "pxo":"^"}[m[:3]]
            code = ""
            for i in range(count):
                a,b = self.lane(o[0],i),self.lane(o[1],i)
                expr = f"{a}^{b}" if op == "^" else f"as_bits(as_float({a}){op}as_float({b}))"
                code += f"uint32_t v{i}={expr};"
            return code + "".join(self.write_lane(o[0],i,f"v{i}") for i in range(count))
        if m == "cvttss2si" and o[0].size == 4:
            return f"double v=as_float({self.lane(o[1],0)});uint32_t out=(!std::isfinite(v)||v>=2147483648.0||v< -2147483648.0)?0x80000000u:uint32_t(int32_t(v));" + self.write(o[0],"out")
        if m == "cvtsi2ss" and o[1].size == 4:
            return self.write_lane(o[0],0,f"as_bits(float(sign({self.read(o[1])},32)))")
        if m in ("wait", "fwait"):
            return "fwait();"
        if m == "fabs":
            return "fabsolute();"
        if m in ("fcom", "fcomp") and len(o)==1 and o[0].type==X86_OP_MEM and o[0].size in (4,8):
            return f"fcompare(fload({self.address(o[0])},{o[0].size*8}),{'true' if m=='fcomp' else 'false'});"
        if m == "fninit":
            return "finit();"
        if m == "fnclex":
            return "fpu_status&=~0x80ffu;"
        if m == "fnstcw" and o[0].type == X86_OP_MEM and o[0].size == 2:
            return self.write(o[0], "fpu_control")
        if m == "fldcw" and o[0].type == X86_OP_MEM and o[0].size == 2:
            return f"fldcw({self.address(o[0])});"
        if m == "fnstsw" and o[0].size == 2:
            return self.write(o[0], "fpu_status")
        if m == "fld" and o[0].type == X86_OP_MEM and o[0].size in (4,8):
            return f"fpush(fload({self.address(o[0])},{o[0].size*8}));"
        if m in ("fld1", "fldz"):
            return f"fpush({1 if m=='fld1' else 0}.0);"
        if m in ("fst", "fstp") and o[0].type == X86_OP_MEM and o[0].size in (4,8):
            return f"fstore({self.address(o[0])},{o[0].size*8});" + ("if(!error)fpop();" if m=="fstp" else "")
        if m in ("rep stosd", "rep stosb", "rep movsd", "rep movsb", "stosd", "stosb", "movsd", "movsb"):
            # SSE2 MOVSD shares a mnemonic with string MOVSD. Its register
            # operand must never select the ESI/EDI string-copy semantics.
            kind = m.split()[-1]
            if kind.startswith('movs') and not (len(o)==2 and all(op.type==X86_OP_MEM for op in o)):
                raise Unsupported('SSE2 scalar-double MOVSD')
            if any(op.type==X86_OP_MEM and op.mem.segment and self.insn.reg_name(op.mem.segment) not in ('ds','es') for op in o):
                raise Unsupported('string operation segment override')
            repeat = m.startswith("rep ")
            size = 4 if kind.endswith("d") else 1
            value = "r[0]" if kind.startswith("stos") else f"rd(r[6],{size*8})"
            code = f"wr(r[7],{value},{size*8});uint32_t delta=(flags&DF)?uint32_t(-{size}):{size};r[7]+=delta;"
            if kind.startswith("movs"): code += "r[6]+=delta;"
            if repeat: code = f"if(r[1]){{{code}if(--r[1])next=ip;}}"
            return code
        raise Unsupported(f"instruction {m} {self.insn.op_str}")


def lift(image: PEImage, seeds, output: Path, limit=20000, imports=None):
    # The configured original installation is an immutable input boundary even
    # when this lower-level CLI is used instead of the build wrappers.
    from tools.game_config import load_game_root, require_external_output
    try:
        game_root=load_game_root()
    except ValueError:
        game_root=None # synthetic-only builds do not require game configuration
    if game_root is not None:
        require_external_output(output,game_root)
    if output.resolve()==image.path.resolve():
        raise ValueError('Refusing to overwrite the binary input')
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    decoder.detail = True
    queue = deque(seeds)
    instructions, emitted, unsupported, indirect, missing = {}, {}, [], [], []
    owners = {}
    while queue:
        address = queue.popleft()
        if address in instructions: continue
        if not image.executable(address):
            missing.append(address); continue
        if len(instructions) >= limit:
            missing.extend([address, *queue]); break
        insn = next(decoder.disasm(image.read(address,15), address, count=1), None)
        if insn is None:
            missing.append(address); continue
        if not image.executable(address+insn.size-1):
            missing.append(address); continue
        if any(p in owners and owners[p] != address for p in range(address,address+insn.size)):
            raise ValueError(f"overlapping instruction boundaries at {address:#x}")
        for p in range(address,address+insn.size): owners[p] = address
        instructions[address] = insn
        try:
            emitted[address] = Emitter(insn).emit()
        except Unsupported as exc:
            message = str(exc)
            unsupported.append({"address":address,"message":message})
            emitted[address] = f"fault(2,ip,{json.dumps(message)});"
            # Preserve the barrier; do not decode unreachable fallthrough past it.
            continue
        m = insn.mnemonic
        branch = insn.group(cs.CS_GRP_JUMP) or m in ("call", "loop", "jecxz")
        if branch:
            if insn.operands[0].type == X86_OP_IMM:
                queue.append(insn.operands[0].imm & 0xffffffff)
            else:
                indirect.append({"address":address,"mnemonic":m,"operand":insn.op_str})
        if m not in ("ret", "jmp", "int3", "ud2"):
            queue.append(address+insn.size)

    # Keep each LLVM/Wasm control-flow graph small. A single 6,000-way function
    # took minutes to compile even without optimization; page dispatch retains
    # identical instruction transactions while bounding compiler graph size.
    pages={}
    for address in sorted(instructions):
        insn = instructions[address]
        pages.setdefault(address>>12,[]).append(f'case 0x{address:x}u:{{if(!access(ip,{insn.size},4))break;next=0x{address+insn.size:x}u;{emitted[address]}break;}}')
    for address, name in (imports or {}).items():
        pages.setdefault(address>>12,[]).append(f'case 0x{address:x}u:{{if(!win32::dispatch({json.dumps(name)},next))fault(5,ip,{json.dumps("unimplemented import: "+name)});break;}}')
    lines = ['// GENERATED FROM LOCAL BINARY. DO NOT COMMIT OR EDIT.',
             '#include "runtime/win32.hpp"' if imports else '#include "runtime/guest.hpp"']
    for page,cases in sorted(pages.items()):
        lines.extend([f'[[gnu::noinline]] static uint32_t page_{page:x}() {{',
                      'using namespace guest;uint32_t next=ip;switch(ip) {',*cases,
                      'default:fault(3,ip,"untranslated control-flow target");break;',
                      '}return next;}'])
    lines.extend(['extern "C" EMSCRIPTEN_KEEPALIVE int run(uint32_t budget,uint32_t stop) {',
                  'using namespace guest;', 'if(error)return 2;', 'while(budget--) {',
                  'if(ip==stop)return 1;', 'if(!access(ip,1,4))return 2;',
                  'trace[trace_count++%TRACE_SIZE]=ip;++steps;uint32_t next=ip;begin_instruction();', 'switch(ip>>12) {'])
    for page in sorted(pages):lines.append(f'case 0x{page:x}u:next=page_{page:x}();break;')
    lines.extend(['default:fault(3,ip,"untranslated control-flow target");break;',
                  '}', 'end_instruction();if(error)return 2;ip=next;', '}', 'return ip==stop?1:0;', '}'])
    if imports:
        lines.extend(['extern "C" EMSCRIPTEN_KEEPALIVE void configure_platform(uint32_t base) {',
                      'win32::reset(base);',
                      'if(!win32::register_module("kernel32.dll",0x70010000u)){guest::fault(5,0,"kernel32 registration failed");return;}'])
        for address,name in imports.items():
            if name.lower().startswith('kernel32.dll!'):
                plain=name.split('!',1)[1]
                lines.append(f'if(win32::supports({json.dumps(name)}) && !win32::register_export(0x70010000u,{json.dumps(plain)},0x{address:x}u))guest::fault(5,0,"API gateway registration failed");')
        lines.append('}')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    report = {"schema":1,"input_name":image.path.name,"input_sha256":image.sha256,
              "image_base":image.base,"entry":image.entry,"seeds":list(seeds),
              "instruction_count":len(instructions),"instruction_limit":limit,
              "dispatch_pages":len(pages),
              "mnemonics":dict(Counter(i.mnemonic for i in instructions.values())),
              "unsupported":unsupported,"indirect_sites":indirect,"untranslated_targets":sorted(set(missing)),
              "output_sha256":hashlib.sha256(output.read_bytes()).hexdigest()}
    output.with_suffix('.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary',type=Path)
    parser.add_argument('--entry',type=lambda s:int(s,0),action='append')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--limit',type=int,default=20000)
    args=parser.parse_args()
    image=PEImage(args.binary)
    report=lift(image,args.entry or [image.entry],args.output,args.limit)
    print(json.dumps({k:report[k] for k in ('input_sha256','instruction_count','unsupported','untranslated_targets')},indent=2))


if __name__=='__main__': main()
