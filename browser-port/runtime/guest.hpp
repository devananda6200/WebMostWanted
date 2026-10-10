#pragma once
#include <cstdint>
#include <cstring>
#include <cmath>
#include <limits>
#include <emscripten/emscripten.h>

// This is a guest address space, not an x86-address-to-host-pointer cast.
namespace guest {
constexpr uint32_t SIZE = 64u * 1024 * 1024;
constexpr uint32_t PAGE = 4096;
constexpr uint32_t CF=1, PF=4, AF=16, ZF=64, SF=128, DF=1024, OF=2048;
constexpr uint32_t ARITH=CF|PF|AF|ZF|SF|OF;
alignas(16) inline uint8_t memory[SIZE];
inline uint8_t permissions[SIZE/PAGE];
inline uint32_t r[8], xmm[8][4], ip, flags=0x202, fsbase, steps;
inline uint32_t error, error_address;
inline const char* error_text="";
inline double fpu[8];
inline uint32_t fpu_depth;
inline uint16_t fpu_control=0x037f, fpu_status;
constexpr uint32_t TRACE_SIZE=4096;
inline uint32_t trace[TRACE_SIZE], trace_count;
struct CpuSnapshot { uint32_t r[8],xmm[8][4],flags; double fpu[8]; uint32_t depth; uint16_t control,status; };
struct UndoWrite { uint32_t address,value; unsigned bits; };
inline CpuSnapshot saved;
inline UndoWrite undo[1024];
inline unsigned undo_count;
inline bool transaction;

inline void begin_instruction() {
    std::memcpy(saved.r,r,sizeof(r)); std::memcpy(saved.xmm,xmm,sizeof(xmm));
    std::memcpy(saved.fpu,fpu,sizeof(fpu)); saved.flags=flags; saved.depth=fpu_depth;
    saved.control=fpu_control; saved.status=fpu_status;
    undo_count=0; transaction=true;
}
inline void end_instruction() {
    if(error) {
        while(undo_count) { auto w=undo[--undo_count]; std::memcpy(memory+w.address,&w.value,w.bits/8); }
        std::memcpy(r,saved.r,sizeof(r));std::memcpy(xmm,saved.xmm,sizeof(xmm));
        std::memcpy(fpu,saved.fpu,sizeof(fpu));flags=saved.flags;fpu_depth=saved.depth;
        fpu_control=saved.control; fpu_status=saved.status;
    }
    transaction=false;
}

inline void fault(uint32_t code, uint32_t address, const char* text) {
    if (!error) { error=code; error_address=address; error_text=text; }
}
inline bool access(uint32_t address, uint32_t length, uint8_t mode) {
    if(error) return false;
    if (!length || uint64_t(address)+length>SIZE) {
        fault(1,address,"guest address outside bounded memory"); return false;
    }
    for (uint32_t p=address/PAGE; p<=(address+length-1)/PAGE; ++p) {
        if ((permissions[p]&mode)!=mode) {
            fault(1,address,"guest page permission or unmapped access"); return false;
        }
        if ((mode&2) && (permissions[p]&4)) {
            fault(4,address,"write to executable page: retranslation required"); return false;
        }
    }
    return true;
}
inline uint32_t mask(unsigned bits) { return bits==32 ? 0xffffffffu : (1u<<bits)-1; }
inline uint32_t rd(uint32_t address, unsigned bits) {
    uint32_t value=0;
    if (access(address,bits/8,1)) std::memcpy(&value,memory+address,bits/8);
    return value;
}
inline void wr(uint32_t address, uint32_t value, unsigned bits) {
    if (access(address,bits/8,2)) {
        if(transaction) {
            if(undo_count==1024) { fault(2,ip,"instruction write-transaction capacity exceeded");return; }
            uint32_t old=0;std::memcpy(&old,memory+address,bits/8);
            undo[undo_count++]={address,old,bits};
        }
        std::memcpy(memory+address,&value,bits/8);
    }
}
inline void push(uint32_t value) { uint32_t sp=r[4]-4; wr(sp,value,32); if (!error) r[4]=sp; }
inline uint32_t pop() { uint32_t value=rd(r[4],32); if (!error) r[4]+=4; return value; }
inline void pop_flags() {
    uint32_t value=pop();
    if(error)return;
    // Arithmetic, DF and the CPUID-detection ID flag are modeled. Reserved bits
    // are ignored; other control/debug/privilege changes require a fuller CPU.
    constexpr uint32_t id_flag=0x00200000u;
    constexpr uint32_t controls=0x001f7300u;
    if((value&controls)!=(flags&controls)) {
        fault(2,ip,"POPFD control/debug/privilege flag change is not implemented");return;
    }
    flags=(value&(ARITH|DF|id_flag))|(flags&controls)|2u;
}
inline uint32_t read_reg(unsigned reg, unsigned bits, unsigned shift=0) { return (r[reg]>>shift)&mask(bits); }
inline void write_reg(unsigned reg, unsigned bits, unsigned shift, uint32_t value) {
    if(error)return;
    uint32_t m=mask(bits)<<shift; r[reg]=(r[reg]&~m)|((value<<shift)&m);
}
inline uint32_t szp(uint32_t result, unsigned bits) {
    result &= mask(bits);
    return (result==0 ? ZF:0) | (result&(1u<<(bits-1)) ? SF:0)
        | ((__builtin_parity(result&255)==0) ? PF:0);
}
inline uint32_t add(uint32_t a,uint32_t b,unsigned bits,uint32_t carry=0) {
    a&=mask(bits); b&=mask(bits);
    uint64_t full=uint64_t(a)+b+carry;
    uint32_t result=uint32_t(full)&mask(bits);
    flags=(flags&~ARITH)|szp(result,bits)|(full>mask(bits)?CF:0)
        | ((a^b^result)&AF) | ((~(a^b)&(a^result)&(1u<<(bits-1)))?OF:0);
    return result;
}
inline uint32_t sub(uint32_t a,uint32_t b,unsigned bits,uint32_t borrow=0) {
    a&=mask(bits); b&=mask(bits);
    uint64_t rhs=uint64_t(b)+borrow;
    uint32_t result=(a-uint32_t(rhs))&mask(bits);
    flags=(flags&~ARITH)|szp(result,bits)|(uint64_t(a)<rhs?CF:0)
        | ((a^b^result)&AF) | (((a^b)&(a^result)&(1u<<(bits-1)))?OF:0);
    return result;
}
inline uint32_t logic(uint32_t value,unsigned bits) {
    value &= mask(bits); flags=(flags&~ARITH)|szp(value,bits); return value;
}
inline int64_t sign(uint32_t value,unsigned bits) {
    value &= mask(bits); return value & (1u<<(bits-1)) ? int64_t(value)-(int64_t(1)<<bits) : value;
}
inline uint32_t multiply(uint32_t a,uint32_t b,unsigned bits) {
    int64_t value=sign(a,bits)*sign(b,bits);
    uint32_t result=uint32_t(value)&mask(bits);
    flags=(flags&~(CF|OF))|(sign(result,bits)!=value ? CF|OF:0); return result;
}
inline uint32_t shift(uint32_t value,uint32_t count,unsigned bits,unsigned kind) {
    count &= 31; value &= mask(bits); if (!count) return value;
    if (count>bits) { fault(2,ip,"shift count exceeds supported operand width"); return value; }
    uint32_t result=0,carry=0,overflow=0;
    if (kind==0) { carry=(value>>(bits-count))&1; result=uint32_t(uint64_t(value)<<count)&mask(bits); overflow=((result>>(bits-1))^carry)&1; }
    if (kind==1) { carry=(value>>(count-1))&1; result=uint32_t(uint64_t(value)>>count); overflow=value>>(bits-1); }
    if (kind==2) { carry=(value>>(count-1))&1; result=uint32_t(sign(value,bits)>>count)&mask(bits); }
    flags=(flags&~(CF|PF|ZF|SF|(count==1?OF:0)))|szp(result,bits)|(carry?CF:0)|(count==1&&overflow?OF:0);
    return result;
}
inline bool condition(unsigned c) {
    bool z=flags&ZF,s=flags&SF,o=flags&OF,p=flags&PF,b=flags&CF;
    switch(c) {
        case 0:return o; case 1:return !o; case 2:return b; case 3:return !b;
        case 4:return z; case 5:return !z; case 6:return b||z; case 7:return !b&&!z;
        case 8:return s; case 9:return !s; case 10:return p; case 11:return !p;
        case 12:return s!=o; case 13:return s==o; case 14:return z||(s!=o); case 15:return !z&&(s==o);
    } return false;
}
inline void cpuid() {
    // Measured with authored CPUID instructions on pinned Unicorn 2.1.4's
    // UC_CPU_X86_PENTIUM3 profile. Leaves 0/1 ignore incoming ECX. These are
    // declared guest capabilities, never a query of the browser host's CPU.
    if(r[0]==0) { r[0]=3; r[3]=0x756e6547; r[1]=0x6c65746e; r[2]=0x49656e69; }
    else if(r[0]==1) { r[0]=0x673; r[3]=0x800; r[1]=0x80000000; r[2]=0x0383fbfd; }
    else fault(2,ip,"CPUID leaf outside verified guest profile");
}
inline float as_float(uint32_t bits) { float result; std::memcpy(&result,&bits,4); return result; }
inline uint32_t as_bits(float value) { uint32_t result; std::memcpy(&result,&value,4); return result; }
inline void fwait() {
    if(fpu_status & ~fpu_control & 0x3f)
        fault(2,ip,"pending unmasked x87 exception requires guest exception delivery");
}
inline void finit() {
    fpu_control=0x037f; fpu_status=0; fpu_depth=0;
    std::memset(fpu,0,sizeof(fpu));
}
inline void fldcw(uint32_t address) {
    fwait();
    uint32_t value=rd(address,16);
    if(!error)fpu_control=uint16_t(value);
}
inline void fpush(double value) {
    fwait(); if(error)return;
    if(fpu_depth==8) { fault(2,ip,"x87 stack overflow"); return; }
    for(unsigned i=fpu_depth;i>0;--i) fpu[i]=fpu[i-1]; fpu[0]=value; ++fpu_depth;
    fpu_status=(fpu_status&~0x3a00u)|((((fpu_status>>11)-1u)&7u)<<11);
}
inline void fpop() {
    if(!fpu_depth) { fault(2,ip,"x87 stack underflow"); return; }
    for(unsigned i=1;i<fpu_depth;++i) fpu[i-1]=fpu[i]; --fpu_depth;
    fpu_status=(fpu_status&~0x3800u)|((((fpu_status>>11)+1u)&7u)<<11);
}
// Control words are real guest state. Only finite, normal/zero exact loads and
// stores are supported: rounding/denormal/NaN exception behavior must not be
// silently inherited from the Wasm host's double operations.
inline double fload(uint32_t address,unsigned bits) {
    fwait(); if(error)return 0;
    double value=0;
    if(bits==32) {
        float single=as_float(rd(address,32)); value=single;
        if(!std::isfinite(single)||std::fpclassify(single)==FP_SUBNORMAL)
            fault(2,ip,"x87 nonfinite/denormal load is not implemented");
    } else {
        if(access(address,8,1)) std::memcpy(&value,memory+address,8);
        if(!std::isfinite(value)||std::fpclassify(value)==FP_SUBNORMAL)
            fault(2,ip,"x87 nonfinite/denormal load is not implemented");
    }
    return value;
}
inline void fstore(uint32_t address,unsigned bits) {
    fwait(); if(error)return;
    if(!fpu_depth) { fault(2,ip,"x87 stack underflow"); return; }
    if(bits==32) {
        float value=float(fpu[0]);
        if(!std::isfinite(value)||std::fpclassify(value)==FP_SUBNORMAL||double(value)!=fpu[0]) {
            fault(2,ip,"x87 rounded/denormal store is not implemented");return;
        }
        wr(address,as_bits(value),32);
    }
    else { uint64_t value;std::memcpy(&value,&fpu[0],8);wr(address,uint32_t(value),32);wr(address+4,uint32_t(value>>32),32); }
}
} // namespace guest

extern "C" {
EMSCRIPTEN_KEEPALIVE void reset() {
    using namespace guest;
    std::memset(memory,0,SIZE); std::memset(permissions,0,sizeof(permissions));
    std::memset(r,0,sizeof(r)); std::memset(xmm,0,sizeof(xmm)); std::memset(fpu,0,sizeof(fpu));
    ip=fsbase=steps=error=error_address=fpu_depth=trace_count=0; flags=0x202; error_text="";
    fpu_control=0x037f; fpu_status=0;
    transaction=false;undo_count=0;
}
EMSCRIPTEN_KEEPALIVE uintptr_t memory_base() { return reinterpret_cast<uintptr_t>(guest::memory); }
EMSCRIPTEN_KEEPALIVE uint32_t memory_size() { return guest::SIZE; }
EMSCRIPTEN_KEEPALIVE int map_region(uint32_t address,uint32_t size,uint32_t perms) {
    if(!size || address%guest::PAGE || size%guest::PAGE || uint64_t(address)+size>guest::SIZE || perms>7) return 0;
    for(uint32_t p=address/guest::PAGE;p<(address+size)/guest::PAGE;++p) guest::permissions[p]=perms;
    return 1;
}
EMSCRIPTEN_KEEPALIVE uint32_t get_reg(uint32_t i) { return i<8?guest::r[i]:0; }
EMSCRIPTEN_KEEPALIVE void set_reg(uint32_t i,uint32_t value) { if(i<8) guest::r[i]=value; }
EMSCRIPTEN_KEEPALIVE uint32_t get_eip() { return guest::ip; }
EMSCRIPTEN_KEEPALIVE void set_eip(uint32_t value) { guest::ip=value; }
EMSCRIPTEN_KEEPALIVE uint32_t get_flags() { return guest::flags; }
EMSCRIPTEN_KEEPALIVE void set_flags(uint32_t value) { guest::flags=value|2; }
EMSCRIPTEN_KEEPALIVE void set_fs_base(uint32_t value) { guest::fsbase=value; }
EMSCRIPTEN_KEEPALIVE uint32_t get_xmm(uint32_t i,uint32_t lane) { return i<8&&lane<4?guest::xmm[i][lane]:0; }
EMSCRIPTEN_KEEPALIVE void set_xmm(uint32_t i,uint32_t lane,uint32_t bits) { if(i<8&&lane<4) guest::xmm[i][lane]=bits; }
EMSCRIPTEN_KEEPALIVE uint32_t get_fpu_depth() { return guest::fpu_depth; }
EMSCRIPTEN_KEEPALIVE uint32_t get_fpu_control() { return guest::fpu_control; }
EMSCRIPTEN_KEEPALIVE uint32_t get_fpu_status() { return guest::fpu_status; }
EMSCRIPTEN_KEEPALIVE void set_fpu_control(uint32_t value) { guest::fpu_control=uint16_t(value); }
EMSCRIPTEN_KEEPALIVE void set_fpu_status(uint32_t value) { guest::fpu_status=uint16_t(value); }
EMSCRIPTEN_KEEPALIVE uint32_t fault_code() { return guest::error; }
EMSCRIPTEN_KEEPALIVE uint32_t fault_address() { return guest::error_address; }
EMSCRIPTEN_KEEPALIVE const char* fault_text() { return guest::error_text; }
EMSCRIPTEN_KEEPALIVE uint32_t get_steps() { return guest::steps; }
EMSCRIPTEN_KEEPALIVE uint32_t get_trace_count() { return guest::trace_count<guest::TRACE_SIZE?guest::trace_count:guest::TRACE_SIZE; }
EMSCRIPTEN_KEEPALIVE uint32_t get_trace(uint32_t i) {
    uint32_t n=get_trace_count(); return i<n ? guest::trace[(guest::trace_count-n+i)%guest::TRACE_SIZE] : 0;
}
}
