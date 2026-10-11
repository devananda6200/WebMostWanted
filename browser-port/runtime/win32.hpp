#pragma once
#include "guest.hpp"
#include <algorithm>
#include <string>
#include <vector>
#include <emscripten/html5.h>

// Narrow browser-local Win32 contracts. See docs/WIN32_COMPATIBILITY.md.
// Only one guest thread exists. New guest threads must not reuse this state.
namespace win32 {
constexpr uint32_t ARENA_BEGIN=0x02600000u, ARENA_END=0x02f00000u;
constexpr uint32_t ARENA_PAGES=(ARENA_END-ARENA_BEGIN)/guest::PAGE;
constexpr uint32_t PROCESS_BEGIN=0x02510000u, PROCESS_END=ARENA_BEGIN;
constexpr uint32_t PROCESS_PAGES=(PROCESS_END-PROCESS_BEGIN)/guest::PAGE;
constexpr char EXECUTABLE_PATH[]="C:\\NFS\\speed.exe";
constexpr char COMMAND_LINE[]="\"C:\\NFS\\speed.exe\"";
constexpr uint32_t INVALID_PARAMETER=87, INVALID_HANDLE=6, NOT_ENOUGH_MEMORY=8;
constexpr uint32_t MODULE_NOT_FOUND=126, PROCEDURE_NOT_FOUND=127;
constexpr uint32_t INSUFFICIENT_BUFFER=122, ACP=1252, WC_NO_BEST_FIT_CHARS=0x400;
constexpr uint32_t HEAP_NO_SERIALIZE=1, HEAP_GENERATE_EXCEPTIONS=4, HEAP_ZERO_MEMORY=8;
constexpr uint32_t HEAP_REALLOC_IN_PLACE_ONLY=0x10;
constexpr uint32_t HEAP_CREATE_ENABLE_EXECUTE=0x40000;
constexpr uint32_t HEAP_HANDLE_BASE=0x70000000u;
struct Heap { bool active=false; bool fixed=false; uint32_t maximum=0, committed=0; };
struct Block { uint32_t address, size, heap, requested; bool used; };
inline Heap heaps[32];
inline std::vector<Block> blocks;
inline uint32_t owners[ARENA_PAGES], last_error, module_base, process_heap;
enum class ProcessString : uint8_t { Free, CommandLine, EnvironmentA, EnvironmentW };
inline ProcessString process_strings[PROCESS_PAGES];
inline uint32_t command_line, unhandled_exception_filter;
inline double boot_epoch_ms;
inline bool clock_initialized;
inline bool tls_used[64];
inline uint32_t tls_values[64];
struct Module { std::string name; uint32_t handle; };
struct Export { uint32_t module; std::string name; uint32_t gateway; };
inline std::vector<Module> modules;
inline std::vector<Export> exports;
inline std::string dynamic_error;
struct CriticalSection { uint32_t address, owner, recursion; };
inline std::vector<CriticalSection> critical_sections;

inline void reset(uint32_t executable_base=0) {
    // A Wasm module is one virtual boot; process resets preserve its uptime.
    if(!clock_initialized) { boot_epoch_ms=emscripten_get_now();clock_initialized=true; }
    for(uint32_t i=0;i<ARENA_PAGES;++i)
        if(owners[i]) guest::permissions[ARENA_BEGIN/guest::PAGE+i]=0;
    for(uint32_t i=0;i<PROCESS_PAGES;++i)
        if(process_strings[i]!=ProcessString::Free) guest::permissions[PROCESS_BEGIN/guest::PAGE+i]=0;
    std::memset(heaps,0,sizeof(heaps)); std::memset(owners,0,sizeof(owners));
    std::memset(tls_used,0,sizeof(tls_used)); std::memset(tls_values,0,sizeof(tls_values));
    std::memset(process_strings,0,sizeof(process_strings)); command_line=0;
    unhandled_exception_filter=0;
    blocks.clear(); last_error=process_heap=0; module_base=executable_base;
    modules.clear(); exports.clear(); dynamic_error.clear();
    critical_sections.clear();
}

inline uint32_t tick_count_from_elapsed(double milliseconds) {
    if(!std::isfinite(milliseconds) || milliseconds<0) {
        guest::fault(5,guest::ip,"GetTickCount invalid monotonic elapsed time");return 0;
    }
    // Convert only after reducing the value into the uint32 range.
    return uint32_t(std::fmod(std::floor(milliseconds),4294967296.0));
}

inline uint32_t process_string(ProcessString kind) {
    if(kind==ProcessString::CommandLine && command_line) return command_line;
    for(uint32_t i=0;i<PROCESS_PAGES;++i) {
        uint32_t address=PROCESS_BEGIN+i*guest::PAGE;
        if(process_strings[i]!=ProcessString::Free || guest::permissions[address/guest::PAGE]) continue;
        // Map a fresh owned page only after validating that it has no other user.
        std::memset(guest::memory+address,0,guest::PAGE);
        if(kind==ProcessString::CommandLine) {
            std::memcpy(guest::memory+address,COMMAND_LINE,sizeof(COMMAND_LINE)); command_line=address;
        }
        // Environment blocks contain two NULs in A/W form. The guest process
        // starts with an explicitly empty environment, not the host environment.
        process_strings[i]=kind;guest::permissions[address/guest::PAGE]=1;
        return address;
    }
    last_error=NOT_ENOUGH_MEMORY;
    if(kind==ProcessString::CommandLine)
        guest::fault(5,guest::ip,"guest command-line storage exhausted");
    return 0;
}
inline uint32_t free_environment(uint32_t address,ProcessString kind) {
    if(address<PROCESS_BEGIN || address>=PROCESS_END || address%guest::PAGE ||
       process_strings[(address-PROCESS_BEGIN)/guest::PAGE]!=kind) {
        last_error=INVALID_PARAMETER;return 0;
    }
    if(!guest::access(address,kind==ProcessString::EnvironmentW?4:2,1)) return 0;
    process_strings[(address-PROCESS_BEGIN)/guest::PAGE]=ProcessString::Free;
    guest::permissions[address/guest::PAGE]=0;return 1;
}

inline bool supported_code_page(uint32_t code_page) {
    if(code_page==0 || code_page==ACP) return true;
    dynamic_error="unimplemented Windows code page: "+std::to_string(code_page);
    guest::fault(5,guest::ip,dynamic_error.c_str());return false;
}
// Exact round-trip repertoire from Microsoft's published Windows-1252
// mapping, including the five control slots in its WindowsBestFit table.
inline constexpr uint16_t CP1252_EXTENDED[32]={
        0x20ac,0x0081,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,
        0x02c6,0x2030,0x0160,0x2039,0x0152,0x008d,0x017d,0x008f,
        0x0090,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
        0x02dc,0x2122,0x0161,0x203a,0x0153,0x009d,0x017e,0x0178};
inline uint16_t cp1252_word(uint8_t byte) {
    return byte>=0x80 && byte<0xa0?CP1252_EXTENDED[byte-0x80]:byte;
}
inline int cp1252_byte(uint16_t character) {
    if(character<0x80 || (character>=0xa0 && character<=0xff)) return character;
    for(unsigned i=0;i<32;++i) if(character==CP1252_EXTENDED[i]) return 0x80+i;
    return -1;
}
inline uint32_t wide_to_multi(const uint32_t* a) {
    if(!supported_code_page(a[0])) return 0;
    if(a[1]&~WC_NO_BEST_FIT_CHARS) {
        guest::fault(5,guest::ip,"WideCharToMultiByte unsupported conversion flags");return 0;
    }
    int32_t count=int32_t(a[3]),capacity=int32_t(a[5]);
    if(!a[2] || !count || capacity<0 || (a[4] && a[2]==a[4])) {
        last_error=INVALID_PARAMETER;return 0;
    }
    if(count < -1) {
        guest::fault(5,guest::ip,"WideCharToMultiByte undocumented negative length is unsupported");return 0;
    }
    if(capacity && !a[4]) { last_error=INSUFFICIENT_BUFFER;return 0; }
    constexpr uint32_t limit=32768;
    if(count>int32_t(limit)) {
        guest::fault(5,guest::ip,"WideCharToMultiByte input exceeds 32768 UTF-16 units");return 0;
    }
    uint32_t default_byte='?';
    if(a[6]) { default_byte=guest::rd(a[6],8);if(guest::error) return 0; }
    if(a[7] && !guest::access(a[7],4,2)) return 0;
    std::vector<uint8_t> converted;converted.reserve(count>0?uint32_t(count):64);
    uint32_t first_default=0xffffffffu;
    bool terminated=false;
    for(uint32_t i=0;i<(count<0?limit:uint32_t(count));++i) {
        uint64_t address=uint64_t(a[2])+uint64_t(i)*2;
        if(address+2>guest::SIZE) {
            guest::fault(1,a[2],"WideCharToMultiByte input exceeds guest memory");return 0;
        }
        uint16_t character=uint16_t(guest::rd(uint32_t(address),16));if(guest::error) return 0;
        if(character>=0xd800 && character<=0xdfff) {
            guest::fault(5,uint32_t(address),"WideCharToMultiByte XP surrogate conversion is unsupported");return 0;
        }
        int byte=cp1252_byte(character);
        // The observed CRT uppercases U+0192 to U+0191 before converting its
        // table back to CP1252. This one best-fit pair is verified natively.
        if(byte<0 && character==0x0191 && !(a[1]&WC_NO_BEST_FIT_CHARS)) byte=0x83;
        if(byte<0) {
            if(!(a[1]&WC_NO_BEST_FIT_CHARS)) {
                guest::fault(5,uint32_t(address),"WideCharToMultiByte requires unimplemented CP1252 best-fit mapping");return 0;
            }
            byte=default_byte;first_default=std::min(first_default,i);
        }
        converted.push_back(uint8_t(byte));
        if(count<0 && !character) { terminated=true;break; }
    }
    if(count<0 && !terminated) {
        guest::fault(5,a[2],"WideCharToMultiByte unterminated input exceeds supported bound");return 0;
    }
    uint32_t required=uint32_t(converted.size());
    uint32_t written=capacity?std::min(uint32_t(capacity),required):0;
    if(written && !guest::access(a[4],written,2)) return 0;
    // All guest ranges and conversion modes are checked before any mutation.
    // A too-small nonempty buffer receives the documented converted prefix.
    if(written) std::memcpy(guest::memory+a[4],converted.data(),written);
    if(a[7]) guest::wr(a[7],first_default<(capacity?written:required),32);
    if(capacity && written<required) { last_error=INSUFFICIENT_BUFFER;return 0; }
    return required;
}

inline uint32_t multi_to_wide(const uint32_t* a) {
    if(!supported_code_page(a[0])) return 0;
    // Precomposed is the default. Every byte is defined in Windows CP1252,
    // including its five control slots, so strict input validation also works.
    if(a[1]&~(1u|8u)) {
        guest::fault(5,guest::ip,"MultiByteToWideChar unsupported conversion flags");return 0;
    }
    int32_t count=int32_t(a[3]),capacity=int32_t(a[5]);
    if(!a[2] || !count || capacity<0 || (a[4] && a[2]==a[4])) {
        last_error=INVALID_PARAMETER;return 0;
    }
    if(count < -1) {
        guest::fault(5,guest::ip,"MultiByteToWideChar undocumented negative length is unsupported");return 0;
    }
    if(capacity && !a[4]) { last_error=INSUFFICIENT_BUFFER;return 0; }
    constexpr uint32_t limit=32768;
    if(count>int32_t(limit)) {
        guest::fault(5,guest::ip,"MultiByteToWideChar input exceeds 32768 bytes");return 0;
    }
    std::vector<uint16_t> converted;converted.reserve(count>0?uint32_t(count):64);
    bool terminated=false;
    for(uint32_t i=0;i<(count<0?limit:uint32_t(count));++i) {
        uint64_t address=uint64_t(a[2])+i;
        if(address>=guest::SIZE) {
            guest::fault(1,a[2],"MultiByteToWideChar input exceeds guest memory");return 0;
        }
        uint8_t byte=uint8_t(guest::rd(uint32_t(address),8));if(guest::error) return 0;
        converted.push_back(cp1252_word(byte));
        if(count<0 && !byte) { terminated=true;break; }
    }
    if(count<0 && !terminated) {
        guest::fault(5,a[2],"MultiByteToWideChar unterminated input exceeds supported bound");return 0;
    }
    uint32_t required=uint32_t(converted.size());
    uint32_t written=capacity?std::min(uint32_t(capacity),required):0;
    if(written && !guest::access(a[4],written*2,2)) return 0;
    if(written) std::memcpy(guest::memory+a[4],converted.data(),written*2);
    if(capacity && written<required) { last_error=INSUFFICIENT_BUFFER;return 0; }
    return required;
}

inline uint16_t cp1252_ctype1(uint8_t byte) {
    // Pinned factual API observations for this deliberately restricted
    // repertoire. Reproduce with tools.win32_nls_reference on Windows.
    constexpr uint16_t types[256]={
        0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x268,0x228,0x228,0x228,0x228,0x220,0x220,
        0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,0x220,
        0x248,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,
        0x284,0x284,0x284,0x284,0x284,0x284,0x284,0x284,0x284,0x284,0x210,0x210,0x210,0x210,0x210,0x210,
        0x210,0x381,0x381,0x381,0x381,0x381,0x381,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,
        0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x210,0x210,0x210,0x210,0x210,
        0x210,0x382,0x382,0x382,0x382,0x382,0x382,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,
        0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x210,0x210,0x210,0x210,0x220,
        0x200,0x220,0x210,0x302,0x210,0x210,0x210,0x210,0x200,0x210,0x301,0x210,0x301,0x220,0x301,0x220,
        0x220,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x200,0x200,0x302,0x210,0x302,0x220,0x302,0x301,
        0x248,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x210,0x312,0x210,0x210,0x230,0x210,0x210,
        0x210,0x210,0x214,0x214,0x210,0x312,0x210,0x210,0x210,0x214,0x312,0x210,0x210,0x210,0x210,0x210,
        0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x301,
        0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x210,0x301,0x301,0x301,0x301,0x301,0x301,0x301,0x302,
        0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302,
        0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x210,0x302,0x302,0x302,0x302,0x302,0x302,0x302,0x302};
    return types[byte];
}
inline uint32_t string_type(const uint32_t* a) {
    if(a[0]!=1) { guest::fault(5,guest::ip,"GetStringTypeW classification type is unsupported");return 0; }
    int32_t count=int32_t(a[2]);
    if(!a[1] || !a[3] || !count || a[1]==a[3]) { last_error=INVALID_PARAMETER;return 0; }
    constexpr uint32_t limit=32768;
    if(count>int32_t(limit)) { guest::fault(5,guest::ip,"GetStringTypeW input exceeds 32768 UTF-16 units");return 0; }
    std::vector<uint16_t> types;types.reserve(count>0?uint32_t(count):64);
    bool terminated=false;
    for(uint32_t i=0;i<(count<0?limit:uint32_t(count));++i) {
        uint64_t address=uint64_t(a[1])+uint64_t(i)*2;
        if(address+2>guest::SIZE) { guest::fault(1,a[1],"GetStringTypeW input exceeds guest memory");return 0; }
        uint16_t character=uint16_t(guest::rd(uint32_t(address),16));if(guest::error) return 0;
        int byte=cp1252_byte(character);
        if(byte<0) { guest::fault(5,uint32_t(address),"GetStringTypeW character outside verified CP1252 repertoire");return 0; }
        types.push_back(cp1252_ctype1(uint8_t(byte)));
        if(count<0 && !character) { terminated=true;break; }
    }
    if(count<0 && !terminated) { guest::fault(5,a[1],"GetStringTypeW unterminated input exceeds supported bound");return 0; }
    uint32_t bytes=uint32_t(types.size())*2;
    if(!guest::access(a[3],bytes,2)) return 0;
    std::memcpy(guest::memory+a[3],types.data(),bytes);return 1;
}

inline uint16_t cp1252_case(uint16_t character,bool upper) {
    // Non-linguistic LCMapString casing, verified for all 256 input characters.
    // Sharp S and micro sign stay unchanged in this mode; f-hook uppercases
    // to U+0191, which is a valid Unicode output outside the input repertoire.
    if(upper) {
        if((character>='a' && character<='z') ||
           (character>=0xe0 && character<=0xfe && character!=0xf7)) return character-32;
        switch(character) {
            case 0x192:return 0x191;case 0x161:return 0x160;case 0x153:return 0x152;
            case 0x17e:return 0x17d;case 0xff:return 0x178;
        }
    } else {
        if((character>='A' && character<='Z') ||
           (character>=0xc0 && character<=0xde && character!=0xd7)) return character+32;
        switch(character) {
            case 0x160:return 0x161;case 0x152:return 0x153;case 0x17d:return 0x17e;
            case 0x178:return 0xff;
        }
    }
    return character;
}
inline uint32_t map_string(const uint32_t* a) {
    // Only locale 0 from the observed CRT call, explicit en-US, and invariant
    // have been checked. No host locale lookup occurs during guest execution.
    if(a[0]!=0 && a[0]!=0x409 && a[0]!=0x7f) {
        dynamic_error="LCMapStringW unverified locale: "+std::to_string(a[0]);
        guest::fault(5,guest::ip,dynamic_error.c_str());return 0;
    }
    if(a[1]!=0x100 && a[1]!=0x200) {
        guest::fault(5,guest::ip,"LCMapStringW unsupported flags; only plain lower/uppercase implemented");return 0;
    }
    int32_t count=int32_t(a[3]),capacity=int32_t(a[5]);
    if(!a[2] || !count || capacity<0 || (capacity && !a[4])) {
        last_error=INVALID_PARAMETER;return 0;
    }
    constexpr uint32_t limit=32768;
    if(count>int32_t(limit)) { guest::fault(5,guest::ip,"LCMapStringW input exceeds 32768 UTF-16 units");return 0; }
    std::vector<uint16_t> converted;converted.reserve(count>0?uint32_t(count):64);
    bool terminated=false;
    for(uint32_t i=0;i<(count<0?limit:uint32_t(count));++i) {
        uint64_t address=uint64_t(a[2])+uint64_t(i)*2;
        if(address+2>guest::SIZE) { guest::fault(1,a[2],"LCMapStringW input exceeds guest memory");return 0; }
        uint16_t character=uint16_t(guest::rd(uint32_t(address),16));if(guest::error) return 0;
        if(cp1252_byte(character)<0) {
            guest::fault(5,uint32_t(address),"LCMapStringW character outside verified CP1252 repertoire");return 0;
        }
        converted.push_back(cp1252_case(character,a[1]==0x200));
        if(count<0 && !character) { terminated=true;break; }
    }
    if(count<0 && !terminated) { guest::fault(5,a[2],"LCMapStringW unterminated input exceeds supported bound");return 0; }
    uint32_t required=uint32_t(converted.size());
    if(!capacity) return required;
    // The reference leaves an insufficient destination unchanged for these
    // flags. In-place conversion is permitted, after reading the whole input.
    if(uint32_t(capacity)<required) { last_error=INSUFFICIENT_BUFFER;return 0; }
    if(!guest::access(a[4],required*2,2)) return 0;
    std::memcpy(guest::memory+a[4],converted.data(),required*2);return required;
}

inline uint32_t heap_index(uint32_t handle) {
    uint32_t index=handle-HEAP_HANDLE_BASE;
    return index<32 && heaps[index].active ? index : 0xffffffffu;
}
inline uint32_t bad_read_pointer(uint32_t address,uint32_t length) {
    // Query only: unlike guest::access, unreadable memory must return TRUE
    // without creating a guest fault or changing the thread's last error.
    if(!length) return 0;
    uint64_t end=uint64_t(address)+length;
    if(!address || end>guest::SIZE) return 1;
    for(uint32_t page=address/guest::PAGE;page<=(end-1)/guest::PAGE;++page)
        if(!(guest::permissions[page]&1)) return 1;
    return 0;
}
inline void coalesce() {
    std::sort(blocks.begin(),blocks.end(),[](const Block& a,const Block& b){return a.address<b.address;});
    for(size_t i=1;i<blocks.size();) {
        Block& a=blocks[i-1]; const Block& b=blocks[i];
        if(!a.used && !b.used && a.heap==b.heap && a.address+a.size==b.address) {
            a.size+=b.size; blocks.erase(blocks.begin()+i);
        } else ++i;
    }
}
inline bool add_chunk(uint32_t heap,uint32_t bytes) {
    uint32_t count=(bytes+guest::PAGE-1)/guest::PAGE;
    if(!count || uint64_t(heaps[heap].committed)+count*guest::PAGE>heaps[heap].maximum) return false;
    uint32_t run=0;
    for(uint32_t i=0;i<ARENA_PAGES;++i) {
        if(owners[i] || guest::permissions[ARENA_BEGIN/guest::PAGE+i]) run=0;
        else ++run;
        if(run!=count) continue;
        uint32_t start=i+1-count;
        for(uint32_t p=start;p<=i;++p) {
            owners[p]=heap+1; guest::permissions[ARENA_BEGIN/guest::PAGE+p]=3;
        }
        uint32_t address=ARENA_BEGIN+start*guest::PAGE;
        std::memset(guest::memory+address,0,count*guest::PAGE);
        blocks.push_back({address,count*guest::PAGE,heap,0,false});
        heaps[heap].committed+=count*guest::PAGE;
        coalesce(); return true;
    }
    return false;
}
inline uint32_t heap_create(uint32_t options,uint32_t initial,uint32_t maximum) {
    if(options&(HEAP_GENERATE_EXCEPTIONS|HEAP_CREATE_ENABLE_EXECUTE)) {
        guest::fault(5,guest::ip,"HeapCreate executable/SEH allocation mode is not implemented"); return 0;
    }
    if(options&~HEAP_NO_SERIALIZE || initial>ARENA_END-ARENA_BEGIN ||
       (maximum && (initial>maximum || maximum>ARENA_END-ARENA_BEGIN))) {
        last_error=INVALID_PARAMETER; return 0;
    }
    uint32_t index=0; while(index<32 && heaps[index].active) ++index;
    if(index==32) { last_error=NOT_ENOUGH_MEMORY; return 0; }
    uint32_t limit=maximum ? (maximum+4095u)&~4095u : ARENA_END-ARENA_BEGIN;
    heaps[index]={true,maximum!=0,limit,0};
    if(!add_chunk(index,std::max(initial,1u))) {
        heaps[index]={}; last_error=NOT_ENOUGH_MEMORY; return 0;
    }
    return HEAP_HANDLE_BASE+index;
}
inline uint32_t heap_alloc(uint32_t handle,uint32_t options,uint32_t requested) {
    // HeapAlloc and HeapSize do not set last error, even on allocation failure.
    if(options&HEAP_GENERATE_EXCEPTIONS) {
        guest::fault(5,guest::ip,"HeapAlloc HEAP_GENERATE_EXCEPTIONS requires guest SEH"); return 0;
    }
    uint32_t index=heap_index(handle);
    if(index==0xffffffffu || options&~(HEAP_NO_SERIALIZE|HEAP_ZERO_MEMORY) ||
       requested>ARENA_END-ARENA_BEGIN || (heaps[index].fixed && requested>=0x7fff8)) return 0;
    uint32_t needed=(std::max(requested,1u)+7)&~7u;
    for(unsigned attempt=0;attempt<2;++attempt) {
        for(size_t i=0;i<blocks.size();++i) {
            Block block=blocks[i];
            if(block.heap!=index || block.used || block.size<needed) continue;
            if(!guest::access(block.address,needed,2)) return 0;
            blocks[i]={block.address,needed,index,requested,true};
            if(block.size>needed) blocks.push_back({block.address+needed,block.size-needed,index,0,false});
            if(options&HEAP_ZERO_MEMORY) std::memset(guest::memory+block.address,0,needed);
            return block.address;
        }
        if(attempt==0) {
            uint32_t remaining=heaps[index].maximum-heaps[index].committed;
            uint32_t grow=std::min(std::max(needed,65536u),remaining);
            if(grow<needed || !add_chunk(index,grow)) return 0;
        }
    }
    return 0;
}
inline uint32_t heap_size(uint32_t handle,uint32_t options,uint32_t address) {
    uint32_t index=heap_index(handle);
    if(index==0xffffffffu || options&~HEAP_NO_SERIALIZE) return 0xffffffffu;
    for(const Block& block:blocks)
        if(block.heap==index && block.used && block.address==address) return block.requested;
    return 0xffffffffu;
}
inline bool heap_header_valid(uint32_t index) {
    const Heap& heap=heaps[index];
    return heap.active && heap.maximum && heap.maximum<=ARENA_END-ARENA_BEGIN &&
        !(heap.maximum%guest::PAGE) && heap.committed && !(heap.committed%guest::PAGE) &&
        heap.committed<=heap.maximum && (heap.fixed || heap.maximum==ARENA_END-ARENA_BEGIN);
}
inline bool heap_block_valid(const Block& block,uint32_t index) {
    uint64_t end=uint64_t(block.address)+block.size;
    if(block.heap!=index || !block.size || block.address%8 || block.size%8 ||
       block.address<ARENA_BEGIN || end>ARENA_END) return false;
    if(block.used) {
        if(block.requested>block.size ||
           uint64_t(block.size)!=((std::max(uint64_t(block.requested),uint64_t(1))+7)&~uint64_t(7)) ||
           (heaps[index].fixed && block.requested>=0x7fff8)) return false;
    } else if(block.requested) return false;
    for(uint32_t page=block.address/guest::PAGE;page<=(end-1)/guest::PAGE;++page)
        if(owners[page-ARENA_BEGIN/guest::PAGE]!=index+1 || guest::permissions[page]!=3) return false;
    return true;
}
inline uint32_t heap_validate(uint32_t handle,uint32_t options,uint32_t address) {
    // Per Win32, every outcome preserves last error. Invalid metadata returns
    // FALSE without repairing it or dereferencing the candidate guest pointer.
    uint32_t index=heap_index(handle);
    if(index==0xffffffffu || (options&~HEAP_NO_SERIALIZE) || !heap_header_valid(index)) return 0;
    if(address) {
        const Block* found=nullptr;
        for(const Block& block:blocks) if(block.heap==index && block.address==address) {
            if(found) return 0;
            found=&block;
        }
        if(!found || !found->used || !heap_block_valid(*found,index)) return 0;
        uint64_t end=uint64_t(found->address)+found->size;
        for(const Block& block:blocks) if(&block!=found && block.size &&
            uint64_t(block.address)<end && uint64_t(block.address)+block.size>found->address) return 0;
        return 1; // Only this allocation's control structures were checked.
    }
    uint64_t committed=0,covered=0;
    for(uint32_t page=0;page<ARENA_PAGES;++page) if(owners[page]==index+1) {
        if(guest::permissions[ARENA_BEGIN/guest::PAGE+page]!=3) return 0;
        committed+=guest::PAGE;
    }
    if(committed!=heaps[index].committed) return 0;
    std::vector<const Block*> ordered;
    for(const Block& block:blocks) {
        if(block.heap==index) {
            if(!heap_block_valid(block,index)) return 0;
            ordered.push_back(&block);covered+=block.size;
        } else {
            uint64_t end=std::min(uint64_t(block.address)+block.size,uint64_t(ARENA_END));
            uint64_t begin=std::max(uint64_t(block.address),uint64_t(ARENA_BEGIN));
            if(begin<end) for(uint32_t page=uint32_t(begin)/guest::PAGE;page<=(end-1)/guest::PAGE;++page)
                if(owners[page-ARENA_BEGIN/guest::PAGE]==index+1) return 0;
        }
    }
    if(covered!=committed) return 0;
    std::sort(ordered.begin(),ordered.end(),[](const Block* a,const Block* b){return a->address<b->address;});
    for(size_t i=1;i<ordered.size();++i)
        if(uint64_t(ordered[i-1]->address)+ordered[i-1]->size>ordered[i]->address) return 0;
    return 1;
}
inline uint32_t heap_free(uint32_t handle,uint32_t options,uint32_t address) {
    uint32_t index=heap_index(handle);
    if(index==0xffffffffu) { last_error=INVALID_HANDLE; return 0; }
    if(options&~HEAP_NO_SERIALIZE) { last_error=INVALID_PARAMETER; return 0; }
    if(!address) return 1;
    for(Block& block:blocks) {
        if(block.heap==index && block.used && block.address==address) {
            block.used=false; block.requested=0; coalesce(); return 1;
        }
    }
    last_error=INVALID_PARAMETER; return 0;
}
inline bool extend_heap_at(uint32_t index,uint32_t address,uint32_t needed) {
    uint32_t bytes=(needed+guest::PAGE-1)&~(guest::PAGE-1);
    if(address%guest::PAGE || address<ARENA_BEGIN || uint64_t(address)+bytes>ARENA_END ||
       uint64_t(heaps[index].committed)+bytes>heaps[index].maximum) return false;
    uint32_t first=(address-ARENA_BEGIN)/guest::PAGE, count=bytes/guest::PAGE;
    for(uint32_t page=first;page<first+count;++page)
        if(owners[page] || guest::permissions[ARENA_BEGIN/guest::PAGE+page]) return false;
    // All pages were checked before committing any. Existing mappings stay intact.
    for(uint32_t page=first;page<first+count;++page) {
        owners[page]=index+1;guest::permissions[ARENA_BEGIN/guest::PAGE+page]=3;
    }
    std::memset(guest::memory+address,0,bytes);
    blocks.push_back({address,bytes,index,0,false});heaps[index].committed+=bytes;
    coalesce();return true;
}
inline uint32_t heap_realloc(uint32_t handle,uint32_t options,uint32_t address,uint32_t requested) {
    if(options&HEAP_GENERATE_EXCEPTIONS) {
        guest::fault(5,guest::ip,"HeapReAlloc HEAP_GENERATE_EXCEPTIONS requires guest SEH");return 0;
    }
    uint32_t index=heap_index(handle);
    if(index==0xffffffffu || options&~(HEAP_NO_SERIALIZE|HEAP_ZERO_MEMORY|HEAP_REALLOC_IN_PLACE_ONLY) ||
       !address || requested>ARENA_END-ARENA_BEGIN || (heaps[index].fixed && requested>=0x7fff8) ||
       !heap_validate(handle,0,0)) return 0;
    size_t current=blocks.size();
    for(size_t i=0;i<blocks.size();++i)
        if(blocks[i].heap==index && blocks[i].used && blocks[i].address==address) { current=i;break; }
    if(current==blocks.size()) return 0;
    const Block original=blocks[current];
    uint32_t needed=(std::max(requested,1u)+7)&~7u;
    uint32_t available=original.size;
    for(const Block& block:blocks)
        if(block.heap==index && !block.used && block.address==address+original.size) available+=block.size;
    if(needed>available && extend_heap_at(index,address+available,needed-available)) {
        // Coalescing may reorder records, so reacquire indices below.
        available=needed;
    }
    if(needed>available) {
        if(options&HEAP_REALLOC_IN_PLACE_ONLY) return 0;
        // Keep the original allocation live until the replacement is available.
        uint32_t replacement=heap_alloc(handle,options&HEAP_NO_SERIALIZE,requested);
        if(!replacement) return 0;
        std::memcpy(guest::memory+replacement,guest::memory+address,std::min(original.requested,requested));
        if((options&HEAP_ZERO_MEMORY) && requested>original.requested)
            std::memset(guest::memory+replacement+original.requested,0,requested-original.requested);
        for(Block& block:blocks) if(block.heap==index && block.used && block.address==address) {
            block.used=false;block.requested=0;break;
        }
        coalesce();return replacement;
    }
    for(size_t i=0;i<blocks.size();++i)
        if(blocks[i].heap==index && blocks[i].used && blocks[i].address==address) { current=i;break; }
    blocks[current]={address,needed,index,requested,true};
    if(needed<original.size) {
        blocks.push_back({address+needed,original.size-needed,index,0,false});coalesce();
    } else if(needed>original.size) {
        uint32_t consumed=needed-original.size;
        for(size_t i=0;i<blocks.size();++i) if(blocks[i].heap==index && !blocks[i].used &&
            blocks[i].address==address+original.size) {
            blocks[i].address+=consumed;blocks[i].size-=consumed;
            if(!blocks[i].size) blocks.erase(blocks.begin()+i);
            break;
        }
    }
    if((options&HEAP_ZERO_MEMORY) && requested>original.requested)
        std::memset(guest::memory+address+original.requested,0,requested-original.requested);
    return address;
}
inline uint32_t heap_destroy(uint32_t handle) {
    uint32_t index=heap_index(handle);
    if(index==0xffffffffu || handle==process_heap) { last_error=INVALID_HANDLE; return 0; }
    for(uint32_t i=0;i<ARENA_PAGES;++i) if(owners[i]==index+1) {
        owners[i]=0; guest::permissions[ARENA_BEGIN/guest::PAGE+i]=0;
    }
    blocks.erase(std::remove_if(blocks.begin(),blocks.end(),[index](const Block& block){return block.heap==index;}),blocks.end());
    heaps[index]={}; return 1;
}

inline CriticalSection* find_critical(uint32_t address) {
    for(CriticalSection& item:critical_sections) if(item.address==address) return &item;
    return nullptr;
}
inline bool critical_storage(uint32_t address) {
    if(address&3) { guest::fault(5,address,"unaligned critical-section object");return false; }
    return guest::access(address,24,3);
}
inline void store_critical(const CriticalSection& item) {
    // x86 CRITICAL_SECTION is 24 bytes. It is opaque to application code.
    // This single-processor guest has no debug record, semaphore, or spinning.
    guest::wr(item.address,0,32); guest::wr(item.address+4,item.recursion-1,32);
    guest::wr(item.address+8,item.recursion,32); guest::wr(item.address+12,item.owner,32);
    guest::wr(item.address+16,0,32); guest::wr(item.address+20,0,32);
}
inline bool validate_critical(const CriticalSection& item) {
    if(!critical_storage(item.address)) return false;
    if(guest::rd(item.address,32)!=0 || guest::rd(item.address+4,32)!=item.recursion-1 ||
       guest::rd(item.address+8,32)!=item.recursion || guest::rd(item.address+12,32)!=item.owner ||
       guest::rd(item.address+16,32)!=0 || guest::rd(item.address+20,32)!=0) {
        guest::fault(5,item.address,"critical-section storage was copied or modified");return false;
    }
    return true;
}
inline uint32_t initialize_critical(uint32_t address) {
    if(!critical_storage(address)) return 0;
    if(find_critical(address)) { guest::fault(5,address,"critical section initialized twice without deletion");return 0; }
    for(const CriticalSection& item:critical_sections)
        if(uint64_t(address)<uint64_t(item.address)+24 && uint64_t(item.address)<uint64_t(address)+24) {
            guest::fault(5,address,"overlapping critical-section objects");return 0;
        }
    if(critical_sections.size()>=4096) { last_error=NOT_ENOUGH_MEMORY;return 0; }
    critical_sections.push_back({address,0,0});store_critical(critical_sections.back());return 1;
}
inline uint32_t critical_operation(const char* operation,uint32_t address) {
    CriticalSection* item=find_critical(address);
    if(!item) { guest::fault(5,address,"critical section has not been initialized");return 0; }
    if(!validate_critical(*item)) return 0;
    if(!std::strcmp(operation,"DeleteCriticalSection")) {
        if(item->owner || item->recursion) { guest::fault(5,address,"cannot delete an owned critical section");return 0; }
        for(unsigned i=0;i<24;i+=4) guest::wr(address+i,0,32);
        critical_sections.erase(std::remove_if(critical_sections.begin(),critical_sections.end(),
            [address](const CriticalSection& section){return section.address==address;}),critical_sections.end());
        return 1;
    }
    if(!std::strcmp(operation,"LeaveCriticalSection")) {
        if(item->owner!=1 || !item->recursion) { guest::fault(5,address,"critical-section leave without ownership");return 0; }
        if(--item->recursion==0) item->owner=0;
        store_critical(*item);return 1;
    }
    if(item->owner && item->owner!=1) {
        if(!std::strcmp(operation,"TryEnterCriticalSection")) return 0;
        guest::fault(5,address,"critical-section contention requires guest thread scheduling");return 0;
    }
    if(item->recursion==0x7fffffffu) { guest::fault(5,address,"critical-section recursion limit exceeded");return 0; }
    item->owner=1;++item->recursion;store_critical(*item);return 1;
}

inline bool kernel32_name(const char* qualified,const char*& name) {
    if(!qualified) return false;
    const char* bang=std::strchr(qualified,'!');
    if(!bang) { name=qualified; return true; }
    const char* expected="kernel32.dll";
    if(bang-qualified!=12) return false;
    for(unsigned i=0;i<12;++i) {
        char c=qualified[i]; if(c>='A'&&c<='Z') c+=32;
        if(c!=expected[i]) return false;
    }
    name=bang+1; return true;
}

inline int argument_count(const char* name) {
    if(!std::strcmp(name,"GetVersionExA") || !std::strcmp(name,"GetModuleHandleA") ||
       !std::strcmp(name,"GetStartupInfoA") || !std::strcmp(name,"GetStdHandle") ||
       !std::strcmp(name,"GetFileType") || !std::strcmp(name,"SetHandleCount") ||
       !std::strcmp(name,"IsProcessorFeaturePresent") || !std::strcmp(name,"SetUnhandledExceptionFilter") ||
       !std::strcmp(name,"FreeEnvironmentStringsA") || !std::strcmp(name,"FreeEnvironmentStringsW") ||
       !std::strcmp(name,"SetLastError") || !std::strcmp(name,"HeapDestroy") ||
       !std::strcmp(name,"TlsGetValue") || !std::strcmp(name,"TlsFree") ||
       !std::strcmp(name,"GetSystemTimeAsFileTime") || !std::strcmp(name,"QueryPerformanceCounter") ||
       !std::strcmp(name,"QueryPerformanceFrequency") || !std::strcmp(name,"InitializeCriticalSection") ||
       !std::strcmp(name,"EnterCriticalSection") || !std::strcmp(name,"LeaveCriticalSection") ||
       !std::strcmp(name,"TryEnterCriticalSection") || !std::strcmp(name,"DeleteCriticalSection")) return 1;
    if(!std::strcmp(name,"TlsSetValue") || !std::strcmp(name,"GetProcAddress") ||
       !std::strcmp(name,"InitializeCriticalSectionAndSpinCount") || !std::strcmp(name,"GetCPInfo") ||
       !std::strcmp(name,"IsBadReadPtr")) return 2;
    if(!std::strcmp(name,"HeapCreate") || !std::strcmp(name,"HeapAlloc") ||
       !std::strcmp(name,"HeapFree") || !std::strcmp(name,"HeapSize") || !std::strcmp(name,"HeapValidate") ||
       !std::strcmp(name,"GetModuleFileNameA")) return 3;
    if(!std::strcmp(name,"GetLastError") || !std::strcmp(name,"GetCurrentThreadId") ||
       !std::strcmp(name,"GetCurrentProcessId") || !std::strcmp(name,"TlsAlloc") ||
       !std::strcmp(name,"GetProcessHeap") || !std::strcmp(name,"GetCommandLineA") ||
       !std::strcmp(name,"GetEnvironmentStrings") || !std::strcmp(name,"GetEnvironmentStringsA") ||
       !std::strcmp(name,"GetEnvironmentStringsW") || !std::strcmp(name,"GetACP") ||
       !std::strcmp(name,"GetTickCount")) return 0;
    if(!std::strcmp(name,"WideCharToMultiByte")) return 8;
    if(!std::strcmp(name,"MultiByteToWideChar") || !std::strcmp(name,"LCMapStringW")) return 6;
    if(!std::strcmp(name,"GetStringTypeW") || !std::strcmp(name,"HeapReAlloc")) return 4;
    return -1;
}
inline bool supports(const char* qualified) {
    const char* name;
    return kernel32_name(qualified,name) && argument_count(name)>=0;
}
inline std::string module_key(std::string name) {
    for(char& c:name) if(c>='A' && c<='Z') c+=32;
    size_t slash=name.find_last_of('\\');
    size_t base=slash==std::string::npos ? 0 : slash+1;
    if(base==name.size()) return {};
    if(name.back()=='.') name.pop_back();
    else if(name.find('.',base)==std::string::npos) name+=".dll";
    return name;
}
inline std::string basename(const std::string& name) {
    size_t slash=name.find_last_of('\\');
    return slash==std::string::npos ? name : name.substr(slash+1);
}
inline bool register_module(const char* name,uint32_t handle) {
    if(!name || !handle) return false;
    std::string key=module_key(name);
    // This implementation supplies only the explicit kernel32 replacement.
    if(basename(key)!="kernel32.dll" || key.find('/')!=std::string::npos) return false;
    for(const Module& module:modules) if(module.name==key) return module.handle==handle;
    modules.push_back({key,handle}); return true;
}
inline bool registered_handle(uint32_t handle) {
    for(const Module& module:modules) if(module.handle==handle) return true;
    return false;
}
inline bool register_export(uint32_t handle,const char* name,uint32_t gateway) {
    if(!registered_handle(handle) || !name || !supports(name) || !gateway) return false;
    // API names are case sensitive and unqualified, unlike module names.
    if(std::strchr(name,'!')) return false;
    for(const Export& item:exports) if(item.module==handle && item.name==name) return item.gateway==gateway;
    exports.push_back({handle,name,gateway}); return true;
}
inline bool guest_string(uint32_t address,std::string& out,uint32_t bound=32768) {
    out.clear();
    for(uint32_t i=0;i<bound;++i) {
        uint64_t current=uint64_t(address)+i;
        if(current>=guest::SIZE) { guest::fault(1,address,"guest API string exceeds bounded memory");return false; }
        char c=char(guest::rd(uint32_t(current),8));
        if(guest::error) return false;
        if(!c) return true;
        out+=c;
    }
    guest::fault(5,address,"guest API string exceeds supported length"); return false;
}
inline uint32_t module_handle(uint32_t address) {
    if(!address) {
        if(!module_base) guest::fault(5,guest::ip,"executable module base has not been configured");
        return module_base;
    }
    std::string name;
    if(!guest_string(address,name)) return 0;
    std::string key=module_key(name);
    bool full=key.find('\\')!=std::string::npos;
    for(const Module& module:modules)
        if((full && key==module.name) || (!full && key==basename(module.name))) return module.handle;
    last_error=MODULE_NOT_FOUND; return 0;
}
inline uint32_t proc_address(uint32_t handle,uint32_t address) {
    if(!registered_handle(handle)) { last_error=INVALID_HANDLE; return 0; }
    if(address<65536) {
        guest::fault(5,guest::ip,"GetProcAddress ordinal lookup is not implemented"); return 0;
    }
    std::string name;
    if(!guest_string(address,name,4096)) return 0;
    for(const Export& item:exports) if(item.module==handle && item.name==name) return item.gateway;
    if(name=="FlsAlloc" || name=="FlsFree" || name=="FlsGetValue" || name=="FlsSetValue") {
        // FLS is absent from the declared Windows XP client profile.
        last_error=PROCEDURE_NOT_FOUND; return 0;
    }
    dynamic_error="GetProcAddress unresolved required export: "+name;
    guest::fault(5,guest::ip,dynamic_error.c_str()); return 0;
}

// Hundreds of generated import gateways share this implementation. Keep the
// dispatcher out of line to avoid duplicating its API branches at each gateway.
[[gnu::noinline]] inline bool dispatch(const char* qualified,uint32_t& next) {
    const char* name;
    if(!kernel32_name(qualified,name)) return false;
    int arity=argument_count(name); if(arity<0) return false;
    unsigned argc=unsigned(arity);
    if(guest::error) return true;
    if(!guest::access(guest::r[4],(argc+1)*4,1)) return true;
    uint32_t args[8]={};
    for(unsigned i=0;i<argc;++i) args[i]=guest::rd(guest::r[4]+4+i*4,32);
    uint32_t result=0; bool has_result=true;
    if(!std::strcmp(name,"GetVersionExA")) {
        uint32_t p=args[0],size=guest::rd(p,32);
        if(guest::error) return true;
        if(size!=148 && size!=156) { last_error=INVALID_PARAMETER; }
        else {
            if(!guest::access(p,size,2)) return true;
            // Declared virtual Windows XP SP3 workstation compatibility profile.
            std::memset(guest::memory+p+4,0,size-4);
            guest::wr(p+4,5,32); guest::wr(p+8,1,32); guest::wr(p+12,2600,32); guest::wr(p+16,2,32);
            std::memcpy(guest::memory+p+20,"Service Pack 3",15);
            if(size==156) { guest::wr(p+148,3,16); guest::wr(p+154,1,8); }
            result=1;
        }
    } else if(!std::strcmp(name,"GetStartupInfoA")) {
        // A GUI guest process with no inherited console handles or CRT data.
        if(!guest::access(args[0],68,2)) return true;
        for(unsigned i=0;i<68;i+=4) guest::wr(args[0]+i,i==0?68:0,32);
        has_result=false;
    } else if(!std::strcmp(name,"GetStdHandle")) {
        if(args[0]!=uint32_t(-10) && args[0]!=uint32_t(-11) && args[0]!=uint32_t(-12)) {
            result=0xffffffffu; last_error=INVALID_PARAMETER;
        }
        // No console exists and no standard handle has been inherited.
    } else if(!std::strcmp(name,"GetFileType")) {
        if(args[0] && args[0]!=0xffffffffu)
            guest::fault(5,guest::ip,"GetFileType requires a registered guest file handle");
        else last_error=INVALID_HANDLE;
    } else if(!std::strcmp(name,"SetHandleCount")) {
        result=args[0]; // Documented no-op on the declared NT-family profile.
    } else if(!std::strcmp(name,"GetCommandLineA")) {
        result=process_string(ProcessString::CommandLine);
    } else if(!std::strcmp(name,"GetEnvironmentStringsW")) {
        result=process_string(ProcessString::EnvironmentW);
    } else if(!std::strcmp(name,"GetEnvironmentStringsA") || !std::strcmp(name,"GetEnvironmentStrings")) {
        result=process_string(ProcessString::EnvironmentA);
    } else if(!std::strcmp(name,"FreeEnvironmentStringsA") || !std::strcmp(name,"FreeEnvironmentStringsW")) {
        result=free_environment(args[0],!std::strcmp(name,"FreeEnvironmentStringsW")?
            ProcessString::EnvironmentW:ProcessString::EnvironmentA);
    } else if(!std::strcmp(name,"GetModuleFileNameA")) {
        if(args[0] && args[0]!=module_base) {
            if(registered_handle(args[0]))
                guest::fault(5,guest::ip,"replacement module has no guest filesystem path");
            else last_error=MODULE_NOT_FOUND;
        } else if(!module_base) {
            guest::fault(5,guest::ip,"executable module base has not been configured");
        } else {
            constexpr uint32_t length=sizeof(EXECUTABLE_PATH)-1;
            uint32_t copied=std::min(args[2],length+1);
            if(copied && !guest::access(args[1],copied,2)) return true;
            for(uint32_t i=0;i<copied;++i) guest::wr(args[1]+i,uint8_t(EXECUTABLE_PATH[i]),8);
            result=std::min(args[2],length);
            // The declared XP contract leaves truncated output unterminated,
            // returns nSize, and reports ERROR_SUCCESS even for zero nSize.
            if(args[2]<=length) last_error=0;
        }
    } else if(!std::strcmp(name,"GetACP")) {
        result=ACP;
    } else if(!std::strcmp(name,"IsBadReadPtr")) {
        result=bad_read_pointer(args[0],args[1]);
    } else if(!std::strcmp(name,"GetCPInfo")) {
        if(!supported_code_page(args[0])) return true;
        if(!args[1]) last_error=INVALID_PARAMETER;
        else {
            if(!guest::access(args[1],20,2)) return true;
            for(unsigned i=0;i<20;i+=4) guest::wr(args[1]+i,i==0?1:0,32);
            guest::wr(args[1]+4,'?',8);result=1;
        }
    } else if(!std::strcmp(name,"WideCharToMultiByte")) {
        result=wide_to_multi(args);
    } else if(!std::strcmp(name,"MultiByteToWideChar")) {
        result=multi_to_wide(args);
    } else if(!std::strcmp(name,"GetStringTypeW")) {
        result=string_type(args);
    } else if(!std::strcmp(name,"LCMapStringW")) {
        result=map_string(args);
    } else if(!std::strcmp(name,"GetModuleHandleA")) {
        result=module_handle(args[0]);
    } else if(!std::strcmp(name,"GetProcAddress")) {
        result=proc_address(args[0],args[1]);
    } else if(!std::strcmp(name,"InitializeCriticalSection") || !std::strcmp(name,"InitializeCriticalSectionAndSpinCount")) {
        result=initialize_critical(args[0]);
        if(!std::strcmp(name,"InitializeCriticalSection")) {
            has_result=false;
            if(!result && !guest::error) guest::fault(5,guest::ip,"InitializeCriticalSection resource exhaustion requires guest SEH");
        }
    } else if(!std::strcmp(name,"EnterCriticalSection") || !std::strcmp(name,"LeaveCriticalSection") ||
              !std::strcmp(name,"TryEnterCriticalSection") || !std::strcmp(name,"DeleteCriticalSection")) {
        result=critical_operation(name,args[0]);has_result=!std::strcmp(name,"TryEnterCriticalSection");
    } else if(!std::strcmp(name,"HeapCreate")) result=heap_create(args[0],args[1],args[2]);
    else if(!std::strcmp(name,"HeapAlloc")) result=heap_alloc(args[0],args[1],args[2]);
    else if(!std::strcmp(name,"HeapReAlloc")) result=heap_realloc(args[0],args[1],args[2],args[3]);
    else if(!std::strcmp(name,"HeapFree")) result=heap_free(args[0],args[1],args[2]);
    else if(!std::strcmp(name,"HeapSize")) result=heap_size(args[0],args[1],args[2]);
    else if(!std::strcmp(name,"HeapValidate")) result=heap_validate(args[0],args[1],args[2]);
    else if(!std::strcmp(name,"HeapDestroy")) result=heap_destroy(args[0]);
    else if(!std::strcmp(name,"GetProcessHeap")) {
        if(!process_heap) process_heap=heap_create(0,4096,0);
        result=process_heap;
    } else if(!std::strcmp(name,"GetLastError")) result=last_error;
    else if(!std::strcmp(name,"GetTickCount")) result=tick_count_from_elapsed(emscripten_get_now()-boot_epoch_ms);
    else if(!std::strcmp(name,"SetLastError")) { last_error=args[0]; has_result=false; }
    else if(!std::strcmp(name,"SetUnhandledExceptionFilter")) {
        // Registration stores a guest callback address; it does not invoke it.
        result=unhandled_exception_filter;unhandled_exception_filter=args[0];
    }
    else if(!std::strcmp(name,"GetCurrentThreadId") || !std::strcmp(name,"GetCurrentProcessId")) {
        result=1; // IDs of the one actual guest process and its one actual guest thread.
    } else if(!std::strcmp(name,"IsProcessorFeaturePresent")) {
        // The virtual CPU does not reproduce the Pentium FDIV precision erratum.
        // Other feature answers need a verified guest capability contract.
        if(args[0]) {
            dynamic_error="IsProcessorFeaturePresent unmodeled virtual CPU feature "+std::to_string(args[0]);
            guest::fault(5,guest::ip,dynamic_error.c_str());
        }
        result=0;
    } else if(!std::strcmp(name,"TlsAlloc")) {
        result=0xffffffffu;
        for(unsigned i=0;i<64;++i) if(!tls_used[i]) { tls_used[i]=true;tls_values[i]=0;result=i;break; }
        if(result==0xffffffffu) last_error=NOT_ENOUGH_MEMORY;
    } else if(!std::strcmp(name,"TlsGetValue")) {
        // Win32 validates the minimum 64-slot range, not its allocation bitmap.
        if(args[0]>=64) last_error=INVALID_PARAMETER;
        else { result=tls_values[args[0]];last_error=0; }
    } else if(!std::strcmp(name,"TlsSetValue")) {
        if(args[0]>=64) last_error=INVALID_PARAMETER;
        else { tls_values[args[0]]=args[1];result=1; }
    } else if(!std::strcmp(name,"TlsFree")) {
        if(args[0]>=64 || !tls_used[args[0]]) last_error=INVALID_PARAMETER;
        else { tls_used[args[0]]=false;tls_values[args[0]]=0;result=1; }
    } else {
        if(!guest::access(args[0],8,2)) return true;
        uint64_t ticks;
        if(!std::strcmp(name,"QueryPerformanceFrequency")) ticks=1000000;
        else if(!std::strcmp(name,"QueryPerformanceCounter")) ticks=uint64_t(emscripten_get_now()*1000.0);
        else { ticks=(uint64_t(emscripten_date_now())+11644473600000ull)*10000ull;has_result=false; }
        guest::wr(args[0],uint32_t(ticks),32); guest::wr(args[0]+4,uint32_t(ticks>>32),32); result=1;
    }
    if(guest::error) return true;
    next=guest::pop();
    if(guest::error) return true;
    guest::r[4]+=argc*4;
    if(has_result) guest::r[0]=result;
    return true;
}
} // namespace win32

extern "C" EMSCRIPTEN_KEEPALIVE void win32_reset(uint32_t executable_base) { win32::reset(executable_base); }
