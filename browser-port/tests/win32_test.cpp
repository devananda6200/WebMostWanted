#include "runtime/win32.hpp"
#include <cassert>
#include <cstdio>
#include <initializer_list>

constexpr uint32_t SP=0x00100800, DATA=0x00200000, RETURN=0x00401000;
static uint32_t tests=0;
static uint16_t observed_decode[256],observed_types[256];
static uint32_t invoke(const char* name,std::initializer_list<uint32_t> args={}) {
    guest::r[4]=SP; guest::wr(SP,RETURN,32);
    uint32_t p=SP+4; for(uint32_t value:args) { guest::wr(p,value,32);p+=4; }
    uint32_t next=0;
    assert(win32::dispatch(name,next)); assert(!guest::error);
    assert(next==RETURN); assert(guest::r[4]==p);
    return guest::r[0];
}
static void fresh() {
    ::reset(); win32::reset(0x00400000);
    assert(map_region(SP&~4095u,4096,3)); assert(map_region(DATA,8192,3));
    guest::ip=0x00401000;
}
static void version_contract() {
    fresh(); guest::wr(DATA,156,32); guest::wr(DATA+156,0xfeedbeef,32);
    assert(invoke("KERNEL32.dll!GetVersionExA",{DATA})==1);
    assert(guest::rd(DATA,32)==156); assert(guest::rd(DATA+4,32)==5);
    assert(guest::rd(DATA+8,32)==1); assert(guest::rd(DATA+12,32)==2600);
    assert(guest::rd(DATA+16,32)==2); assert(guest::rd(DATA+148,16)==3);
    assert(guest::rd(DATA+154,8)==1); assert(guest::rd(DATA+156,32)==0xfeedbeef);
    assert(!std::strcmp(reinterpret_cast<char*>(guest::memory+DATA+20),"Service Pack 3"));
    guest::wr(DATA,7,32); guest::wr(DATA+4,0x12345678,32);
    assert(invoke("GetVersionExA",{DATA})==0); assert(guest::rd(DATA+4,32)==0x12345678);
    assert(invoke("GetLastError")==win32::INVALID_PARAMETER);
    guest::wr(DATA,148,32); assert(invoke("GetVersionExA",{DATA})==1);
    assert(invoke("GetModuleHandleA",{0})==0x00400000);
    ++tests;
}
static void heap_contract() {
    fresh(); uint32_t heap=invoke("HeapCreate",{0,0,0}); assert(heap);
    uint32_t a=invoke("HeapAlloc",{heap,8,29}),b=invoke("HeapAlloc",{heap,0,17});
    assert(a && b && a!=b && !(a&7) && !(b&7));
    for(unsigned i=0;i<29;++i) assert(guest::memory[a+i]==0);
    assert(invoke("HeapSize",{heap,0,a})==29);
    guest::wr(a,0xaabbccdd,32);
    assert(invoke("HeapFree",{heap,0,a})==1);
    uint32_t reused=invoke("HeapAlloc",{heap,8,29});assert(reused==a);
    assert(guest::rd(reused,32)==0);
    assert(invoke("HeapFree",{heap,0,b})==1);
    assert(invoke("HeapFree",{heap,0,reused})==1);
    assert(invoke("HeapFree",{heap,0,reused})==0);
    assert(invoke("HeapFree",{heap,0,0})==1);
    invoke("SetLastError",{1234});
    assert(invoke("HeapAlloc",{heap,0,0xffffffff})==0);
    assert(invoke("GetLastError")==1234);
    assert(invoke("HeapSize",{heap,0,0x11223344})==0xffffffff);
    assert(invoke("GetLastError")==1234);
    assert(invoke("HeapDestroy",{heap})==1);
    assert(!guest::permissions[a/guest::PAGE]);
    assert(invoke("HeapFree",{heap,0,0})==0);
    ++tests;
}
static void heap_growth_and_limits() {
    fresh(); uint32_t fixed=invoke("HeapCreate",{1,0,8192});assert(fixed);
    uint32_t a=invoke("HeapAlloc",{fixed,0,4096}),b=invoke("HeapAlloc",{fixed,0,4096});
    assert(a && b && a!=b); assert(!invoke("HeapAlloc",{fixed,0,8}));
    assert(invoke("HeapFree",{fixed,0,a}));assert(invoke("HeapFree",{fixed,0,b}));
    assert(invoke("HeapAlloc",{fixed,0,8192})==a);
    uint32_t second=invoke("HeapCreate",{0,0,0});assert(second && second!=fixed);
    uint32_t c=invoke("HeapAlloc",{second,0,100000});assert(c);
    assert(invoke("HeapSize",{second,0,c})==100000);
    uint32_t process=invoke("GetProcessHeap");assert(process);
    assert(invoke("GetProcessHeap")==process);assert(!invoke("HeapDestroy",{process}));
    win32::reset(0x00400000);
    assert(!guest::permissions[a/guest::PAGE] && !guest::permissions[c/guest::PAGE]);
    ++tests;
}
static void tls_contract() {
    fresh(); uint32_t first=invoke("TlsAlloc");assert(first==0);
    invoke("SetLastError",{123});assert(invoke("TlsGetValue",{first})==0);
    assert(invoke("GetLastError")==0);
    assert(invoke("TlsSetValue",{first,0xdeadbeef}));assert(invoke("TlsGetValue",{first})==0xdeadbeef);
    assert(invoke("TlsFree",{first})); assert(invoke("TlsAlloc")==first);
    assert(invoke("TlsGetValue",{first})==0);
    for(unsigned i=1;i<64;++i) assert(invoke("TlsAlloc")==i);
    assert(invoke("TlsAlloc")==0xffffffff);assert(invoke("GetLastError")==8);
    assert(!invoke("TlsGetValue",{64}));assert(invoke("GetLastError")==87);
    assert(invoke("GetCurrentThreadId")==1);assert(invoke("GetCurrentProcessId")==1);
    ++tests;
}
static uint64_t read64(uint32_t p) { return guest::rd(p,32)|(uint64_t(guest::rd(p+4,32))<<32); }
static void clock_contract() {
    fresh();assert(invoke("QueryPerformanceFrequency",{DATA}));assert(read64(DATA)==1000000);
    assert(invoke("QueryPerformanceCounter",{DATA}));uint64_t before=read64(DATA);
    assert(invoke("QueryPerformanceCounter",{DATA}));assert(read64(DATA)>=before);
    invoke("GetSystemTimeAsFileTime",{DATA});
    uint64_t now=read64(DATA);assert(now>116444736000000000ull);
    uint64_t expected=(uint64_t(emscripten_date_now())+11644473600000ull)*10000ull;
    assert(now<=expected && expected-now<10000000ull);
    ++tests;
}
static void failures_do_not_succeed() {
    fresh(); uint32_t next=123;
    assert(!win32::dispatch("WS2_32.dll!GetLastError",next));assert(next==123);
    assert(!win32::dispatch("KERNEL32.dll!LoadLibraryA",next));assert(next==123);
    assert(win32::register_module("kernel32.dll",0x71000000));
    std::memcpy(guest::memory+DATA,"RequiredButUnimplemented",25);
    guest::r[4]=SP;guest::wr(SP,RETURN,32);guest::wr(SP+4,0x71000000,32);guest::wr(SP+8,DATA,32);
    assert(win32::dispatch("GetProcAddress",next));assert(guest::error==5);
    assert(guest::r[4]==SP && next==123);
    fresh();guest::r[4]=SP;guest::wr(SP,RETURN,32);guest::wr(SP+4,DATA+8192-4,32);
    guest::wr(DATA+8192-4,156,32);
    assert(win32::dispatch("GetVersionExA",next));assert(guest::error==1);
    uint32_t unchanged;std::memcpy(&unchanged,guest::memory+DATA+8192-4,4);
    assert(guest::r[4]==SP && unchanged==156);
    fresh();guest::r[4]=SP;guest::wr(SP,RETURN,32);
    guest::wr(SP+4,4,32);guest::wr(SP+8,0,32);guest::wr(SP+12,0,32);
    assert(win32::dispatch("HeapCreate",next));assert(guest::error==5);
    assert(guest::r[4]==SP);
    fresh();assert(map_region(win32::ARENA_BEGIN,4096,5));
    uint32_t heap=invoke("HeapCreate",{0,0,0});assert(heap);
    uint32_t address=invoke("HeapAlloc",{heap,0,8});assert(address>=win32::ARENA_BEGIN+4096);
    assert(guest::permissions[win32::ARENA_BEGIN/4096]==5);
    ++tests;
}
static void text_at(uint32_t address,const char* text) {
    std::memcpy(guest::memory+address,text,std::strlen(text)+1);
}
static void module_registry_contract() {
    fresh();constexpr uint32_t HANDLE=0x71000000,GATEWAY=0x03101000;
    assert(win32::supports("GetProcAddress"));assert(win32::supports("KERNEL32.dll!HeapAlloc"));
    assert(!win32::supports("WS2_32.dll!HeapAlloc"));assert(!win32::supports("FlsAlloc"));
    assert(!win32::register_module("d3d9.dll",HANDLE));
    assert(win32::register_module("C:\\Windows\\System32\\KERNEL32.DLL",HANDLE));
    assert(win32::register_module("C:\\Windows\\System32\\KERNEL32.DLL",HANDLE));
    assert(!win32::register_module("C:\\Windows\\System32\\KERNEL32.DLL",HANDLE+1));
    for(const char* name:{"kernel32.dll","KeRnEl32","C:\\WINDOWS\\system32\\kernel32.dll"}) {
        text_at(DATA,name);assert(invoke("GetModuleHandleA",{DATA})==HANDLE);
    }
    text_at(DATA,"X:\\unregistered\\kernel32.dll");assert(!invoke("GetModuleHandleA",{DATA}));
    assert(invoke("GetLastError")==126);
    text_at(DATA,"not-present.dll");assert(!invoke("GetModuleHandleA",{DATA}));assert(invoke("GetLastError")==126);
    assert(win32::register_export(HANDLE,"GetLastError",GATEWAY));
    assert(!win32::register_export(HANDLE,"GetLastError",GATEWAY+16));
    assert(!win32::register_export(HANDLE,"FlsAlloc",GATEWAY+16));
    text_at(DATA,"GetLastError");assert(invoke("GetProcAddress",{HANDLE,DATA})==GATEWAY);
    invoke("SetLastError",{4321});assert(invoke("GetLastError")==4321);
    for(const char* name:{"FlsAlloc","FlsFree","FlsGetValue","FlsSetValue"}) {
        text_at(DATA,name);assert(!invoke("GetProcAddress",{HANDLE,DATA}));assert(invoke("GetLastError")==127);
    }
    assert(!invoke("GetProcAddress",{HANDLE+1,DATA}));assert(invoke("GetLastError")==6);
    fresh();guest::r[4]=SP;guest::wr(SP,RETURN,32);guest::wr(SP+4,DATA+8192-1,32);
    guest::wr(DATA+8192-1,'x',8);uint32_t next=123;
    assert(win32::dispatch("GetModuleHandleA",next));assert(guest::error==1 && guest::r[4]==SP && next==123);
    ++tests;
}
static void faulting_critical(const char* name,uint32_t address) {
    guest::r[4]=SP;guest::wr(SP,RETURN,32);guest::wr(SP+4,address,32);uint32_t next=123;
    assert(win32::dispatch(name,next));assert(guest::error==5);
    assert(next==123 && guest::r[4]==SP);
}
static void critical_section_contract() {
    fresh();assert(invoke("InitializeCriticalSectionAndSpinCount",{DATA,4000}));
    assert(guest::rd(DATA+4,32)==0xffffffff && guest::rd(DATA+20,32)==0);
    invoke("EnterCriticalSection",{DATA});invoke("EnterCriticalSection",{DATA});
    assert(invoke("TryEnterCriticalSection",{DATA}));
    assert(guest::rd(DATA+8,32)==3 && guest::rd(DATA+12,32)==1);
    invoke("LeaveCriticalSection",{DATA});invoke("LeaveCriticalSection",{DATA});invoke("LeaveCriticalSection",{DATA});
    assert(guest::rd(DATA+8,32)==0 && guest::rd(DATA+12,32)==0);
    invoke("DeleteCriticalSection",{DATA});invoke("InitializeCriticalSection",{DATA});invoke("DeleteCriticalSection",{DATA});
    fresh();faulting_critical("EnterCriticalSection",DATA);
    fresh();invoke("InitializeCriticalSection",{DATA});faulting_critical("LeaveCriticalSection",DATA);
    fresh();invoke("InitializeCriticalSection",{DATA});faulting_critical("InitializeCriticalSection",DATA);
    fresh();invoke("InitializeCriticalSection",{DATA});invoke("EnterCriticalSection",{DATA});faulting_critical("DeleteCriticalSection",DATA);
    assert(win32::find_critical(DATA)->recursion==1);
    fresh();invoke("InitializeCriticalSection",{DATA});guest::wr(DATA+8,7,32);faulting_critical("EnterCriticalSection",DATA);
    fresh();invoke("InitializeCriticalSection",{DATA});faulting_critical("InitializeCriticalSection",DATA+8);
    // Inject another-owner state only to test the unsupported scheduling barrier.
    fresh();invoke("InitializeCriticalSection",{DATA});auto* state=win32::find_critical(DATA);
    state->owner=2;state->recursion=1;win32::store_critical(*state);
    assert(!invoke("TryEnterCriticalSection",{DATA}));faulting_critical("EnterCriticalSection",DATA);
    ++tests;
}
static void startup_information_contract() {
    fresh(); std::memset(guest::memory+DATA,0xcc,72);guest::r[0]=0x11223344;
    assert(invoke("GetStartupInfoA",{DATA})==0x11223344);
    assert(guest::rd(DATA,32)==68 && guest::rd(DATA+68,32)==0xcccccccc);
    for(unsigned i=4;i<68;++i) assert(guest::memory[DATA+i]==0);
    for(uint32_t selector:{uint32_t(-10),uint32_t(-11),uint32_t(-12)}) {
        invoke("SetLastError",{4321});assert(!invoke("GetStdHandle",{selector}));
        assert(invoke("GetLastError")==4321);
    }
    assert(invoke("GetStdHandle",{0})==0xffffffffu);assert(invoke("GetLastError")==87);
    assert(!invoke("GetFileType",{0}));assert(invoke("GetLastError")==6);
    assert(!invoke("GetFileType",{0xffffffffu}));assert(invoke("GetLastError")==6);
    assert(invoke("SetHandleCount",{512})==512);
    fresh();guest::r[4]=SP;guest::wr(SP,RETURN,32);guest::wr(SP+4,DATA+8192-64,32);
    guest::wr(DATA+8192-64,0xaabbccdd,32);uint32_t next=123;
    assert(win32::dispatch("GetStartupInfoA",next));assert(guest::error==1 && next==123 && guest::r[4]==SP);
    uint32_t unchanged;std::memcpy(&unchanged,guest::memory+DATA+8192-64,4);assert(unchanged==0xaabbccdd);
    ++tests;
}
static void command_line_and_module_path_contract() {
    fresh();uint32_t command=invoke("GetCommandLineA");assert(command);
    assert(invoke("GetCommandLineA")==command);
    assert(guest::permissions[command/guest::PAGE]==1);
    assert(!std::strcmp(reinterpret_cast<char*>(guest::memory+command),"\"C:\\NFS\\speed.exe\""));
    constexpr uint32_t length=sizeof(win32::EXECUTABLE_PATH)-1;
    std::memset(guest::memory+DATA,0xcc,100);
    assert(invoke("GetModuleFileNameA",{0,DATA,100})==length);
    assert(!std::strcmp(reinterpret_cast<char*>(guest::memory+DATA),win32::EXECUTABLE_PATH));
    assert(guest::memory[DATA+length+1]==0xcc);
    assert(invoke("GetModuleFileNameA",{0x00400000,DATA,100})==length);
    std::memset(guest::memory+DATA,0xcc,100);invoke("SetLastError",{4321});
    assert(invoke("GetModuleFileNameA",{0,DATA,4})==4);
    assert(!std::memcmp(guest::memory+DATA,"C:\\N",4));assert(guest::memory[DATA+4]==0xcc);
    assert(invoke("GetLastError")==0);
    assert(!invoke("GetModuleFileNameA",{0,0,0}));assert(invoke("GetLastError")==0);
    assert(!invoke("GetModuleFileNameA",{0x1234,DATA,100}));assert(invoke("GetLastError")==126);
    guest::wr(command,'X',8);assert(guest::error==1 && guest::memory[command]=='"');
    fresh();guest::r[4]=SP;guest::wr(SP,RETURN,32);guest::wr(SP+4,0,32);
    guest::wr(SP+8,DATA+8192-2,32);guest::wr(SP+12,100,32);uint32_t next=123;
    guest::wr(DATA+8192-2,0xabcd,16);
    assert(win32::dispatch("GetModuleFileNameA",next));assert(guest::error==1 && next==123 && guest::r[4]==SP);
    assert(guest::memory[DATA+8192-2]==0xcd);
    ++tests;
}
static void environment_block_contract() {
    fresh();uint32_t wide=invoke("GetEnvironmentStringsW"),ansi=invoke("GetEnvironmentStringsA");
    uint32_t legacy=invoke("GetEnvironmentStrings");assert(wide && ansi && legacy);
    assert(wide!=ansi && wide!=legacy && ansi!=legacy);
    assert(guest::rd(wide,32)==0 && guest::rd(ansi,16)==0 && guest::rd(legacy,16)==0);
    assert(guest::permissions[wide/guest::PAGE]==1 && guest::permissions[ansi/guest::PAGE]==1);
    assert(!invoke("FreeEnvironmentStringsA",{wide}));assert(invoke("GetLastError")==87);
    assert(guest::permissions[wide/guest::PAGE]==1);
    assert(invoke("FreeEnvironmentStringsW",{wide}));assert(!guest::permissions[wide/guest::PAGE]);
    assert(!invoke("FreeEnvironmentStringsW",{wide}));assert(invoke("GetLastError")==87);
    assert(invoke("FreeEnvironmentStringsA",{ansi}));assert(invoke("FreeEnvironmentStringsA",{legacy}));
    uint32_t command=invoke("GetCommandLineA");assert(!invoke("FreeEnvironmentStringsA",{command}));
    assert(guest::permissions[command/guest::PAGE]==1);
    assert(!invoke("FreeEnvironmentStringsW",{0}));assert(!invoke("FreeEnvironmentStringsA",{DATA}));
    for(uint32_t i=1;i<win32::PROCESS_PAGES;++i) assert(invoke("GetEnvironmentStringsW"));
    assert(!invoke("GetEnvironmentStringsW"));assert(invoke("GetLastError")==8);
    win32::reset(0x00400000);
    for(uint32_t p=win32::PROCESS_BEGIN/guest::PAGE;p<win32::PROCESS_END/guest::PAGE;++p)
        assert(!guest::permissions[p]);
    assert(map_region(win32::PROCESS_BEGIN,guest::PAGE,5));
    assert(invoke("GetCommandLineA")==win32::PROCESS_BEGIN+guest::PAGE);
    assert(guest::permissions[win32::PROCESS_BEGIN/guest::PAGE]==5);
    ++tests;
}
static void wide_at(uint32_t address,std::initializer_list<uint16_t> text) {
    for(uint16_t character:text) { guest::wr(address,character,16);address+=2; }
}
static void encoding_information_contract() {
    fresh();assert(invoke("GetACP")==1252);
    std::memset(guest::memory+DATA,0xcc,24);
    assert(invoke("GetCPInfo",{0,DATA}));assert(guest::rd(DATA,32)==1);
    assert(guest::memory[DATA+4]=='?');
    for(unsigned i=5;i<18;++i) assert(!guest::memory[DATA+i]);
    assert(guest::rd(DATA+20,32)==0xcccccccc);
    assert(invoke("GetCPInfo",{1252,DATA}));
    assert(!invoke("GetCPInfo",{1252,0}));assert(invoke("GetLastError")==87);
    ++tests;
}
static void wide_conversion_contract() {
    fresh();constexpr uint32_t OUT=DATA+256,USED=DATA+512,DEFAULT=DATA+516;
    uint32_t env=invoke("GetEnvironmentStringsW");
    // The actual observed startup call: one explicit UTF-16 NUL, size query.
    assert(invoke("WideCharToMultiByte",{0,0,env,1,0,0,0,0})==1);
    wide_at(DATA,{'A',0x20ac,0x00e9,0});guest::wr(USED,99,32);
    invoke("SetLastError",{777});
    assert(invoke("WideCharToMultiByte",{1252,0,DATA,0xffffffffu,0xdeadbeef,0,0,USED})==4);
    assert(guest::rd(USED,32)==0 && invoke("GetLastError")==777);
    std::memset(guest::memory+OUT,0xcc,8);
    assert(invoke("WideCharToMultiByte",{0,0,DATA,0xffffffffu,OUT,8,0,USED})==4);
    const uint8_t expected[]={'A',0x80,0xe9,0,0xcc};
    assert(!std::memcmp(guest::memory+OUT,expected,sizeof(expected)));
    assert(guest::rd(USED,32)==0);
    wide_at(DATA,{'A',0,'B'});
    assert(invoke("WideCharToMultiByte",{0,0,DATA,3,OUT,8,0,USED})==3);
    assert(guest::memory[OUT]=='A' && !guest::memory[OUT+1] && guest::memory[OUT+2]=='B');
    wide_at(DATA,{0x2603,'A',0});guest::wr(DEFAULT,'!',8);
    assert(invoke("WideCharToMultiByte",{1252,0x400,DATA,2,OUT,8,DEFAULT,USED})==2);
    assert(guest::memory[OUT]=='!' && guest::memory[OUT+1]=='A' && guest::rd(USED,32)==1);
    assert(invoke("WideCharToMultiByte",{1252,0x400,DATA,2,0,0,0,USED})==2);
    assert(guest::rd(USED,32)==1);
    wide_at(DATA,{'?',0x0081,0});
    assert(invoke("WideCharToMultiByte",{1252,0x400,DATA,2,OUT,8,0,USED})==2);
    assert(guest::memory[OUT]=='?' && guest::memory[OUT+1]==0x81 && !guest::rd(USED,32));
    wide_at(DATA,{'A','B',0x2603});std::memset(guest::memory+OUT,0xcc,8);
    assert(!invoke("WideCharToMultiByte",{1252,0x400,DATA,3,OUT,2,0,USED}));
    assert(invoke("GetLastError")==122 && !guest::rd(USED,32));
    assert(guest::memory[OUT]=='A' && guest::memory[OUT+1]=='B' && guest::memory[OUT+2]==0xcc);
    wide_at(DATA,{0x2603,'A','B'});
    assert(!invoke("WideCharToMultiByte",{1252,0x400,DATA,3,OUT,2,0,USED}));
    assert(guest::memory[OUT]=='?' && guest::memory[OUT+1]=='A' && guest::rd(USED,32)==1);
    fresh();for(unsigned i=0;i<2048;++i) guest::wr(DATA+i*2,'A',16);
    assert(invoke("WideCharToMultiByte",{0,0,DATA,2048,DATA+4096,2048,0,0})==2048);
    for(unsigned i=0;i<2048;++i) assert(guest::memory[DATA+4096+i]=='A');
    ++tests;
}
static void wide_conversion_failures() {
    fresh();wide_at(DATA,{'A',0});constexpr uint32_t OUT=DATA+256;
    assert(!invoke("WideCharToMultiByte",{0,0,DATA,0,OUT,8,0,0}));assert(invoke("GetLastError")==87);
    assert(!invoke("WideCharToMultiByte",{0,0,DATA,1,OUT,0xffffffffu,0,0}));assert(invoke("GetLastError")==87);
    assert(!invoke("WideCharToMultiByte",{0,0,0,1,OUT,8,0,0}));assert(invoke("GetLastError")==87);
    assert(!invoke("WideCharToMultiByte",{0,0,DATA,1,0,8,0,0}));assert(invoke("GetLastError")==122);
    assert(!invoke("WideCharToMultiByte",{0,0,DATA,1,DATA,8,0,0}));assert(invoke("GetLastError")==87);
    const uint32_t failures[][4]={
        {65001,0,1,'A'},{1252,0x200,1,'A'},{1252,0,0xfffffffeu,'A'},
        {1252,0,1,0x100},{1252,0x400,1,0xd800}};
    for(const auto& item:failures) {
        fresh();guest::wr(DATA,item[3],16);guest::r[4]=SP;guest::wr(SP,RETURN,32);
        uint32_t a[8]={item[0],item[1],DATA,item[2],OUT,8,0,0};
        for(unsigned i=0;i<8;++i) guest::wr(SP+4+i*4,a[i],32);
        guest::wr(OUT,0xcccccccc,32);uint32_t next=123;
        assert(win32::dispatch("WideCharToMultiByte",next));assert(guest::error==5);
        assert(next==123 && guest::r[4]==SP && guest::memory[OUT]==0xcc);
    }
    fresh();guest::wr(DATA+8190,'A',16);guest::r[4]=SP;guest::wr(SP,RETURN,32);
    uint32_t a[8]={0,0,DATA+8190,2,OUT,8,0,0};
    for(unsigned i=0;i<8;++i) guest::wr(SP+4+i*4,a[i],32);
    guest::wr(OUT,0xcccccccc,32);uint32_t next=123;
    assert(win32::dispatch("WideCharToMultiByte",next));assert(guest::error==1 && next==123);
    assert(guest::memory[OUT]==0xcc && guest::r[4]==SP);
    ++tests;
}
static void multibyte_conversion_contract() {
    fresh();constexpr uint32_t OUT=DATA+512;
    const uint8_t input[]={'A',0x80,0xe9,0};std::memcpy(guest::memory+DATA,input,sizeof(input));
    invoke("SetLastError",{777});
    assert(invoke("MultiByteToWideChar",{0,0,DATA,0xffffffffu,0xdeadbeef,0})==4);
    assert(invoke("GetLastError")==777);
    std::memset(guest::memory+OUT,0xcc,16);
    assert(invoke("MultiByteToWideChar",{1252,1,DATA,0xffffffffu,OUT,8})==4);
    const uint16_t expected[]={'A',0x20ac,0xe9,0,0xcccc};
    assert(!std::memcmp(guest::memory+OUT,expected,sizeof(expected)));
    guest::wr(DATA+1,0,8);
    assert(invoke("MultiByteToWideChar",{0,8,DATA,3,OUT,8})==3);
    assert(guest::rd(OUT+2,16)==0 && guest::rd(OUT+4,16)==0xe9);
    std::memcpy(guest::memory+DATA,"ABC",3);std::memset(guest::memory+OUT,0xcc,8);
    assert(!invoke("MultiByteToWideChar",{0,0,DATA,3,OUT,2}));assert(invoke("GetLastError")==122);
    assert(guest::rd(OUT,16)=='A' && guest::rd(OUT+2,16)=='B' && guest::rd(OUT+4,16)==0xcccc);
    assert(!invoke("MultiByteToWideChar",{0,0,DATA,0,OUT,8}));assert(invoke("GetLastError")==87);
    assert(!invoke("MultiByteToWideChar",{0,0,DATA,1,OUT,0xffffffffu}));assert(invoke("GetLastError")==87);
    assert(!invoke("MultiByteToWideChar",{0,0,DATA,1,DATA,8}));assert(invoke("GetLastError")==87);
    assert(!invoke("MultiByteToWideChar",{0,0,DATA,1,0,8}));assert(invoke("GetLastError")==122);
    ++tests;
}
static void classification_contract() {
    fresh();constexpr uint32_t OUT=DATA+512;
    wide_at(DATA,{0});std::memset(guest::memory+OUT,0xcc,64);
    assert(invoke("GetStringTypeW",{1,DATA,1,OUT}));
    assert(guest::rd(OUT,16)==0x220 && guest::rd(OUT+2,16)==0xcccc);
    wide_at(DATA,{'A','f','G','9',' ','\t','\n','!',0x20ac,0xe9,0xa0,0});
    const uint16_t expected[]={0x381,0x382,0x301,0x284,0x248,0x268,0x228,0x210,0x200,0x302,0x248,0x220};
    invoke("SetLastError",{777});
    assert(invoke("GetStringTypeW",{1,DATA,0xffffffffu,OUT}));assert(invoke("GetLastError")==777);
    assert(!std::memcmp(guest::memory+OUT,expected,sizeof(expected)));
    assert(invoke("GetStringTypeW",{1,DATA,0xfffffffeu,OUT}));
    assert(!std::memcmp(guest::memory+OUT,expected,sizeof(expected)));
    assert(!invoke("GetStringTypeW",{1,DATA,0,OUT}));assert(invoke("GetLastError")==87);
    assert(!invoke("GetStringTypeW",{1,DATA,1,DATA}));assert(invoke("GetLastError")==87);
    assert(!invoke("GetStringTypeW",{1,0,1,OUT}));assert(invoke("GetLastError")==87);
    ++tests;
}
static void nls_repertoire_contract() {
    fresh();for(unsigned i=0;i<256;++i) guest::wr(DATA+i,i,8);
    assert(invoke("MultiByteToWideChar",{1252,8,DATA,256,DATA+512,256})==256);
    std::memcpy(observed_decode,guest::memory+DATA+512,sizeof(observed_decode));
    assert(invoke("GetStringTypeW",{1,DATA+512,256,DATA+1024}));
    std::memcpy(observed_types,guest::memory+DATA+1024,sizeof(observed_types));
    assert(invoke("WideCharToMultiByte",{1252,0x400,DATA+512,256,DATA+1536,256,0,DATA+2048})==256);
    for(unsigned i=0;i<256;++i) assert(guest::memory[DATA+1536+i]==i);
    assert(!guest::rd(DATA+2048,32));
    ++tests;
}
static void classification_and_inverse_failures() {
    const uint32_t classifications[][2]={{2,'A'},{1,0x2603},{1,0xd800}};
    for(const auto& c:classifications) {
        fresh();wide_at(DATA,{uint16_t(c[1])});guest::r[4]=SP;guest::wr(SP,RETURN,32);
        const uint32_t a[4]={c[0],DATA,1,DATA+512};
        for(unsigned i=0;i<4;++i) guest::wr(SP+4+i*4,a[i],32);
        guest::wr(DATA+512,0xcccccccc,32);uint32_t next=123;
        assert(win32::dispatch("GetStringTypeW",next));assert(guest::error==5 && next==123 && guest::r[4]==SP);
        assert(guest::memory[DATA+512]==0xcc);
    }
    fresh();wide_at(DATA,{'A','B'});guest::r[4]=SP;guest::wr(SP,RETURN,32);
    const uint32_t bounds[4]={1,DATA,2,DATA+8190};
    for(unsigned i=0;i<4;++i) guest::wr(SP+4+i*4,bounds[i],32);
    guest::wr(DATA+8190,0xcccc,16);uint32_t next=123;
    assert(win32::dispatch("GetStringTypeW",next));assert(guest::error==1 && next==123);
    assert(guest::memory[DATA+8190]==0xcc);
    fresh();guest::wr(DATA,'A',8);guest::r[4]=SP;guest::wr(SP,RETURN,32);
    const uint32_t flags[6]={1252,2,DATA,1,DATA+512,8};
    for(unsigned i=0;i<6;++i) guest::wr(SP+4+i*4,flags[i],32);
    assert(win32::dispatch("MultiByteToWideChar",next));assert(guest::error==5 && next==123);
    ++tests;
}
int main() {
    version_contract();heap_contract();heap_growth_and_limits();tls_contract();clock_contract();failures_do_not_succeed();
    module_registry_contract();critical_section_contract();startup_information_contract();
    command_line_and_module_path_contract();environment_block_contract();
    encoding_information_contract();wide_conversion_contract();wide_conversion_failures();
    multibyte_conversion_contract();classification_contract();nls_repertoire_contract();classification_and_inverse_failures();
    std::printf("{\"status\":\"passed\",\"groups\":%u,\"scope\":\"Win32 contract tests in Wasm\",\"cp1252_decode\":[",tests);
    for(unsigned i=0;i<256;++i) std::printf("%s%u",i?",":"",observed_decode[i]);
    std::printf("],\"ctype1\":[");
    for(unsigned i=0;i<256;++i) std::printf("%s%u",i?",":"",observed_types[i]);
    std::printf("]}\n");
}
