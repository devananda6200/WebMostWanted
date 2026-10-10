# Implemented Win32 contracts

`runtime/win32.hpp` is a narrow browser-local implementation for the observed
startup imports. It is not a complete operating system or a promise that
initialization reaches a menu. All unknown imports remain explicit barriers.

Call `win32::reset(actual_pe_image_base)` after resetting guest memory. The
exported `_win32_reset(base)` provides the same operation to the browser loader.
`win32::dispatch("KERNEL32.dll!Function", next)` returns false for unknown
imports. A recognized unsupported parameter mode sets a guest fault. Successful
calls use the guest stdcall stack and preserve nonvolatile registers; void APIs
leave EAX unspecified by retaining its old value.
The dispatcher is explicitly kept out of line so hundreds of generated import
gateways call one shared implementation instead of duplicating its API branches.

After each reset, generated loader code explicitly supplies the replacement
module and the actual translated dispatch gateways:

```cpp
win32::register_module("kernel32.dll", kernel32_handle);
if (win32::supports("InitializeCriticalSectionAndSpinCount")) {
    win32::register_export(kernel32_handle,
        "InitializeCriticalSectionAndSpinCount", actual_gateway_address);
}
```

`supports(name)` accepts a bare API name or a kernel32-qualified name and is
derived from the same signature table used by dispatch. Registration accepts
only implemented APIs of the kernel32 replacement. It does not create code at
an address: the generator must emit the corresponding dispatch case and map
its gateway executable. Reset removes registrations to prevent stale targets.

## Profile, memory, and implemented services

- `GetVersionExA` validates a 148-byte or 156-byte ANSI version structure and its
  complete output range. It returns an explicitly declared virtual Windows XP
  SP3 workstation profile: 5.1, build 2600, NT platform, service pack 3. This
  describes the compatibility profile, not the host operating system or the
  availability of every XP feature. Invalid sizes return failure. [Contract and compatibility-mode behavior](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexa)
- `GetStartupInfoA` writes the verified 68-byte x86 structure for the declared
  browser GUI process: no inherited console handles, reserved CRT data, or
  startup flags. `GetStdHandle` consequently returns NULL for its three valid
  selectors and an error for invalid selectors. `GetFileType` reports an invalid
  handle for NULL/-1; other handles stop until a guest file table exists.
  `SetHandleCount` returns its request unchanged under the NT-family no-op
  contract. These do not create a console or implement file I/O.
  [Startup structure](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa), [Standard handles](https://learn.microsoft.com/en-us/windows/console/getstdhandle), [File types](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype), [Handle-count contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-sethandlecount)
- `GetCommandLineA` returns an actual immutable guest string containing
  `"C:\NFS\speed.exe"` without arguments. `GetModuleFileNameA` recognizes NULL
  and the audited image handle and copies the virtual path `C:\NFS\speed.exe`.
  This is the declared virtual guest executable name; the corresponding guest
  filesystem mount is not yet implemented. The declared XP truncation
  contract copies exactly `nSize` bytes without a terminator, returns `nSize`,
  and reports success; size zero returns zero without writing. Unregistered
  modules report error 126; a registered replacement DLL without a filesystem
  path faults. All actual output bytes are validated before writing.
  [Command-line lifetime](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinea), [Module filename and XP behavior](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamea)
- `GetEnvironmentStringsW`, `GetEnvironmentStringsA`, and this executable's
  legacy `GetEnvironmentStrings` ANSI import return owned read-only double-NUL
  blocks. This virtual process begins with an explicitly empty environment;
  it does not inherit the host environment. The matching A/W free releases the
  page; mismatched, duplicate, and foreign frees fail. Command-line and
  environment storage use at most 60 pages (240 KiB) in
  `0x02510000..0x02600000`, separate from the TEB and allocation arena. Existing
  mappings are preserved and allocation exhaustion fails. Environment mutation
  and nonempty environment encoding remain unsupported.
  [Environment block contract](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentstringsw), [Matching free](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-freeenvironmentstringsa)
- `GetACP` declares Windows-1252 for this guest. `GetCPInfo` accepts CP_ACP (0)
  and 1252 and writes single-byte metadata with `?` as its default and no lead
  bytes. `WideCharToMultiByte` handles the exact CP1252 repertoire, positive
  UTF-16 lengths including embedded NULs, and -1 terminated strings including
  their terminator. A zero output capacity queries the required size. With
  `WC_NO_BEST_FIT_CHARS`, unmapped BMP characters use the supplied/default byte
  and report its use; with flags zero, an unmapped character faults because
  the full Windows best-fit table is not implemented. Other code pages, flags,
  surrogate conversion, and undocumented negative lengths fault explicitly.
  Invalid parameters fail; unmapped guest buffers fault before writing. A short
  valid output buffer receives its converted prefix and error 122. Conversion
  has a 32,768 UTF-16-unit bound and uses a temporary bounded output vector.
  [Conversion contract](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte), [Code-page information](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getcpinfo), [Microsoft CP1252 mapping data](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WindowsBestFit/bestfit1252.txt)
- `MultiByteToWideChar` provides the inverse Windows-1252 mapping for every byte,
  including the five control slots. It supports default/precomposed mode and
  strict input checking; every byte in this repertoire has a mapping. Positive
  counts preserve embedded NULs; -1 includes the terminator. Queries report
  UTF-16 units, output sizes are in units rather than bytes, and insufficient
  buffers receive the converted prefix before error 122. Other code pages,
  decomposition/glyph flags and undocumented negative lengths fault. Input is
  limited to 32,768 bytes and all output is checked before writing.
  [Reverse-conversion contract](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar)
- `GetStringTypeW` supports CT_CTYPE1 for the 256 Unicode characters of the
  CP1252 repertoire. Each output is an actual 16-bit classification mask. The
  pinned table was measured against isolated calls to the installed Windows
  system API; all 256 masks are checked against that reference by the Wasm
  test runner. Positive counts include any explicitly supplied NULs; any
  negative count includes a terminating NUL, as documented. Zero length,
  NULL pointers and identical input/output pointers fail. Unsupported types,
  characters, unmapped output, or inputs exceeding 32,768 units stop with
  diagnostics. This restricted table agrees with the measured current host;
  equivalence to every historical XP classification is unverified.
  [Classification contract and bit values](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-getstringtypew)
- `GetModuleHandleA(NULL)` returns the configured executable image base. Named
  queries inspect explicitly registered replacement modules; absent modules
  return NULL with error 126. Matching is ASCII case insensitive and appends
  `.dll` when no extension is supplied. A basename query matches a registered
  full name; a full-path query requires that exact registered path (case aside).
  This registry does not load DLLs, search the host filesystem, or normalize
  drive aliases/dot-segment paths. Missing image-base configuration faults.
  [Module-handle contract](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)
- `GetProcAddress` returns an exact-case registered gateway. `FlsAlloc`,
  `FlsFree`, `FlsGetValue`, and `FlsSetValue` return NULL/error 127 because they
  are absent from this XP client profile. Every other unresolved requested
  export faults with its name; ordinal lookup also faults. This prevents an
  unimplemented required API from masquerading as an optional missing API.
  Guest strings have checked memory access and explicit length bounds.
  [Lookup contract](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress), [FLS client availability](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc)
- `HeapCreate`, `GetProcessHeap`, `HeapAlloc`, `HeapFree`, `HeapSize`, and
  `HeapDestroy` maintain actual guest allocations in the bounded 9 MiB range
  `0x02600000..0x02f00000`. Page ownership is checked before mapping; existing
  mappings are preserved. Allocations are eight-byte aligned, stable until
  freed, reused through splitting/coalescing, and zeroed when requested.
  Fixed heap limits, invalid handles, and exhaustion produce failure. The
  allocator commits chunks from this arena; it does not reproduce the Windows
  heap's internal bookkeeping or virtual-memory reservation layout.
  [HeapCreate](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate), [HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)
- Heap allocation and size failures preserve last error, as documented.
  HeapFree accepts NULL and reports invalid/double frees without inventing
  success. Executable heaps and exception-generating allocation modes fault
  until generated-code handling and guest SEH exist. HeapReAlloc, HeapValidate,
  HeapLock, and HeapUnlock remain unsupported.
  [HeapFree](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree), [HeapSize](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapsize)
- `TlsAlloc`, `TlsFree`, `TlsGetValue`, and `TlsSetValue` manage 64 slots for the
  one actual guest thread. Slots initialize to zero; exhaustion fails.
  TlsGetValue clears last error on successful retrieval, including zero.
  `GetLastError`/`SetLastError` retain that thread's error value. IDs returned
  by `GetCurrentProcessId` and `GetCurrentThreadId` identify this guest process
  and thread, both currently 1. Guest thread creation remains unsupported.
  [TlsAlloc](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsalloc), [TlsGetValue](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue)
- `InitializeCriticalSection`, `InitializeCriticalSectionAndSpinCount`,
  `EnterCriticalSection`, `TryEnterCriticalSection`, `LeaveCriticalSection`,
  and `DeleteCriticalSection` maintain registered objects, owner IDs, and
  recursion depth. Initialization validates all 24 bytes and rejects overlapping
  or duplicate objects. Spin count is zero for the single virtual processor,
  matching that documented case. Recursion is real; each entry requires a
  corresponding leave. Leave without ownership, deletion while owned, copied
  or modified opaque storage, and uninitialized access fault. Blocking contention
  faults until a guest scheduler exists; TryEnter returns zero for another owner.
  The 24-byte x86 field layout was checked against local Windows SDK
  10.0.26100.0 `winnt.h`, `_RTL_CRITICAL_SECTION`; its debug and semaphore fields
  are unused by this single-thread replacement.
  [Initialization](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionandspincount), [Recursion and ownership](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-entercriticalsection), [Deletion](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-deletecriticalsection)
- `QueryPerformanceCounter` uses Emscripten's monotonic browser/Node clock in
  microsecond units; `QueryPerformanceFrequency` returns 1,000,000. Actual clock
  precision remains browser dependent. `GetSystemTimeAsFileTime` converts the
  actual host wall clock to 100-nanosecond units since 1601 with millisecond
  source precision. Outputs are fully validated eight-byte guest buffers.
  [QPC](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter), [FILETIME API](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime)

There is no threading model, TEB field synchronization for direct LastError/TLS
access, DLL loader, SEH dispatch, Windows registry, filesystem, or Direct3D support in
this header. Such required behavior must stop until implemented. One guest
thread means current API invocations are serialized; this is not a substitute
for synchronization once multiple guest threads exist.

## Verification

From `browser-port/`:

```powershell
.\.venv\Scripts\python.exe -m tools.win32_test
```

The current command builds `tests/win32_test.cpp` with pinned Emscripten and runs
it in Node Wasm. Eighteen groups passed: version/ABI output; allocation/reuse/zeroing;
heap growth/limits/reset; TLS/error contracts; actual clocks; invalid pointers,
unsupported exports/flags and preservation of existing mappings; module/export
registration with absent-module/FLS responses and bounded strings; and recursive
critical sections with invalid-operation checks; process startup/standard handles;
immutable command line and module-path buffer/truncation checks; environment
allocation/free/exhaustion/reset and preservation of existing mappings.
The additional encoding groups check code-page metadata, the actual empty
environment conversion, exact characters, terminated/explicit lengths, sizing,
custom defaults, partial output, large output, errors and unsupported modes.
Four further groups cover reverse conversion, classification, the entire
CP1252 repertoire, and explicit classification/conversion failures.
The contention test deliberately
injects another-owner state to verify the scheduling barrier; it does not claim
that a second guest thread was run.
Evidence is `artifacts/win32-contract-tests.json`. Most groups are API contract
tests; the limited NLS repertoire has the native comparison described below.
These tests are not proof of successful game startup.

The authored optional reference probe executes only trusted system NLS APIs on
isolated in-memory strings:

```powershell
.\.venv\Scripts\python.exe -m tools.win32_nls_reference
```

`artifacts/win32-nls-reference.json` retains 22 observed conversion/classification cases, CPINFO
bytes, exact command, Python and Windows identities, and the loaded kernel32
path/hash. The recorded host was Windows build 26300, Python 3.11.0 x64, kernel32
SHA-256 `8f8629741558b5df71def4e1dd8ef9645d4f806b949762c47757c50fea1a9e6d`.
It confirmed prefix writes and default-use reporting on short buffers, the five
CP1252 control slots, and the metadata. With this reference artifact present,
`tools.win32_test` also compares all 256 decoded Unicode values and all 256
CT_CTYPE1 masks returned by Wasm. All 512 values matched. The test report pins
the reference artifact hash and host build; if the reference is missing, this
comparison is marked unverified. The probe is not a native game run or a complete XP oracle. The
host accepts undocumented length -2 as terminated; this runtime deliberately
faults for that unverified XP behavior rather than assuming it.

During implementation, the first compile found the clock declaration missing
because `emscripten_date_now` belongs to `emscripten/html5.h`; adding that header
fixed it. The first runtime test inspected faulted guest memory using `rd`,
which intentionally stops after a fault; the test now inspects unchanged raw
test memory without attempting another guest read. The rerun passed.

The actual audited startup code at `0x007ddc74` requests `kernel32.dll`, then at
`0x007ddc88` requests `InitializeCriticalSectionAndSpinCount`. These addresses
were read from this installation's pinned executable, not borrowed from a
different build. Registry and critical-section implementation follows that
observed CRT initialization requirement. Startup integration is verified
separately from these contract tests.
