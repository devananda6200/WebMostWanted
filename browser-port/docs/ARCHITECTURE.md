# Architecture

The first backend is a bounded, fail-closed x86-to-C++ AOT translator, selected
after inspecting this installation. Capstone 5.0.7 provides decoding; it is not
treated as an instruction-semantics engine. `translator/lift.py` supplies explicit
semantics for a tested subset and walks control flow from verified seed addresses.
Unsupported encodings become diagnostic barriers. Unknown indirect targets also
fault. No runtime x86 decoding or Unicorn interpreter is shipped in Wasm.

Each generated case implements the decoded instruction as C++ operations on a
guest CPU. Emscripten 4.0.23 lowers the generated program to Wasm. A dispatch
switch grouped by 4 KiB guest address pages handles control flow; this design
prioritizes inspectable semantics over whole-program optimization. Generated
output is ignored and regenerated after every rule fix.

Ghidra raw p-code was considered as a later coverage source. It would still need
verified lowering for flags, x87, memory, indirect calls, and ABI boundaries.
Installing/exporting an entire program would not prove a working recompiler.
The current bounded backend permits the first binary differential proof with
fewer moving parts. Its instruction coverage is intentionally incomplete.

## Guest memory and ABI

Guest addresses are unsigned 32-bit values in a 64 MiB checked address window,
independent of Wasm heap pointers. A 4 KiB page map records R/W/X permissions.
The loader maps the PE at its audited preferred base, preserves image data,
allocates an isolated stack/TEB, and rewrites IAT entries only in the ignored
working image to explicit compatibility gateways. The original file is untouched.
Executable-page writes, unmapped accesses, unsupported operations, and unknown
targets have separate faults. Per-instruction CPU/memory transactions preserve
the pre-fault instruction state. This is not yet guest SEH exception delivery.

Synthetic PE exports define reproducible test seeds. Actual game seeds are gated
by SHA-256 and byte-range identity. Unicorn is an isolated development reference,
not a browser runtime. Its GPLv2 core stays in the local Python tool environment.
No original untrusted Windows executable is launched on the host.

## Browser and platform boundary

A module worker initializes the Wasm instance, loads bounded test/PE data,
executes instruction budgets, receives input messages, and exports diagnostics.
The main thread owns UI and WebGPU device/canvas setup. The initial runtime is
single-threaded and does not use shared-memory pthreads; COOP/COEP and
cross-origin isolation are nevertheless served and verified for future needs.

The localhost Python server only serves read-only resources. It runs no guest
physics, AI, or gameplay. The browser asset client has asynchronous read/seek
and a 16 MiB cache; a resumable guest file-call boundary remains to implement.
No entire-installation preload or upload is performed. Profile writes will need
a separate browser-local store, without touching original saves.

## Graphics boundary

The audited executable imports D3D9 and D3DX9_26 and contains compiled effect
resources. Future D3D9 COM gateways must preserve object/ABI/state behavior,
decode actual required buffers/textures/shader formats, and emit WebGPU commands.
Current code only verifies browser WebGPU adapter/device/clear and the pinned
Emdawnwebgpu C binding. There is no D3D9 wrapper or game draw call yet.
Emscripten's pinned `--use-port=emdawnwebgpu` is verified; obsolete USE_WEBGPU
flags are not used. Resource formats remain data, not translated instructions.

## Coverage limits

The current float proof covers controlled finite SSE scalar/vector operations,
exact normal/zero x87 load/store round trips, and x87 control-word initialization.
WAIT, FNSTCW, FLDCW, FNCLEX, FNINIT and FNSTSW preserve explicit guest control,
status and stack-top state. The reset control word is `0x037f`; the observed CRT
requests 53-bit precision while preserving rounding and exception masks. Tests
compare raw control/status words and memory with pinned Unicorn, including the
CRT's `0x023f` word, exception clearing and exact stores under four rounding modes.
This is an emulator reference, not a native hardware proof of reserved-bit values.
The architectural reference is [Intel Volume 1, Chapter 8](https://cdrdv2-public.intel.com/782149/253665-sdm-vol-1.pdf).

Finite normal/zero FABS and memory FCOM/FCOMP are supported without arithmetic
rounding. Tests preserve raw Unicorn status/EAX evidence and explicitly correct
only C1 to Intel's defined zero: Unicorn 2.1.4 incorrectly retains a seeded C1.
The initial raw differential run failed on that bit, and the correction is named
`oracle_adjustment` in each affected case. All other state remains differential.
This is an identified oracle defect, not evidence of full x87 compatibility.
Pending unmasked exceptions on these waiting instructions have separate
specification tests: this Unicorn version raises them on explicit WAIT but
incorrectly continues through FABS/FCOM/FCOMP. The runtime checks them first and
stops with a pending-exception diagnostic, preserving state.

Rounded stores, nonfinite/denormal loads or stores, and pending unmasked x87
exception delivery fail explicitly. Control-word support does not implement
80-bit arithmetic. MXCSR exception behavior, arbitrary NaN payloads, complete instruction-prefix
semantics, guest exceptions, multithreading, DLL loading, callbacks, and shaders
are not validated. Unsupported required instructions/imports stop execution.
Passing a short routine proves only those tested operations and input classes.

Memory FADD/FSUB now admits finite results that are exactly representable in
the current binary64 storage and selected precision. Knuth TwoSum checks for a
nonzero rounding residue; PC=24 additionally requires a 24-bit significand.
PC=53/64 is supported only for that exact storage subset, not full extended
precision. Exact cancellation uses the guest rounding mode for signed zero;
successful operations clear C1. Reserved precision, rounded results, extended
exponent needs, stack faults and pending exceptions stop with state rollback.
Fault diagnostics include raw binary64 words for the current x87 stack.
Memory FMUL strips powers of two from the normal inputs' significands and checks
the odd product's bit length against the precision limit before accepting host
multiplication. Its exact exponent is checked before host rounding. This rejects
a product just below DBL_MIN that host rounding would turn into a normal double;
checking the rounded result alone was insufficient. Signed zero, all rounding
modes, precision boundaries, exponent limits and transactional faults are tested.
[Error-free TwoSum analysis](https://www.tuhh.de/ti3/paper/rump/OgRuOi05.pdf),
[Intel FADD/FSUB semantics](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).
The [extended arithmetic assessment](FLOATING_POINT.md) records a pinned
SoftFloat candidate and the remaining x87 status/exception work. Its separate
library harness is being built; it is not part of the guest runtime.

32-bit DIV/IDIV use the full EDX:EAX dividend, capture the divisor before any
register write, and check zero/overflow before committing quotient and remainder.
Guest #DE delivery remains an explicit barrier. The signed INT64_MIN / -1 pair
is checked before C++ division: the pinned Unicorn helper crashes its host on
this case, so its regression is specification-based rather than a falsely
claimed emulator comparison. Other division edges use Unicorn's guest vector 0.
See [Intel DIV/IDIV](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf)
and the [pinned reference helper](https://github.com/unicorn-engine/unicorn/blob/2.1.4/qemu/target/i386/int_helper.c).
Successful division arithmetic flags are undefined and excluded from comparison.

32-bit SHLD/SHRD mask the count to five bits and check result flags; OF is checked
only for a count of one, and AF is undefined. Memory operands still perform their
checked read/write when the effective count is zero. Narrow forms remain explicit
unsupported operations until their semantics are separately tested.

The decoder refuses partial instructions at a section boundary, even where the
next virtual section is also executable. SSE2 scalar-double MOVSD is currently
unsupported and is distinguished from the string instruction. Operand-size-16
control transfers fail explicitly. POPFD restores ordinary arithmetic/DF flags
and the ID flag used to detect CPUID. It ignores reserved bits; other
control/debug/privilege changes remain unsupported.
These restrictions follow the
[Intel instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
and isolated binary regressions, not assumptions about decompiler output.

## Startup platform profile and reproducibility

The narrow Win32 layer declares an XP SP3, single-thread GUI process with no
inherited standard handles and an empty environment. It implements bounded
heap ownership, TLS slots, critical-section recursion, process strings, module
lookup and selected startup/timing APIs. Its contracts and unsupported behavior
are detailed in [Win32 compatibility](WIN32_COMPATIBILITY.md). This profile is
not a complete Windows environment, and no thread scheduler is provided.

The guest's CPUID leaves 0 and 1 use the measured Unicorn 2.1.4
`UC_CPU_X86_PENTIUM3` profile, including its hypervisor bit. Incoming ECX is
ignored for these leaves; unknown requested leaves fault explicitly. This is a
declared virtual baseline, not the host CPU or a physical Pentium 4 claim.
The original CRT follows its normal non-SSE2 branch for this profile. Its CPU
checks still execute; no branch or result flag in the game is patched. Other
advertised instruction families still require translation coverage before use.
The reference explicitly enables OS x87/SSE state (CR0.EM/TS clear, MP/NE set,
CR4 bits 9/10 set). Selecting a model without that initialization caused the existing
SIMD fixture to fail; the explicit state fixes that reference setup failure.
Review also found that a clear CR0.NE suppressed Unicorn's native WAIT exception;
three focused oracle tests now verify masked, unmasked and cleared exceptions.
Authored native PE32 probes establish `(cw & 0x1f3f) | 0x40` readback for this
AMD host. FLDCW and diagnostic setters use this declared control-word profile;
the reference records its raw discrepancy before normalization. Intel reserves
these bits, so this measurement is not a universal or physical Pentium III
claim. The 18 FLDCW cases plus FNINIT and process-return plumbing are repeatable
with `tools.native_fpu_reference`; no game executable is run natively.
Model/API sources: [Unicorn CPU definitions](https://github.com/unicorn-engine/unicorn/blob/2.1.4/qemu/target/i386/cpu.c)
and [Python controls](https://github.com/unicorn-engine/unicorn/blob/2.1.4/bindings/python/unicorn/unicorn_py3/unicorn.py).

The entry-prefix test compares the actual original SEH/stack-probe instructions
against Unicorn with explicit 32-bit CS/SS/DS/ES/FS descriptors, stopping before
the first platform call. Later startup execution exercises the replacement APIs;
it does not constitute a native-Windows differential proof of their contracts.

The startup probe uses `-O0` while discovering coverage; the small differential
modules use `-O1`. One giant dispatch function took about 102 seconds to build
without optimization, so generated code now uses smaller page functions.
Neither build is evidence of playable performance. Startup manifests
record input, image, Wasm and source hashes, optimization, seeds and build timing.
Builds reject a source change during compilation. `startup.ps1 -FromTrace`
adds observed executable addresses from the matching local trace to the ignored
seed file; it never executes a runtime x86 decoder. Each failed probe records
its exact build command and the latest 4,096 dispatch addresses.
Seeds are saved as immutable SHA-256-named snapshots. `--seed-file` validates
executable identity, file-backed executable addresses, snapshot identity and
source stability, without mutating the input or default progress. This replaces
an unusable 121,267-character command; a measured replay was 191 characters and
reproduced identical Wasm bytes and the exact fault. Twenty-four tests cover
validation, aliasing, output containment, concurrent edits and compact replay.
Node and browser exports include stack arguments and a 64-byte fault-memory
window when the fault address is in bounds. These private artifacts are ignored;
they must not be committed or uploaded.

The intended path is original entry -> verified CRT/platform initialization ->
static constructors -> actual application init -> genuine quick race. There are
870 distinct nonzero constructor targets in the audited table; none may be
skipped solely to manufacture a startup success. A race entry and its resource
working set have not yet been established.
