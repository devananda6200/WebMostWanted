# Architecture

The first backend is a bounded, fail-closed x86-to-C++ AOT translator, selected
after inspecting this installation. Capstone 5.0.7 provides decoding; it is not
treated as an instruction-semantics engine. `translator/lift.py` supplies explicit
semantics for a tested subset and walks control flow from verified seed addresses.
Unsupported encodings become diagnostic barriers. Unknown indirect targets also
fault. No runtime x86 decoding or Unicorn interpreter is shipped in Wasm.

Each generated case implements the decoded instruction as C++ operations on a
guest CPU. Emscripten 4.0.23 lowers the generated program to Wasm. A dispatch
switch handles guest control-flow addresses; this conservative initial design
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

The current float proof covers controlled finite SSE scalar/vector operations
and exact x87 load/store round trips. 80-bit arithmetic, x87 status/control,
MXCSR exception behavior, arbitrary NaN payloads, complete instruction-prefix
semantics, guest exceptions, multithreading, DLL loading, callbacks, and shaders
are not validated. Unsupported required instructions/imports stop execution.
Passing a short routine proves only those tested operations and input classes.

The intended path is original entry -> verified CRT/platform initialization ->
static constructors -> actual application init -> genuine quick race. There are
870 distinct nonzero constructor targets in the audited table; none may be
skipped solely to manufacture a startup success. A race entry and its resource
working set have not yet been established.
