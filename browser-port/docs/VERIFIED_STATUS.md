# Verified status

Checkpoint: 2026-10-11T02:43:30+05:30. Highest completed milestone: **M1**.

| Milestone | State | Evidence / limitation |
| --- | --- | --- |
| M0 audit/environment | Tested | 1,363 files / 3,025,210,311 bytes; five PE identities; portable Windows SDK |
| M1 binary translation | Tested, limited subset | 2,199 synthetic + 38 real routine + 1 original entry prefix + 97 expected faults: **2,335/2,335** in Node/browser; named oracle corrections below |
| M2 translated initialization | Implemented / Built / Tested partially / Failing | 2,053,284 dispatches from original entry into game constructors, then unsupported FILD |
| M3 menu or initialized race | Proposed / Unverified | No authentic game frame or menu |
| M4 original driving | Proposed / Unverified | Worker input only; no vehicle simulation |
| M5 complete race/results | Proposed / Unverified | **Zero complete races demonstrated** |
| M6 replay/reliability | Proposed / Unverified | No race to replay; diagnostic-host runs only |

## Actual checks

- `scripts/build.ps1`: assembly -> COFF -> PE32 binary -> generated C++ -> Wasm,
  actual game routine, and original entry-prefix reference. Fixture source is
  never compiled directly to Wasm for the binary-translation proof.
- `scripts/test.ps1`: 78 Python tests, 2,335 Node binary cases, exact 34-instruction
  entry-prefix trace/register/flags/memory comparison, and 33 Win32 Wasm groups.
- `tools.win32_nls_reference`: 2,048 CP1252 decode/classification/casing values
  and eight best-fit conversion cases match trusted native system APIs.
  Windows build 26300 is not a historical XP oracle.
- `tools.win32_heap_reference`: four trusted native private-heap reallocation
  observations match Wasm. Source is authored; no native game code is executed.
- `tools.native_fpu_reference`: 20 authored native PE32 probes pass, covering
  18 control words, FNINIT, and process-return plumbing. This measured AMD-host
  reserved-bit profile differs from raw Unicorn in 15 cases; it is not a physical
  Pentium III or universal architecture claim. Original game code is not run.
- Snapshot replay preserves the input and default seed files, reproduces identical
  Wasm bytes and the 2,042,864-dispatch checkpoint using a 191-character command.
- Browser: 2,335/2,335, approximately 40.59 seconds including worker scheduling.
  Wasm and PE-image hashes checked before execution.
  Earlier runs reached their previous CRT/constructor barriers; the current
  2,335-case artifact includes the current constructor checkpoint.
  These diagnostic checks are not race-launch reliability.
- Startup: 2,053,284 dispatches, then fault 2 at `0x00887040`,
  `fild dword ptr [0x8f82fc]`. Node reaches this barrier in approximately
  1,058.4 ms. These diagnostic timings are not gameplay FPS.
  Dispatches include gateways/repeated string iterations; the build contains
  40,000 distinct original instructions. Neither count proves completed startup.
  Five error-returning CRT initializers and the early void/game constructors
  execute normally, including original registry/hash code and a heap fill.
- Secure context, worker/Wasm, isolation, SharedArrayBuffer availability, AMD
  RDNA3 nonfallback WebGPU device/clear, and Emdawn C instance creation passed.
  There is no D3D9 implementation or game rendering yet.
- Real ArrowUp press/release reached the worker with `gameplayConnected:false`.
  Browser console warning/error query was empty. No vehicle response is claimed.
- Follow-up audit matched all 1,363 path/size/mtime entries and five PE records.
  No original game/installer was run. A snapshot during browser execution found
  zero native `speed` processes; the localhost server only serves resources.

Each module reserves 83,886,080 Wasm bytes including a 67,108,864-byte guest window.
This is per-module allocation, not total browser or full-game memory. The heap
arena is 9 MiB. There is no gameplay FPS measurement. Native game execution,
guest file continuations, D3D9, audio, threads, full x87 and race flow are unverified.

## Local ignored evidence

- `artifacts/audit.json`, `audit-final.json`, `startup-analysis.json`
- `artifacts/environment.json`, `toolchain-smoke.json`
- `artifacts/translation-build.json`, `wasm-tests.json`
- `artifacts/startup-reference.json`, `startup-prefix-test.json`
- `artifacts/win32-contract-tests.json`, `win32-nls-reference.json`
- `artifacts/browser-m1.json`, `browser-m1.jpg` (earlier 674-case checkpoint)
- `artifacts/browser-crt-9829.json`, `browser-crt-9829.jpg`
- `artifacts/browser-crt-10126.json`, `process-check.json`
- `artifacts/browser-crt-10126-repeat.json`
- `artifacts/browser-crt-17689.json` (intermediate best-fit conversion barrier)
- `artifacts/browser-constructors.json`, `browser-constructors.jpg`
- `artifacts/browser-division.json`, `browser-arithmetic.json`
- `artifacts/browser-heap-realloc.json`, `heap-realloc-reference.json`
- `artifacts/wasm-tests-x87-oracle-failure.json`
- `artifacts/native-fpu-control/results.json`
- `artifacts/startup-seed-replay.json`, `artifacts/startup-seeds/*.json`
- `artifacts/fmul-constructor-analysis.json`, `fmul-predicate-review.json`
- `artifacts/browser-exact-x87.json`, `browser-exact-arithmetic.json`
- `artifacts/process-check-exact-arithmetic.json`, `validation-exact-arithmetic.txt`
- `artifacts/initializer-analysis.json`, `cpuid-profile-analysis.json`
- `artifacts/bounded-constructor-seeds.json`
- `artifacts/constructor-batch-2.json`, `constructor-batch-3.json`, `constructor-batch-4.json`
- `artifacts/initializer-seeds.json` (latest bounded table selection)
- `artifacts/constructor-vtables.json` (read-only target review)
- `artifacts/startup-node.json`, `startup-history.jsonl`, `startup-build.json`
- `generated/*.json` coverage; `generated/startup-seeds.json` retained local seeds

## Corrections and remaining limits

Initial HEAPU8 exports, unsupported prefixes, fault rollback, server path checks
and excessive diagnostic rendering were corrected and retested. Later review
found SSE MOVSD/string ambiguity, 16-bit conditional targets, cross-section raw
decoding and reserved POPFD bits. These now have correction/explicit rejection
and regressions. Indirect stdcall cleanup and partial SIMD-store rollback pass.

The first FS oracle retained a 16-bit SS descriptor; explicit 32-bit descriptors
fixed the reference without a guest bypass. Two costly optimized startup builds
were cancelled. A monolithic O0 build completed in about 102 seconds; page-sized
dispatch reduced a later build to 2.09 seconds. This is build throughput, not game
performance. Source hashes and checks reject edits during compilation. Required
unsupported behavior still stops; constructors are not skipped to force startup.

CPUID uses a measured, declared Unicorn Pentium III profile. Its original
non-SSE2 branch executes without patching game checks. Reference setup now
explicitly enables OS SSE and native x87 exception delivery; three oracle tests
cover masked/unmasked/cleared WAIT. Limited x87 control/status operations pass;
rounded stores, denormals and exception delivery still fail explicitly.
Increasing the bounded translation set from 6,000 to 8,000 restored entry
coverage after adding constructor targets. Raising the dispatch budget from
one to two million let the observed finite REP STOSD fill finish normally.

DIV/IDIV, SHLD/SHRD, finite FABS/FCOM/FCOMP, exact-store C1 clearing, and
HeapReAlloc now pass focused tests. Seventeen initializer-seeding tests cover
identity, bounds, concurrent changes, and original-file protection. Later bounded
constructor batches increased coverage to 40,000 instructions; no constructor was
skipped. Exact FADD/FSUB pass the original 10,000 and 4,000 constructor constants.
Exact FMUL then passes the original value 8738133/524288 multiplied by 0.5 and
its following float store. Rounded results remain unsupported. Review caught
host rounding that could conceal an exact product below DBL_MIN; the corrected
pre-rounding exponent guard has binary regressions and agrees with 18,147
independent rational checks. Missing authored fixture exports were corrected
before the successful build. The 3M dispatch bound lets original sorting finish.

Pinned Unicorn 2.1.4 has observed oracle defects. INT64_MIN/-1 crashes its host
division helper; that overflow has a specification test instead. Pending #MF on
FABS/FCOMP likewise has two specification tests. Named finite x87 cases correct
Unicorn's stale C1 against Intel's specified clearing behavior; raw EAX/FPSW and
the named correction remain in case evidence. Three controlled-state checkpoints
isolate that behavior after FLD. These corrections are not hidden differential
matches. Native-reserved-control-bit differences are recorded separately before
normalizing the reference to the declared guest profile. Full extended-precision
arithmetic remains unimplemented; an isolated SoftFloat harness is in progress.
