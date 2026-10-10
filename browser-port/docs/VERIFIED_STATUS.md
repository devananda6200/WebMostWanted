# Verified status

Checkpoint: 2026-10-11T01:11:29+05:30. Highest completed milestone: **M1**.

| Milestone | State | Evidence / limitation |
| --- | --- | --- |
| M0 audit/environment | Tested | 1,363 files / 3,025,210,311 bytes; five PE identities; portable Windows SDK |
| M1 binary translation | Tested, limited subset | 635 synthetic + 38 real routine + 1 original entry prefix + 7 expected faults: **681/681** in Node/browser |
| M2 translated initialization | Implemented / Built / Tested partially / Failing | 10,126 dispatches from original entry, then LCMapStringW faults; still CRT initialization |
| M3 menu or initialized race | Proposed / Unverified | No authentic game frame or menu |
| M4 original driving | Proposed / Unverified | Worker input only; no vehicle simulation |
| M5 complete race/results | Proposed / Unverified | **Zero complete races demonstrated** |
| M6 replay/reliability | Proposed / Unverified | No race to replay; diagnostic-host runs only |

## Actual checks

- `scripts/build.ps1`: assembly -> COFF -> PE32 binary -> generated C++ -> Wasm,
  actual game routine, and original entry-prefix reference. Fixture source is
  never compiled directly to Wasm for the binary-translation proof.
- `scripts/test.ps1`: 34 Python tests, 681 Node binary cases, exact 34-instruction
  entry-prefix trace/register/flags/memory comparison, and 18 Win32 Wasm groups.
- `tools.win32_nls_reference`: 512 CP1252 decode/classification values match
  trusted native system APIs. Windows build 26300 is not a historical XP oracle.
- Browser: 681/681, approximately 4.1 seconds including worker scheduling.
  Wasm and PE-image hashes checked before execution.
  Two fresh loads of the current artifact passed 681/681; both startup probes
  reached the same 10,126-dispatch barrier. This is not race-launch reliability.
- Browser startup: 10,126 dispatches, approximately 56.7 ms, then fault 5 at
  `0x03100740`, `KERNEL32.dll!LCMapStringW`. Node reaches the same barrier.
  Dispatches include gateways/repeated string iterations; the build contains
  6,000 distinct original instructions. Neither count proves completed startup.
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
