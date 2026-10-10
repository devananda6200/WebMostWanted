# Change log

Record each meaningful project change during the event, newest first. Update this file in the same commit as the change. Use a real timestamp with timezone, for example `YYYY-MM-DDTHH:MM:SS+05:30`.

## Event build log

## 2026-10-11T02:43:30+05:30 — exact x87 arithmetic and reproducible startup checkpoints

- Changed: Implemented exact FADD/FSUB/FMUL with precision/exponent guards and
  x87 value diagnostics; added native control-word probes, declared readback
  profile, immutable seed snapshots and compact replay. Updated runtime,
  translator, fixtures, build tools, browser worker and project documentation.
- Why: Advance observed original constructors while rejecting unsupported
  rounded arithmetic, and make thousands of retained translation seeds replayable.
- Validation: 2,335 Node/browser binary cases, 78 Python tests, 33 Win32 groups,
  20 authored native PE32 probes and 18,147 rational multiplication checks pass.
  Snapshot replay reproduced identical Wasm and fault without changing inputs.
  Browser/Node reach FILD at 0x00887040 after 2,053,284 original dispatches.
- Corrections: Native reserved control-bit readback differs from Unicorn and is
  explicitly recorded. Review found a multiplication-underflow false acceptance;
  exact-exponent checks and regression cases fix it. Added missing fixture exports
  after the linker reported them. Reproduction: scripts/build.ps1 and test.ps1;
  startup.ps1 -FromTrace -Limit 40000 -MaxSteps 3000000 reaches the current barrier.
- Limitations: Highest complete milestone M1; M2 remains partial. No menu, game
  rendering, driving, race completion or replay. Full x87 and platform/rendering
  services remain incomplete. SoftFloat harness work is separate and unintegrated.
  Human review pending; all original-derived outputs/evidence remain private.

## 2026-10-11T02:15:04+05:30 — arithmetic, bounded constructor discovery, and heap resizing

- Changed: Implemented DIV/IDIV, SHLD/SHRD, finite x87 ABS/comparison/status
  behavior, HeapReAlloc contracts, native heap probe, and validated initializer
  seeding. Updated browser/Node state checkpoints and project documentation.
- Why: Resolve observed original constructor barriers using repeatable rules,
  with explicit failure for unsupported exceptions and floating-point behavior.
- Validation: 54 Python tests, 1,402 Node/browser binary cases, 33 Win32 Wasm
  groups, 2,048 native NLS values, eight conversion and four heap cases passed.
  Browser/Node reach FSUB at 0x0088585b after 1,765,180 dispatches. Read-only
  reviews covered arithmetic, heap ownership, oracle checkpoints and vtables.
- Corrections: Named Unicorn division/C1/pending-exception defects now retain
  raw evidence and use explicit specification checks; a signed-overflow input
  was removed from successful-division fixtures. Exact stores clear C1 only
  after a successful write. Generated code is never hand patched.
- Limitations: M1 verified for tested subset; M2 partial. No menu, game frame,
  driving, race or results. Rounded/full x87, rendering and major platform
  services remain incomplete. Human review pending; generated artifacts private.

## 2026-10-11T01:47:07+05:30 — execute early game constructors in Wasm

- Changed: Added verified CP1252 casing/best-fit conversion, heap validation,
  pointer queries, clocks, exception-filter registration, x87 control/status,
  declared CPUID profile, bounded constructor seeds and richer fault exports.
  Affected browser-port runtime, translator, test tools, worker and documentation.
- Why: Resolve observed CRT barriers and execute original constructors without
  skipping initialization or changing game state to claim success.
- Validation: 37 Python tests, 712 Node/browser binary cases, 28 Win32 Wasm
  groups, 2,048 native NLS values and eight conversion cases passed. Browser
  startup reaches 1,166,682 dispatches and IDIV at 0x00464f34, matching Node.
- Corrections: Enabled explicit OS SSE/x87 exception state in the reference;
  added three oracle regressions. Expanded bounded instruction coverage and
  dispatch budget after observing entry coverage loss and a finite heap fill.
- Limitations: M1 complete for tested subset; M2 partial. No menu, game frame,
  race, driving or completion. Native historical XP equivalence and full x87
  arithmetic remain unverified. Human review pending; all evidence stays local.

## 2026-10-11T01:11:29+05:30 — verified CRT progress and translation corrections

- Changed: Added process/heap/TLS/lock/startup/NLS contracts, entry-prefix oracle,
  trace-guided seeds, source/artifact checks, stack/fault history, page-sized AOT
  dispatch and CPU/memory regressions. Updated browser-port documentation.
- Why: Advance actual initialization and correct observed silent miscompilation.
- Validation: 34 Python tests; 681 Node/browser binary cases; 18 Wasm API groups;
  512 native NLS values passed. Browser reaches 10,126 dispatches and LCMapStringW.
  Follow-up audit matched original metadata/PE records. Evidence remains ignored.
- Corrections: MOVSD ambiguity, 16-bit branches, section reads, POPFD reserved
  flags, indirect stdcall and SIMD rollback; fixed reference SS and build hashes.
  Two costly optimized compiles cancelled; O0 completed in about 102 seconds;
  page dispatch reduced a later build to 2.09 seconds. No gameplay FPS claim.
- Limitations: M1 completed; M2 partial. No menu, initialized race, D3D9, driving,
  finish/results or replay. Human review pending; XP NLS equivalence unverified.

## 2026-10-11T00:38:35+05:30 — audit, binary translation proof, and browser host

- Changed: Added browser-port tools, translator/runtime, PE fixture, differential
  tests, browser worker/WebGPU probes, read-only bounded asset server, PowerShell
  entry points, and architecture/audit/status/dependency documentation. Ignored
  original installation, local toolchain, generated game code, memory images,
  profiles, and diagnostic artifacts.
- Why: Establish executable identity and a tested translation pipeline before
  expanding original startup and race coverage.
- Validation: Audited 1,363 files and five PE identities without executing original
  binaries; native portable Emscripten/toolchain smoke passed; Node and browser
  passed 632 synthetic + 38 real-routine differential cases + four expected faults.
  Browser WebGPU AMD RDNA3 nonfallback device, Emdawn instance, worker, and COOP/COEP
  verified. Focused audit/server/prefix tests passed. Detailed local evidence is
  indexed in browser-port/docs/VERIFIED_STATUS.md.
- Corrections: Exported HEAPU8 explicitly; rejected unsupported prefixes; added
  fault rollback; fixed request-path normalization; reduced diagnostic DOM churn.
- Limitations: M1 verified for a limited instruction subset. Original startup
  reaches GetVersionExA then stops at the required API. No authentic menu, D3D9
  renderer, driving, completed race, native game reference run, or game FPS result.

## Template setup — 10 October 2026

- Changed: Added the event README, rules, agent guide, change log, AI usage record, submission checklist, Git ignore rules, and pull request checklist.
- Why: Give participants a consistent starting point for event rules, basic coding patterns, documented changes, and regular commits.
- Validation: Checked local Markdown links, event detail consistency, required documents, and diff whitespace before publishing.
- Limitations: Documentation scaffolding only; no participant project, application, or working demo is included. GitHub publication and template status are verified separately after creation.
