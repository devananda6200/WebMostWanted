# AI usage record

Use Codex during the hackathon and briefly document its actual contribution here. Add a row after each meaningful task or milestone. Keep summaries concise and omit secrets, private data, and full chat transcripts.

## Event build log

Human review remains pending unless explicitly recorded otherwise.

| Date and time with timezone | Tool / model, if known | Task | Assistance and affected files | Human review / corrections | Validation and result |
| --- | --- | --- | --- | --- | --- |
| 2026-10-11T02:43:30+05:30 | Codex | Advance exact floating-point constructors and make checkpoints reproducible | Implemented exact FADD/FSUB/FMUL and state comparisons; integrated delegated native control probe and immutable seed snapshots; reviewed rational arithmetic and continued original startup. | Human review pending. Preserved native/Unicorn control differences; fixed hidden multiplication underflow and missing authored fixture exports. | 2,335 Node/browser cases, 78 Python tests, 33 API groups, 20 native probes and 18,147 rational checks pass. Compact snapshot replay reproduces Wasm. Startup reaches FILD after 2,053,284 dispatches; zero races. |
| 2026-10-11T02:15:04+05:30 | Codex | Extend original constructors past arithmetic and heap barriers | Implemented division, double shifts, finite x87 operations and binary fixtures; integrated delegated HeapReAlloc/native probe and bounded seeding; reviewed vtable evidence. | Human review pending. Preserved raw Unicorn oracle defects and explicit Intel-based corrections; corrected a signed-overflow fixture and exact-store status handling. | 1,402 Node/browser cases, 54 Python tests, 33 API groups, 2,048 NLS values, eight conversion and four native heap cases pass. Startup stops at FSUB after 1,765,180 dispatches. Zero races. |
| 2026-10-11T01:47:07+05:30 | Codex | Execute CRT and early original constructors | Implemented x87 control/status and declared CPUID; integrated delegated Win32 contracts and read-only initializer review; expanded binary/native tests and browser diagnostics. | Human review pending. Corrected reference SSE and x87 exception setup; preserved explicit faults for incomplete semantics. | 712 Node/browser cases, 37 Python tests, 28 API groups, 2,048 native NLS values and eight conversion cases pass. Startup stops at IDIV after 1,166,682 dispatches. No game frame or race. |
| 2026-10-11T01:11:29+05:30 | Codex | Advance CRT startup and correct translation | Win32 contracts/native NLS probes; entry-prefix oracle; trace-guided AOT; page dispatch; CPU regressions. Delegated bounded review/platform work with separate ownership. | Human review pending. Corrected MOVSD ambiguity, 16-bit branches, section reads, POPFD flags and reference segments. | 681 Node/browser cases, 34 Python tests, 18 API groups, 512 native values pass. Startup reaches LCMapStringW after 10,126 dispatches. No race claimed. |
| 2026-10-11T00:38:35+05:30 | Codex | Local browser-port implementation | Audited installation; built portable toolchain, binary lifter, checked guest memory, reference/Wasm tests, worker host and read-only server; delegated bounded audit/toolchain/browser tasks with separate file ownership. | Human review pending. Agent review corrected prefix handling, HEAPU8 exports, fault state rollback, path validation and diagnostic rendering. | 674 Node/browser cases passed; WebGPU/worker/isolation verified. Original entry reaches a required platform barrier; no playable game claimed. |

<!-- local-source-reconstruction -->

### 2026-10-11T03:27:54+05:30 — local source reconstruction

Codex authored and ran the source_code inventory, PE extraction, Ghidra export and validation tools; preserved uncommitted browser-port work; reconstructed one small hash routine. No agents were delegated and no game data was uploaded.

Checks: 27,112 function exports, 1,309,073 original-byte instruction comparisons, unchanged hashes for 1,363 original files, and 1,264 original-x86 versus Node-Wasm hash cases. Ghidra analysis/export completed for five PEs without timeouts. Human review pending.

Corrections: resumed the slow Ghidra download with checked ranges, verified its published checksum, added emulator completion and stale-summary checks, and used unsigned arithmetic to preserve hash overflow. Automatic decompiler output remains unverified and is not claimed as exact source or a working game.

## Template preparation

On 10 October 2026, Codex prepared this documentation template from the organizer's supplied rules and checked the linked Luma page for the event name and dates. This covered `README.md`, `RULES.md`, `AGENTS.md`, `CHANGELOG.md`, `AI_USAGE.md`, `SUBMISSION.md`, `.gitignore`, and the pull request checklist. Agent validation covered local links, event consistency, required documents, and diff whitespace; organizer review is pending.

This preparation is separate from participant project implementation and participant AI usage during the event.
