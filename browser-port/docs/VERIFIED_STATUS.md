# Verified status

Checkpoint: 2026-10-11T00:38:35+05:30 (evidence captured before this documentation).

| Milestone | State | Evidence / limitation |
| --- | --- | --- |
| M0 audit and reproducible environment | Tested | 1,363 files / 3,025,210,311 bytes; five PE identities; native Windows portable SDK; audit/server tests |
| M1 binary translation | Tested, limited instruction subset | 632 synthetic PE cases + 38 real-routine cases + 4 expected fault cases passed in Node and browser worker |
| M2 translated initialization | Implemented / Built / Failing | Original PE entry executes 34 original instructions then faults at GetVersionExA; platform expansion in progress |
| M3 authentic menu or initialized race | Proposed / Unverified | No game graphics, menu, or race scene reached |
| M4 controllable original driving | Proposed / Unverified | No vehicle simulation or game input demonstrated |
| M5 full race and genuine results | Proposed / Unverified | **Zero complete races demonstrated** |
| M6 replay / launch reliability | Proposed / Unverified | No race to replay; browser test host run once at this checkpoint |

## Actual checks

- `python -m tools.build_tests`: built two Wasm modules from two PE binary inputs.
- `node tests/run_wasm.mjs`: 632 + 38 differential cases and four fail-closed
  cases passed; CPU registers, defined flags, XMM values, watched memory checked.
- Browser **Run translation tests**: **674/674 passed**, with Wasm SHA checks.
- Browser secure context, Wasm, worker, cross-origin isolation, and shared-array
  availability passed. WebGPU: AMD `rdna-3`, nonfallback adapter, device and clear
  successful. Emdawn C instance create/release returned 1. No game rendering.
- `python -m unittest discover -s tests -p test_translator.py -v`: three focused
  prefix/unsupported/address-capture tests passed after review corrections.
- `scripts/test.ps1` passed 30 Python audit/server/prefix tests plus the Node
  differential suite. A direct unittest invocation from the parent directory
  failed imports; the documented script correctly changes into browser-port.
- Initial startup probe recorded fault code 5 at gateway `0x031001f0`,
  `KERNEL32.dll!GetVersionExA`, after 35 dispatches (34 original instructions).
- No native game or installer was executed by these tools.

Each module reserves 83,886,080 bytes of Wasm memory, of which 67,108,864 is the
guest window. This is not a measured full-game working set. No FPS or racing
performance claim is made. Reference execution used Unicorn CPU isolation;
native game differential execution is unverified.

## Local evidence (ignored)

- `artifacts/audit.json`, `artifacts/startup-analysis.json`
- `artifacts/environment.json`, `artifacts/toolchain-smoke.json`
- `artifacts/translation-build.json`, `artifacts/wasm-tests.json`
- `artifacts/browser-m1.json`, `artifacts/browser-m1.jpg`
- `artifacts/startup-node.json`, `artifacts/startup-build.json`
- `generated/*.json` instruction coverage/unsupported-site reports

## Failures corrected

1. Emscripten 4.0.23 did not expose HEAPU8 by default. Explicitly exported it,
   rebuilt modules, and reran the full Node/browser suite successfully.
2. Review found unsupported operand/address/segment prefixes could otherwise
   silently use 32-bit semantics. Those encodings now fail translation explicitly.
3. Faulting loads could alter a destination register before reporting failure.
   Added per-instruction rollback and a pre-fault register regression check.
4. Read-only server originally normalized leading `//` too early. Original
   request-target validation now rejects it; regression test passed.
5. Browser diagnostic DOM rendering was excessive for hundreds of results.
   A compact/coalesced diagnostic view is being verified; full export stays local.
