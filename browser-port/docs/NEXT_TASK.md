# Next executable task

Use the existing local configuration and hash-bound seeds. Do not repeat the
audit unless inputs changed. Original executable SHA-256:
`80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c`.

Current Node/browser startup reaches 1,765,180 dispatches and faults at
`0x0088585b`, `fsub dword ptr [0x8ee6b8]`. Implement verified x87 subtraction
in `runtime/guest.hpp` and `translator/lift.py`. The preceding original FLD reads
10,000 from 0x8ee6bc; the subtrahend is 4,000. Observed control word is 0x023f
(53-bit precision, nearest rounding, exceptions masked). The next conditional
path also contains FADD. A bounded exact arithmetic implementation must reject
rounding/range/precision cases it cannot represent; do not silently use double
as a complete x87 replacement. Evaluate a verified extended-precision library
before expanding rounded arithmetic. Add binary tests for values, control/status,
stack state, all rounding modes, exactness and fault rollback. Preserve documented
oracle discrepancies. Regenerate output, then resume original initialization.

```powershell
Set-Location 'C:\Users\festi\Downloads\WebMostWanted\browser-port'
.\scripts\build.ps1
.\scripts\test.ps1
.\scripts\startup.ps1 -FromTrace -Limit 32000
```

The startup script builds, refreshes/checks the original-prefix oracle, then
probes startup. Nonzero exit at a required barrier is deliberate. Read
`artifacts/startup-node.json` for stack words and last 4,096 dispatches. History
records exact commands and source/artifact identities. For untranslated
file-backed targets, `-FromTrace` prioritizes observed instructions on the next
bounded build. Explicit targets use `-Seed 0xADDRESS`. Never edit generated C++.
Current defaults are 24,000 unique instructions and two million dispatches;
the latest constructor checkpoint uses the explicit 32,000 limit above.
`-MaxSteps` changes only the bounded execution budget, never guest state.

Reload the browser after rebuilding; run **Run translation tests**, then
**Probe translated startup**, and export diagnostics. Restart `scripts/serve.ps1`
if new filenames were added. Host: http://127.0.0.1:8000/.

Continue the 870 nonzero void constructors in the audit without skipping them. Full x87,
guest file continuations, DLL/COM callbacks, D3D9 effects/WebGPU, audio and race
input remain substantial work. No direct quick-race entry/resource working set
has been verified. No menu or race has been reached. Preserve original files,
save data, ignored generated artifacts and local evidence. Do not bypass
licensing, force race state, invent physics/AI, or publish game-derived data.
