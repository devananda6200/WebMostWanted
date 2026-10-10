# Next executable task

Use the existing local configuration and hash-bound seeds. Do not repeat the
audit unless inputs changed. Original executable SHA-256:
`80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c`.

Current Node/browser startup reaches 1,166,682 dispatches and faults at
`0x00464f34`, `idiv dword ptr [esp + 0x28]`. Implement 32-bit signed division
in `runtime/guest.hpp` and `translator/lift.py`: signed EDX:EAX dividend,
signed divisor, quotient truncated toward zero in EAX, remainder in EDX.
Check zero divisor, quotient overflow, and INT64_MIN / -1 before C++ division;
required guest divide-exception delivery must fail explicitly with state intact.
Add binary fixture tests for signs, remainder, boundaries, aliasing and memory
operands. Compare defined state with Unicorn; arithmetic flags are undefined.
Regenerate output rather than editing game-derived code. Then resume startup.

```powershell
Set-Location 'C:\Users\festi\Downloads\WebMostWanted\browser-port'
.\scripts\build.ps1
.\scripts\test.ps1
.\scripts\startup.ps1 -FromTrace
```

The startup script builds, refreshes/checks the original-prefix oracle, then
probes startup. Nonzero exit at a required barrier is deliberate. Read
`artifacts/startup-node.json` for stack words and last 4,096 dispatches. History
records exact commands and source/artifact identities. For untranslated
file-backed targets, `-FromTrace` prioritizes observed instructions on the next
bounded build. Explicit targets use `-Seed 0xADDRESS`. Never edit generated C++.
Current defaults are 8,000 unique instructions and two million dispatches.
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
