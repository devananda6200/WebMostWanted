# Next executable task

Use the existing local configuration and hash-bound seeds. Do not repeat the
audit unless inputs changed. Original executable SHA-256:
`80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c`.

Current Node startup reaches 2,053,284 dispatches and faults at `0x00887040`,
`fild dword ptr [0x8f82fc]`. Implement signed integer-to-x87 loads in
`runtime/guest.hpp` and `translator/lift.py`; this observed m32 form fits exact
binary64 storage. Add binary tests for signed boundaries, precision independence,
stack/status behavior, unmapped memory, pending exceptions and rollback.
Do not extend m64 loading by silently rounding integers that need more than
53 bits. Preserve current exact arithmetic restrictions and oracle corrections.
The separate pinned SoftFloat build is preparatory work, not yet a runtime
backend. See [floating-point assessment](FLOATING_POINT.md).

```powershell
Set-Location 'C:\Users\festi\Downloads\WebMostWanted\browser-port'
.\scripts\build.ps1
.\scripts\test.ps1
.\scripts\startup.ps1 -FromTrace -Limit 40000 -MaxSteps 3000000
```

The startup script builds, refreshes/checks the original-prefix oracle, then
probes startup. Nonzero exit at a required barrier is deliberate. Read
`artifacts/startup-node.json` for stack words and last 4,096 dispatches. History
records compact `--seed-file` commands with immutable snapshots and source/artifact identities. For untranslated
file-backed targets, `-FromTrace` prioritizes observed instructions on the next
bounded build. Explicit targets use `-Seed 0xADDRESS`. Never edit generated C++.
Current defaults are 24,000 unique instructions and two million dispatches;
the latest constructor checkpoint uses the explicit 40,000 / 3M limits above.
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
