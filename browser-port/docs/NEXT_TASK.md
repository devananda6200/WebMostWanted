# Next executable task

Use the existing local configuration and hash-bound seeds. Do not repeat the
audit unless inputs changed. Original executable SHA-256:
`80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c`.

Current Node/browser startup reaches 10,126 dispatches and faults at
`KERNEL32.dll!LCMapStringW`, gateway `0x03100740`, return `0x007d40d7`.
Arguments: locale 0, flags `0x100` (lowercase), source `0x008bd0fc` containing UTF-16
NUL, count 1, null destination, capacity 0 (size query). Implement its actual
bounded contract and tests in `runtime/win32.hpp` / `tests/win32_test.cpp`;
extend the trusted system NLS reference tool. Never return unconditional success.

```powershell
Set-Location 'C:\Users\festi\Downloads\WebMostWanted\browser-port'
.\.venv\Scripts\python.exe -m tools.win32_nls_reference
.\.venv\Scripts\python.exe -m tools.win32_test
.\scripts\startup.ps1 -FromTrace
.\scripts\test.ps1
```

The startup script builds, refreshes/checks the original-prefix oracle, then
probes startup. Nonzero exit at a required barrier is deliberate. Read
`artifacts/startup-node.json` for stack words and last 4,096 dispatches. History
records exact commands and source/artifact identities. For untranslated
file-backed targets, `-FromTrace` prioritizes observed instructions on the next
bounded build. Explicit targets use `-Seed 0xADDRESS`. Never edit generated C++.

Reload the browser after rebuilding; run **Run translation tests**, then
**Probe translated startup**, and export diagnostics. Restart `scripts/serve.ps1`
if new filenames were added. Host: http://127.0.0.1:8000/.

After CRT, preserve/validate the 870 nonzero constructors in the audit. Full x87,
guest file continuations, DLL/COM callbacks, D3D9 effects/WebGPU, audio and race
input remain substantial work. No direct quick-race entry/resource working set
has been verified. No menu or race has been reached. Preserve original files,
save data, ignored generated artifacts and local evidence. Do not bypass
licensing, force race state, invent physics/AI, or publish game-derived data.
