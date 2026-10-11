# NFS Most Wanted 2005 — private Chrome build

**Original code is compiled and running in Chrome with WebGPU.** The original title and 3D world were observed directly; the user confirmed driving, audio, race completion and restart. See [test results](docs/test-results.md) for measured evidence and remaining limitations.

Open **http://127.0.0.1:8080/** while the private server is running and click **Play**. The first visit automatically acquires about 3.02 GB from the original local installation. Subsequent visits verify/reuse OPFS assets. No folder selection, archive upload, Windows game launch or gameplay streaming is involved.

To restart the already built local server from this folder:

```powershell
.\scripts\serve.ps1
```

Keep Chrome visible in the foreground. Use the game's original keyboard controls: arrows for driving/menu navigation, Enter to confirm, Escape to pause/back, Space for handbrake, Left Shift for nitrous. Controls and race-completion acceptance are tracked in the test report. Browser saves use a separate OPFS profile directory.

- [Build, launch and architecture](docs/browser-runtime.md)
- [Actual executable and engine evidence](docs/engine-map.md)
- [File inventory](docs/file-inventory.md)
- [Verified tests and remaining work](docs/test-results.md)

Upstream game configuration and runtime are pinned under ignored `reference/nfsmw-recomp`, with their MIT LICENSE/NOTICE retained. This project adds private automatic asset delivery, validation, browser diagnostics and reproducible Windows orchestration. Original files, translated proprietary code and built binaries are private ignored artifacts. Nothing has been publicly deployed; public delivery requires appropriate distribution rights.
