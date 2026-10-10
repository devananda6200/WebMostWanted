# Most Wanted browser-port laboratory

This project translates bounded portions of a locally supplied Most Wanted x86
executable into C++ and WebAssembly. It is **not a playable game yet**. No original
game files or generated game code are included in the repository.

The verified checkpoint is M1: an assembled/linked PE32 fixture and a routine
from the audited game executable pass differential CPU-state/memory tests in
Node and a browser worker. Original PE-entry execution has begun, but required
platform services still stop startup. See [verified status](docs/VERIFIED_STATUS.md).

## Setup on this Windows machine

Requires Windows x64, Python 3.11+, Git, PowerShell, network access for initial
official tool downloads, and a desktop browser with WebGPU. No WSL is required.
The scripts use a portable Emscripten 4.0.23 SDK under ignored `.tools/` and a
project-local Python virtual environment. They do not change system PATH.

From `browser-port`:

```powershell
.\scripts\setup.ps1
Copy-Item config.example.json config.local.json
# Edit config.local.json game_root to your existing installation directory.
# Alternatively, set $env:NFS_GAME_ROOT to that directory for this process.
.\scripts\environment.ps1
.\.venv\Scripts\python.exe -m tools.audit_installation
.\.venv\Scripts\python.exe -m tools.toolchain smoke
.\scripts\build.ps1
.\scripts\test.ps1
.\scripts\serve.ps1
```

Do not overwrite an existing `config.local.json`; this session already created
one for the supplied installation. Paths with spaces are passed as argument
arrays. Setup pins pefile 2024.8.26, Capstone 5.0.7, Unicorn 2.1.4, and the SDK
manager commit. Sources and licenses are in [dependencies](docs/DEPENDENCIES.md).

Open [the local host](http://127.0.0.1:8000/). Browser services initialize, then use
**Run translation tests**. **Export diagnostics** saves evidence locally.
The black canvas is only a WebGPU initialization clear, never a game screenshot.

To build and probe the original entry path:

```powershell
.\scripts\startup.ps1
```

This currently returns a nonzero exit code at a required compatibility barrier.
Read `artifacts/startup-node.json`, then use **Probe translated startup** in the
browser. Restart the resource server after adding build filenames, and reload
the browser after every rebuild; the worker verifies Wasm identity hashes.

## What the commands actually test

`build.ps1` assembles `tests/fixture.S` to i386 COFF, links a PE32 executable,
then feeds that binary to `translator/lift.py`. It does not compile fixture
source directly to Wasm. The generated C++ is compiled by Emscripten. Unicorn
executes identical mapped bytes with isolated inputs and no host syscalls.
Tests compare general registers, defined flag bits, XMM registers, return
addresses, and watched input/output/stack memory. The real routine is pinned
by executable hash, address, size, and routine-byte hash.

The runtime currently uses a 64 MiB guest address window and an 80 MiB Wasm heap
per module. It has explicit page permissions, checked accesses, fault rollback,
bounded dispatch, and diagnostic instruction traces. This is a limited AOT
translation backend; it is not a complete x86 compiler or Windows emulator.

The resource server binds only `127.0.0.1`. It exposes selected static mounts,
GET/HEAD, bounded byte ranges, and read-only game assets, with path containment,
case-insensitive lookup, COOP/COEP, and Wasm MIME types. The async asset client
uses a 16 MiB block cache. Guest file APIs, saving, OPFS import, D3D9 rendering,
audio, game input, threads, full x87 arithmetic, and race flow remain incomplete.

## Further work and evidence

- [Architecture](docs/ARCHITECTURE.md)
- [Binary audit](docs/BINARY_AUDIT.md)
- [Verified status](docs/VERIFIED_STATUS.md)
- [Next executable task](docs/NEXT_TASK.md)

Detailed outputs are local-only in `artifacts/`, `generated/`, and `build/`.
Original assets, generated game code, memory images, test profiles, and SDK
downloads are ignored by Git. Never publish those directories or run bundled
installers. The original installation and Windows saves remain read-only.
