# Codex task — NFS Most Wanted (2005), actual game in Chrome

## Goal
Reverse-engineer my existing **PC Black Edition** installation and use static recompilation to get the **same original game** running locally in Google Chrome. We are not making a lookalike. The user should not have to install Windows software, choose game files, or upload an archive in the browser. Ultimately the site must deliver executable runtime and game assets automatically over HTTPS and render via WebGPU; it must not stream video from a PC. Start by proving this on my local development machine. Never claim public distribution of proprietary game data is permitted without appropriate rights.

## My installation
`C:\Users\festi\Downloads\WebMostWanted\NFS-Most-Wanted-2005\Need For Speed Most Wanted Black Edition`

## Public technical references
- https://github.com/veritr1x/nfsmw-recomp (existing *experimental* static recompilation for this version)
- https://github.com/veritr1x/recomp-kit (x86 translator, PE loader, Win32 / D3D9 shims, SDL/WebGPU browser host)
- https://github.com/s-b-repo/nfsmw-re (function and subsystem reverse-engineering notes)
- https://github.com/TsyVM/MWEncyclopedia (file formats and game engine reference)

## Stage A — inspect the ACTUAL installation before coding
1. Confirm the directory is readable. Run `inventory_game.py` provided with this workspace, or equivalent, to record each file's relative path and byte size, extension summary, and SHA-256 of `speed.exe`. Do not move any game files into version control. Compare the executable hash against the reference `80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c` and identify mismatches explicitly.
2. Analyze PE architecture with Ghidra (PE32 x86, imports, sections, entry point, strings, vtables, xrefs, resources). Identify executable version and differences from reference. Produce `docs/engine-map.md` with tested facts and separate inferences.
3. Catalog `CARS/`, `FRONTEND/`, `GLOBAL/`, `SOUND/`, `TRACKS/` and any other directories actually found. Classify only verified formats. Map how these assets are loaded (e.g. `.bun`/`.bin`, textures, UI, audio/video) and document dependency ordering and case sensitivity.

## Stage B — reproduce a working original-game browser runtime
1. Clone `nfsmw-recomp` with `--recurse-submodules` into an isolated reference/working directory and check the commit and license. Use its existing translator and compatibility implementation rather than inventing an entire new emulator. Preserve upstream attribution.
2. Read upstream README, `game.toml`, `docs/analysis.md`, `kit/README.md`, web launcher and host source code. Identify working macOS/Linux+Emscripten build prerequisites and Windows/WSL2 adaptations. Install/test Ghidra, Python 3, CMake, Ninja and emsdk as needed; do not claim a verified build if any prerequisite is unavailable.
3. Run supported analysis -> translation -> WebAssembly build, retaining logs. Attempt a browser launch with locally acquired game files. The existing launcher imports files into OPFS; keep that flow as a baseline for diagnosis only.
4. Check Chrome WebGPU, COOP/COEP, WasmFS, pthreads, D3D9->WebGPU shader backend, input, audio and workers. Collect console logs, failing requests, frame timing and crashes.

## Stage C — remove MANUAL import without changing gameplay
1. Implement an **automatic asset delivery** path for a **private, authorized local asset server**. Generate a versioned manifest from local files with safe, relative paths, byte sizes and checksums, and exclude anything not needed by the port.
2. Browser launcher fetches manifest and streams required assets into the browser's origin-private filesystem, preserving the layout that the recompilation's virtual filesystem expects. Report download and validation progress, support resumable downloads and HTTP range requests when sensible, and cache successful assets. Do not load everything into one JS ArrayBuffer. Keep saves in a separate persistent OPFS area.
3. On the first visit, clicking Play should automatically acquire the needed resources from the permitted server. On later visits it should reuse valid browser cached assets. No input type=file, folder chooser, native installer, or cloud streaming.
4. Serve from localhost with HTTPS or secure-context provisions and Cross-Origin-Opener-Policy: same-origin plus Cross-Origin-Embedder-Policy: require-corp, along with correct wasm MIME type. Ensure workers, fetch and WebGPU work.
5. For deployment to the public, require a licensed asset distribution mechanism. Do not commit, publicly deploy or share `speed.exe`, translated proprietary code, licensed soundtrack or EA-owned assets without the necessary rights.

## Stage D — original gameplay MVP
1. Boot original front-end and menus in Chrome, then select an original Quick Race and attempt one full event.
2. Diagnose known intermittent race-loading spin/hang reported by upstream (do not simply increase timeouts). Investigate worker scheduling, race state, Direct3D9 shim behavior, asset readiness, and logging that changes timing.
3. Validate: original game title screen; original menus; loaded original car/track; acceleration/braking/steering; in-game audio where possible; race start; finish; ability to restart without fresh asset import. Provide repeatable pass/fail evidence.
4. Do not use mock races, fake progress, screenshots, video playback, WebRTC streaming or a lookalike as a substitute for running translated original game code.

## Deliverables and operating principles
- Maintain clear logs, `docs/engine-map.md`, `docs/file-inventory.md`, `docs/browser-runtime.md` and `docs/test-results.md`.
- Show exact commands and environment prerequisites on Windows/WSL2; distinguish tested from untested.
- Fix one blocker at a time. If executable hash differs, determine what adaptation is required before attempting translation.
- Expose the current actual working result, current blocker and next smallest valid experiment. Avoid unsupported claims of complete browser playability or performance.
