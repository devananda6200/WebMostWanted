# Verified results — 2026-10-11

The private original-game MVP reached manual acceptance: the user confirmed driving controls, music/engine sound, finishing a race and restarting it. This is **user-confirmed gameplay acceptance**, not an automated finish-line assertion. The agent directly observed the original title, original settings menus and an original car/world/HUD rendered by the compiled runtime.

The user's reply to the bundled acceptance question was: **“yes everything worked correctly”**. That question explicitly asked about acceleration, braking, steering, music/engine sounds, race finish and restart. The user had requested control of testing and that the game remain running, so the agent stopped sending input. The exact event name, finish time, final placing and restart network trace were not recorded.

## Build and execution

| Check | Result | Evidence |
|---|---|---|
| Original executable identity | PASS, exact upstream SHA-256 | `artifacts/pe-audit.json`, `inventory.json` |
| Existing Ghidra project export | PASS, 25,768/25,768 functions, zero failed decompilations | `artifacts/ghidra-export.log`, exported summary |
| Static translation | PASS, 36,690 emitted functions, 185 chunks, 42,544 entries | upstream `build/recomp/translate-report.json` |
| Translator limits | 17 recovery diagnostics; no reported translation failures, unmodelled instructions, table gaps or undecoded records | Full report retained; counts do not prove semantic completeness |
| Full Emscripten/WebGPU build | PASS, exit 0 | `artifacts/build-latest.json`, `build-20261010T234814Z.log` |
| Wasm debug compaction | PASS, retained sections unchanged; 561,083,929 -> 152,284,486 bytes | `artifacts/wasm-compaction.json` |
| Actual compacted build boot | PASS, original code reached rendered world | `artifacts/first-world.jpg`, `world-console.json` |
| HTTP/path/range regression suite | PASS, 3 tests | `python -m unittest discover -s tests -v` |
| Upstream game configuration suite | PASS, 4 tests | `.venv/Scripts/python.exe -m pytest -q reference/nfsmw-recomp/tests` |

A successful build is an execution milestone, not a complete correctness proof. Generated code was never hand-edited, and no native gameplay process or streaming service was used.

## Chrome and automatic asset delivery

Chrome 155 on Windows, AMD RDNA3 adapter. Secure context, cross-origin isolation, SharedArrayBuffer, worker execution and a real WebGPU buffer write/completion passed. Browser test evidence is in `artifacts/browser-assets.json`.

| Check | Measured result |
|---|---|
| Automatic acquisition | 1,356 files / 3,024,656,547 bytes verified in real OPFS |
| Interrupted transfer | Worker terminated after 21,340,664 verified bytes |
| Resume | Reused those 21,340,664 bytes; downloaded remaining 3,003,315,883 bytes |
| Subsequent cache validation | Downloaded **0** asset bytes; reused all 3,024,656,547 bytes |
| Deliberate browser-copy corruption | Modified one byte of `00000000.256`; repaired that 1,091,256-byte file and reused the other 3,023,565,291 bytes |
| Complete diagnostic run | PASS, 87.42 seconds for the combined local tests on this machine |
| Original installation/saves | Read-only; corruption test touched only OPFS's game-asset copy |

The full content is cached before runtime startup. A versioned manifest is fetched again on Play. No file chooser/import flow is required. The runtime's profile path is separate from downloaded assets; persistent-save contents across a full browser shutdown were not independently inspected.

## Original gameplay acceptance

| Criterion | Status and source |
|---|---|
| Original title | Agent-observed; `artifacts/boot.jpg` |
| Original menus | Agent-observed original Options/Video menus |
| Original car and track/world | Agent-observed 3D scene, traffic, HUD and navigation marker; `first-world.jpg` |
| Trusted keyboard events reach canvas | Measured in DOM diagnostics |
| Acceleration / braking / steering | User-confirmed working |
| In-game music and engine sounds | User-confirmed working; SDL sink initialization also measured |
| Race start and finish | User-confirmed working; no automated finish/placing capture |
| Restart | User-confirmed working; separate cache test proves zero-download reuse |
| No native gameplay streaming | Runtime built from translated original code; local Wasm/WebGPU path and original OPFS file reads observed |

The original VP6 intro/attract movies rendered during boot, but those were not counted as gameplay. Acceptance requires the later original 3D world and the user's race test.

## Diagnosed issues and remaining limits

1. **Browser presentation throttling:** The initial run delivered approximately 1 animation callback/second even though DOM visibility/focus reported true; ordinary 100 ms timers still ran at 10 Hz. A separate control page without the game, Wasm or WebGPU reproduced it (`browser-timing-control.json`). Foregrounding the Chrome window resolved it to approximately 30 callbacks/second. This was not bypassed by changing game timers.
2. **Scene performance:** Observed original scene throughput varied roughly 12–29 new frames/second while display callbacks were near 30 Hz. The presenter logged dropped frames and some 250 ms target-pool stalls. No stable performance target is claimed.
3. **Audio diagnostics:** The sink reports many empty-queue observations and some late pulls. Reading the implementation showed that `starved` counts a queue empty at callback entry, not proven silence. The user's listening test passed; detailed PCM fidelity and long-session crackle analysis remain open.
4. **Runtime fallback:** Logs show dynamically generated/copied guest thunks not handled by the small thunk prober. The runtime then attempts its interpreter fallback. These warnings alone are not proof of dropped execution or a crash. Optional API stub messages remain.
5. **Known upstream race-loading spin:** Source review confirms the `00684710` tree walk, its links and caller `00684b60`. The specific upstream malformed-tree stall was not isolated in this session; the user's successful race does not prove the intermittent bug is eliminated. Next valid investigation if reproduced: capture guest PC/thread/stack, tree root/sentinel links and producer writes in `00684b60`, `00684ae0`, `006846a0`, compare original disassembly, and check the cooperative scheduler. Do not increase a timeout or force a race-state transition.
6. **External exception:** `M_ID` errors came from a Chrome extension URL (`executors/200.js`); no matching game-source exception was found. Extensions/security settings were not modified.
7. **Deployment scope:** Only private loopback delivery is provided. Licensed public asset distribution, HTTPS hosting/authentication, cross-device operation, multiplayer and broad hardware/browser qualification are not implemented.

## Repeat the measured checks

From the inner project folder, with the local server running:

```powershell
python -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pytest -q reference/nfsmw-recomp/tests
```

Open `/diagnostics.html` only when the game is closed to repeat the worker/OPFS tests. Open the launcher and click Play to repeat normal startup. Keep Chrome visible, use Enter/arrows/Escape in the original front end, select an original Quick Race, drive the event to its results screen and restart. Capture the actual result screen and race name on the next supervised run to strengthen the current user-reported finish/restart evidence.
