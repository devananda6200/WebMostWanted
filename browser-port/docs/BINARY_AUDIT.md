# Installation audit

Observed 11 October 2026, 00:29 IST (UTC+05:30), using Python 3.11,
pefile 2024.8.26 and Capstone 5.0.7. All original files were opened read-only;
no original executable, DLL, installer, or script was executed. The selected
installation comes from `NFS_GAME_ROOT` or ignored `config.local.json`.

## Reproduce

From `browser-port` in PowerShell:

```powershell
.\.venv\Scripts\python.exe tools/audit_installation.py
.\.venv\Scripts\python.exe tools/audit_installation.py --startup-output artifacts/startup-analysis.json --function 0x665fc0 --function 0x6cbc00 --function 0x7d0d60 --pointer-table 0x8eb168:0x8eb180 --pointer-table 0x8ea000:0x8eb164
.\.venv\Scripts\python.exe -m unittest tests.test_audit -v
```

The additional function addresses below are verified against the `speed.exe`
SHA-256 in this report only. Re-audit any different executable before using them.
`artifacts/audit.json` contains the complete inventory, directory totals,
EXE/DLL hashes, PE metadata, imports, exports, debug references, resources, TLS,
relocations, heuristic indicators and sample asset signatures. Optional
`artifacts/startup-analysis.json` contains bounded static instruction analysis.
Both are ignored local evidence. This document contains metadata and conclusions,
not executable bytes or generated game code.

Eleven synthetic audit/configuration tests passed. They cover PE metadata, malformed
input reporting, output-path protection, config precedence, unchanged original
test bytes/timestamps, interface classification and bounded disassembly. The
real audit observed unchanged file sizes and modification timestamps before and
after inspection; this is not a guarantee against concurrent external writes.

## Executable identity: verified

| File | Size (bytes) | SHA-256 |
| --- | ---: | --- |
| `speed.exe` | 6,029,312 | `80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c` |
| `server.dll` | 380,928 | `c4fdd0e9e779be7f4be7728b03339eda4fd27248ceb9d2c640403b8fc90587ff` |
| `nfsmwres.exe` | 36,864 | `6ebf62cf48a79f9a5e93b60240cfc01f21df6b0ebdd8fadb926e31c5e82e4247` |
| `safemode_inst.exe` | 40,960 | `652481c95e3db9e52eb6bdd62c981d377037b9850a1cb3f3714d128922802380` |
| `shell_inst.exe` | 40,960 | `0c125958dc0191e59cbd1f68335674ad4a3e42f46f502eab980e4899bbd7bead` |

All five are PE32 i386 images. `speed.exe` is a GUI-subsystem image at base
`0x00400000`, entry RVA `0x003c4040` / VA `0x007c4040`, with declared image size
`0x00678e4e`. Its linker-version field is 7.10. It has no version-string resource,
no exported symbols, no COFF symbols, no TLS directory, and no base-relocation
directory. An RSDS debug record names `NfsMWCollectorsRelease.pdb`; the PDB itself
is absent. No `.pdb`, `.map`, or `.dbg` file was found in this installation.
The folder label and embedded strings do **not** authenticate a release/patch
number or provenance. This project must identify the binary by hash.

| Section | RVA | Virtual size | Raw size | Permissions | Entropy |
| --- | --- | --- | --- | --- | ---: |
| `.text` | `0x1000` | `0x48e2a5` | `0x48f000` | read, execute | 6.5135 |
| `.rdata` | `0x490000` | `0x5971d` | `0x5a000` | read | 5.3634 |
| `.data` | `0x4ea000` | `0xdce10` | `0x24000` | read, write | 3.9560 |
| `.rsrc` | `0x5c7000` | `0x7064e` | `0x71000` | read | 3.6328 |
| eight-space name | `0x638000` | `0x40e4e` | `0x41000` | read | 6.4728 |

No section is simultaneously writable and executable. No overlay or certificate
table was found; pefile reported no parser warnings. These facts favor starting
with ordinary static decoding, but do not prove the absence of runtime-generated
code, protection logic or indirect dispatch. `VirtualAlloc`, `VirtualProtect`,
`LoadLibraryA` and `GetProcAddress` are imported. The unusual last section name and
non-page-aligned declared image size are observations, not a protection diagnosis.
No licensing or protection behavior was modified or bypassed.

## Dependencies and platform boundaries

`speed.exe` has 300 import entries across 14 DLLs, with no delay-import directory.
None of those DLLs are bundled in the selected folder. These are static imports;
actual loading and selected-race reachability remain unverified.

| DLL | Import count | Verified interface evidence | Planned MVP handling, not yet verified |
| --- | ---: | --- | --- |
| `KERNEL32.dll` | 157 | Files, heap/VM, threads, events, TLS, timing, loader, process APIs | Implement encountered contracts with guest addresses and explicit failures |
| `d3d9.dll` | 1 | `Direct3DCreate9` | D3D9 object/ABI layer backed by WebGPU |
| `d3dx9_26.dll` | 13 | Effect creation/pools and matrix/vector operations | Adapt required math and compiled effect/shader behavior |
| `DINPUT8.dll` | 1 | `DirectInput8Create` | Map required DirectInput interfaces to browser input |
| `USER32.dll` | 41 | Window/message and keyboard APIs | Browser window/input host with verified callback ABI |
| `ADVAPI32.dll` | 6 | Registry key creation/open/query/write/close | Browser-local settings with verified registry contracts |
| `SHFOLDER.dll` | 1 | Shell-folder path lookup | Separate browser-local profile/save namespace |
| `SHELL32.dll` | 1 | Shell execution | Explicit unsupported/excluded policy after call-path analysis |
| `DSOUND.dll` | 2 | Ordinal imports 1 and 6 | Resolve the exact contracts before replacing with browser audio |
| `WINMM.dll` | 24 | Timers, wave input/output | Browser timing/audio; microphone necessity unverified |
| `GDI32.dll` | 12 | Fonts, text, bitmaps and drawing | Translate only required initialization/UI behavior |
| `TAPI32.dll` | 9 | Telephony APIs | Exclude only after offline selected-path reachability is established |
| `NETAPI32.dll` | 1 | `Netbios` | Same reachability requirement; no fake network success |
| `WS2_32.dll` | 31 | Winsock networking/event APIs | Disable optional online flow through proper failure contracts |

The bundled `server.dll` imports Winsock/Kernel32/NetAPI and exports
`IsServerRunning`, `StartServer`, `StopServer`. Its debug record names LANServer.
`speed.exe` does not statically import it. A runtime loading path has not yet been
established. The other EXEs are not game-startup dependencies established by this
audit. `nfsmwres.exe` labels itself a ToCA EDIT utility and imports `MSVBVM60.DLL`;
that self-description is unauthenticated. Installer-named EXEs remain unexecuted.

The game embeds 31 named `RT_RCDATA` resources ending in `_FX`, totaling 455,140
bytes. Examples include `IDI_CAR_FX`, `IDI_WORLD_FX`, `IDI_WORLDNORMALMAP_FX`,
`IDI_FE_FX` and depth/shadow variants. Combined with
`D3DXCreateEffectFromResourceA`, these support the hypothesis that the rendering
path needs an embedded D3DX effect adaptation layer. Their exact shader format,
profiles, passes and runtime usage still need validation. The `.fx` files under
`SOUND/FXEDIT` have audio-oriented names and binary headers; their extension alone
must not be taken to mean HLSL source.

## Installation data

There are 1,363 files totaling 3,025,210,311 bytes. No symlink/junction/reparse
points were encountered. All directory/file details are in the ignored report.

| Directory | Files | Bytes |
| --- | ---: | ---: |
| `CARS` | 344 | 390,153,664 |
| `FRONTEND` | 9 | 63,192,835 |
| `GLOBAL` | 39 | 53,503,164 |
| `TRACKS` | 273 | 621,656,659 |
| `SOUND` | 530 | 950,176,167 |
| `MOVIES` | 32 | 897,524,536 |
| `NIS` | 87 | 40,403,632 |

Observed resource families: 679 `.bin`, 101 `.bun`, four `.lzc`, 301 `.abk`,
160 `.gin`, two `.big`, 32 `.vp6`, one `.mus` and one `.mpf`.
Sample `.lzc` headers identify `JDLZ`; sampled `.big` files begin `SCHl`, sampled
`.abk` files `ABKC`, `.gin` files `Gnsu20`, and movie files `MVhd`. These signatures
are verified observations, not complete validated format specifications. Do not
apply a generic BIG archive parser merely because of the extension.

There are 86 zero-length files, including `FRONTEND/FRONTA.BUN`,
`TRACKS/LOC2DYNTEX.BIN`, and assorted cosmetic/car resources. Their necessity and
whether they are intentional placeholders remain unverified. Do not silently
fabricate replacements. Important observed resource names include
`GLOBAL/gameplay.bin`, `GLOBAL/gameplay.lzc`, `GLOBAL/attributes.bin`,
`GLOBAL/FE_ATTRIB.bin`, `GLOBAL/HUDTEXRACE.BIN`, and `TRACKS/L2RA.BUN` plus per-event
minimap files. These are candidates for selected-race dependencies, not proof of
the required preload set. The minimum working set must come from actual loader
tracing rather than importing all 3.0 GB into Wasm memory.

`server.cfg` is present. `MEMCARD/LOCALE_ENGLISH.loc` has a `LOCH` header; its name
is insufficient evidence of a player-save format. No external Windows profile
or save directory was inspected, copied or modified.

## Bounded translation targets and startup findings

An actual leaf routine is at VA `0x00460bf0`, RVA `0x00060bf0`, length 33 bytes,
SHA-256 `c5798f0490c6fc265ff0ebd063a7c536e8281fb2789eb4434900ebb3d3896808`.
Its 14 decoded instructions form a NUL-terminated byte loop with no imported
calls. Static semantics indicate a 32-bit rolling hash, seed `0xffffffff`,
multiply by 33 then add each unsigned byte. The first argument is at `[esp+4]`
and result in EAX; it does not write input memory. Empty input preserves ECX's
upper bits, unlike nonempty input. Compare complete relevant registers, defined
flags and memory against reference execution, including empty/high-byte/overflow
inputs. Function purpose is inferred from instructions, not debug symbols.
The integration owner's differential results are recorded separately in
[VERIFIED_STATUS.md](VERIFIED_STATUS.md).

The bounded entry analysis recovers 125 statically reachable instructions using
direct branches. It does not execute them or resolve exception-handler flow.
The entry immediately installs an `FS:[0]` structured-exception frame and calls
a stack-probe helper at `0x007c94b0`. The first directly imported call is
`GetVersionExA` at `0x007c4089`, through IAT slot `0x008900e0`.

Before the application transfer, the normal branch includes these observed
helpers and API references:

1. `0x007c42a0`: `GetModuleHandleA` plus inspection of the loaded image's PE headers.
2. `0x007cd4b0`: `HeapCreate`, with a failure cleanup using `HeapDestroy`.
3. `0x007ccf60`: thread state and dynamically looked-up `FlsAlloc`, `FlsGetValue`,
   `FlsSetValue`, `FlsFree` from `kernel32.dll`; a TLS fallback exists. Its
   indirect callback storage must be initialized correctly.
4. `0x007cce50`, then `0x007cca20`: startup/file-handle preparation including
   `GetStartupInfoA`, `GetFileType`, `GetStdHandle`, `SetHandleCount`.
5. `GetCommandLineA`, then `0x007cc800`: environment-string retrieval, conversion
   and release; `0x007cc3a0`: module filename/argument handling; `0x007cc220`.
6. `0x007ca2c0`: initializer iteration with indirect callbacks. Initial table
   `[0x008eb168,0x008eb180)` has six slots and five nonzero targets. Table
   `[0x008ea000,0x008eb164)` has 1,113 slots and 870 distinct nonzero targets.
   Callback slot `0x0090623c` initially points to `0x007c4360`. These callbacks
   have not been translated or dynamically validated; skipping them is not a
   justified initialization shortcut. The earlier `0x007cce50` helper uses equal
   initial range bounds `0x008c8738`, so that particular range is empty.
7. At `0x007c41be`, a three-argument call to `0x00666590`. This resembles a
   C `main` boundary; calling it `WinMain` would be an unsupported assumption.

At `0x00666590`, the code passes the string `speed.exe` and a flag to
`0x006cbc00`. That helper enumerates process names via
`CreateToolhelp32Snapshot`, `Process32First`, and `Process32Next` import thunks
and compares a matching count with the provided threshold. This supports the
duplicate-process-check interpretation, not a licensing conclusion. It then
calls `0x00665fc0` with two incoming arguments. That latter
routine calls dozens of application helpers, whose identities are not yet
established. The enclosing application loop already contains x87 comparisons,
status-word transfer, multiply and float-to-integer conversion. Integer-only
translation cannot run this path correctly. An observed update call is
`0x00663d30`; it is not yet verified as a complete game tick.

These are static call-site observations. Which branches run, the direct race
entry, essential race state, car/track selection, resource order and callback
targets remain unverified. No startup, menu, initialized race or gameplay result
is claimed by the audit. The shortest legitimate path currently supported by
evidence is to preserve normal CRT/application initialization and trace its
first failures; a direct quick-race jump has not been justified.
