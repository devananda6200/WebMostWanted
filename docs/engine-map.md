# Engine map and evidence

Measured against the supplied installation on 2026-10-11. This is a static recompilation of original x86 instructions, not recovered EA source code. Ghidra pseudocode is analysis material; the kit translates the instruction listings and PE bytes into C, then Emscripten compiles them.

## Verified executable

`speed.exe` is 6,029,312 bytes. SHA-256 `80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c` exactly matches the pinned upstream executable. It is PE32/i386, image base `00400000`, entry `007c4040`, linker 7.10, link timestamp 2005-12-01 01:06:20 UTC. There is no version resource: the filename/installation label alone does not independently establish its patch level. See `artifacts/pe-audit.json` for reproducible section/import/resource measurements.

| Section | VA | Virtual bytes | File bytes |
|---|---|---:|---:|
| .text | 00401000 | 4,776,613 | 4,780,032 |
| .rdata | 00890000 | 366,365 | 368,640 |
| .data | 008ea000 | 904,720 | 147,456 |
| .rsrc | 009c7000 | 460,366 | 462,848 |
| unnamed | 00a38000 | 265,806 | 266,240 |

The original contains 300 imports from 14 DLLs. Important boundaries are D3D9/D3DX9 effects, DirectInput8, DirectSound/WinMM, Kernel32 threads/files/time, and User32 windows/messages. Import counts alone do not prove complete shim behavior. Current startup reports unimplemented `LightEnable`, `SetFVF`, and some optional dynamic Kernel32 lookups.

Ghidra 12.1.4 re-exported the existing analyzed program read-only with upstream `ExportProgram.java`: 25,768 discovered functions, 25,768 pseudocode exports, zero failed decompilations. This reused an existing audited analysis rather than rerunning upstream's Ghidra 12.1.3 download wrapper. Zero failures does not establish semantic correctness. The actual build recovered additional instruction blocks: 36,698 parsed functions, 36,690 emitted functions and 42,544 dispatcher entries. Seventeen recovery diagnostics remain; see the complete translation report.

## Recovered code relationships

Addresses and names below are analytical labels, not a claim to original source symbols.

| Address/evidence | Direct observation | Interpretation/limit |
|---|---|---|
| `007c4040` | Initializes CRT heap, threads, arguments and environment; calls `00666590` | CRT entry into game startup; not itself the frame loop |
| `00664780` | References GlobalMemoryFile, ATTRIBUTES, GLOBALB.LZC, shared car parts, DYNTEX, widescreen bundles, FE_ATTRIB | Shared asset initialization with explicit loading barriers |
| `00664670` | References `frontend.bin` and `frontend.vlt`, releases objects | Front-end attribute cleanup/lifecycle, not proven to be its initial loader |
| `00510a40` | References `TRACKS\\L2RA\\TrackMaps.bin` three times and releases state | Track map lifecycle; callers/context needed before assigning a stronger name |
| `008abca0 -> 00690100` | Original pointer and disassembly verified | Actual function boundary, not the obsolete mid-instruction seed `00690200` |
| `008f7df0 -> 004497b0` | Pointer/disassembly verified | Chunk tag comparison includes `80037050` |
| `00895964 -> 00498dc0` | Pointer/disassembly verified | x87 comparisons; stronger semantic name not established |
| `00684710` | Follows tree node links and compares keys; inserts through `00683770` | Upstream's reported race-loading spin site; not a timeout loop to bypass |
| `00684b60` | Looks up data and calls `00684710` | One producer/caller to instrument if the race stall is reproduced |

Source evidence lives in ignored `reference/nfsmw-recomp/analysis/decompiled/speed.exe/functions/` and `strings.tsv`. The PE audit independently checks the three vtable slots. Existing sentinel globals/hooks in `game.toml` and `globals.toml` remain unidentified; they have not been renamed into supposedly verified engine state.

## Actual asset signatures and loading

See [file-inventory.md](file-inventory.md) for every directory total and `artifacts/asset-headers.json` for sampled bytes. Format statements apply to inspected samples, not every file sharing an extension.

| Samples | Observed bytes | Supported conclusion |
|---|---|---|
| `FrontB.lzc`, `gameplay.lzc`, `GlobalB.lzc` | `JDLZ` | JDLZ wrapper present; decoded by original game logic |
| demo `.bun` files | Chunk header, then `JDLZ` | Chunked container with compressed content |
| car geometry/vinyl `.bin` | Numeric chunk tags/lengths | Structured binary chunks, not one universal BIN format |
| `.vp6` movies | `MVhd` and `06PV` | EA movie container carrying VP6-labelled content; guest decoder runs |
| engine `.abk` | `ABKC` | Audio-bank container signature |
| engine `.gin` | `Gnsu20` | Ginsu-labelled engine sample data |
| speech/stream `.big` | `SCHl` | EA audio chunk stream; do not assume generic BIG archive |
| credits | `ff fe` then UTF-16LE text | UTF-16LE text |
| `00000000.256` | `BM` | Bitmap header despite the extension |
| PE `IDI_*_FX` resources | Binary `01 09 ff fe` prefix | 31 compiled effect resources, not plain shader source |

The source of truth for initial dependency order is `00664780`: global memory/attributes, GLOBALB, brake geometry/textures, completion barrier, dynamic textures and screen-format bundle, completion barrier, shared car textures/wheel/spoiler/roof geometry, further completion barrier, then front-end attributes. This is a static code observation; a complete per-race live asset-access trace is still needed.

Paths mix case and slash styles (`Global\\GlobalMemoryFile.bin`, `GLOBAL\\GLOBALB.LZC`, `TRACKS/L2RA_Sunset.BUN`). Delivery preserves disk spelling. The runtime's Windows path layer resolves names case-insensitively over case-sensitive OPFS. The manifest rejects case-folding collisions and never rewrites names. All allowlisted assets are verified before boot, so race streaming reads local OPFS rather than racing HTTP downloads.

## Reference assessment

- [nfsmw-recomp](https://github.com/veritr1x/nfsmw-recomp), commit `bb95925d5b58656b8b23e9df6eb0c9647be1bece`: the actual game configuration, recovery seeds, core adaptations and native hot paths used here.
- [recomp-kit](https://github.com/veritr1x/recomp-kit), submodule commit `eb32cc42623e0e9e868b9d27423a57d5a5cba56b`: translator, guest runtime, compatibility shims and browser host used here. Original guest state remains 32-bit addresses in guest memory.
- [nfsmw-re](https://github.com/s-b-repo/nfsmw-re): useful function/subsystem research, based on its own installation and mod context. Labels require checking against this executable. It is not a complete buildable replacement.
- [MWEncyclopedia](https://github.com/TsyVM/MWEncyclopedia): format/engine research with varying evidence levels. It is not a static recompilation pipeline.

Upstream implementation is MIT-licensed with its existing notices retained. That does not relicense EA's executable, translated proprietary code, textures, models, videos or soundtrack. No assets or derived build have been publicly uploaded.
