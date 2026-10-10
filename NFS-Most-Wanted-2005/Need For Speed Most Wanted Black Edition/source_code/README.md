# Local source reconstruction

This directory contains a reverse-engineering workspace for the supplied installation.
**It is not the recovered original source tree, a complete verified reconstruction,
or a buildable WebAssembly game.** No original game files are changed.

The original C/C++ names, types, class layout, comments, project files and source
organization are not fully recoverable from this stripped release executable.
`speed.exe` refers to `NfsMWCollectorsRelease.pdb`, but no matching PDB, MAP or DBG
file exists in the 1,363-file installation. Machine-code semantics remain the
reference when a decompiler's inferred output is ambiguous or wrong.

## Contents

- `recovered/<binary>/all_functions.c`: combined C-like decompiler output.
- `recovered/<binary>/functions/<address>.c`: individual inferred function bodies.
- `recovered/<binary>/functions.tsv`: addresses, names, sizes, signatures, status,
  diagnostics and paths. Inferred names are not evidence of original source names.
- `disassembly.tsv`, `control_flow.tsv`, `indirect_flow.tsv`: instruction bytes,
  analysis-discovered control-flow references and computed call/jump sites.
  These do not resolve every runtime target.
- `inferred_types.h`, `symbols.tsv`, `defined_data.tsv`, `memory_map.tsv`: types,
  symbols, data interpretations and memory layout from Ghidra's program database.
- `executable_noninstruction_ranges.tsv`: executable addresses not classified as
  instructions; these can include padding, data, jump tables or undiscovered code.
- `summary.json`: actual export totals and limitations for each program. Absence
  means that program's export did not finish.
- `projects/`: saved Ghidra databases, preserving cross-references for manual work.
- `evidence/`: original-file SHA-256 inventory, PE metadata, raw sections/resources,
  printable strings, export integrity checks and limited routine test results.
- `reconstructed/hash32.c`: manually reconstructed return-value behavior of the
  33-byte routine at `speed.exe` VA `0x00460bf0`, with binary provenance.
- `tools/`: newly authored reproducible extraction, decompilation and validation tools.

Generated code, original-derived data, tool downloads and project databases are
local ignored outputs. They are not uploaded or published. The parent repository
also ignores the entire original installation. Its existing `browser-port/`
changes are a separate workstream and are preserved.

## Reproduce on Windows

Run these commands from the game installation directory (the parent of this file):

```powershell
python source_code/tools/setup_ghidra.py
& '..\..\browser-port\.venv\Scripts\python.exe' source_code/tools/inspect_inputs.py
& .\source_code\tools\run_recovery.ps1
& '..\..\browser-port\.venv\Scripts\python.exe' source_code/tools/validate_exports.py
& '..\..\browser-port\.venv\Scripts\python.exe' source_code/tools/test_hash32.py
```

Setup downloads Ghidra 12.1.4 from its official release and verifies SHA-256
`ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`.
It resumes its own partial download with bounded HTTP range requests. A checksum
failure stops extraction. It does not install a service or change permanent PATH.

`run_recovery.ps1` needs a full JDK 21. It defaults to the installed Android Studio
JBR; pass `-JavaHome 'C:\path\to\jdk-21'` to use a different JDK. Ghidra settings
and caches are directed into `.tools/ghidra-state/`. Automatic analysis has a
30-minute per-program limit; each function has a 60-second decompilation limit.
Check logs for timeouts or analyzer failures even when an export completes.
Existing projects are exported with `-noanalysis`, preserving manual annotations.
To investigate or change analysis settings, open the corresponding `.gpr` in Ghidra;
the script never overwrites an existing project with a fresh import.

The existing parent project's Python environment supplies pefile 2024.8.26,
Capstone 5.0.7 and Unicorn 2.1.4. The hash test also uses its existing LLVM/Node SDK
at `browser-port/.tools/emsdk-4.0.23`. It compiles the reconstructed C into a small
standalone Wasm module and compares it in Node with original x86 bytes in Unicorn.
It does not execute the original Windows game or auxiliary EXEs on the host.

The inventory excludes `source_code/` and records all original paths, sizes,
modification times and SHA-256 hashes. Re-running it rejects changed originals.
`validate_exports.py` checks every listed instruction's bytes against the supplied
PE, all function files/counts, extracted resources, and the original inventory.
**These checks prove export integrity, not C semantics or complete source recovery.**

## What still needs reverse engineering for a WebAssembly port

The automatic output requires manual recovery of ABI conventions, object layouts,
global data, constructor order, virtual calls, callbacks and undiscovered code.
Decompiled success is not evidence that a function compiles or is correct.
Warnings, undefined operations and failed functions remain visible in the output.
Preserve address-based names until an interpretation has supporting evidence.

The raw resource exports are binary data, not recovered shader/audio source.
Car, world, UI, sound and video formats remain separate reconstruction work.
Static analysis of helper executables does not establish that they are needed
by the game. `nfsmwres.exe` imports the Visual Basic runtime; native decompilation
alone does not reconstruct its original Visual Basic project or any interpreted code.

For Wasm, Windows/D3D9/D3DX9/DirectInput/DirectSound services need browser-compatible
implementations, including asynchronous asset I/O, state, threading and save data.
The existing `browser-port/` work records its own incomplete translation status;
this export neither integrates with it nor makes it playable. No complete game
build, rendering, driving, race or browser gameplay is verified here.

## Tool provenance

- [Ghidra 12.1.4 official release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build),
  Apache-2.0 with bundled component notices; portable local static analysis.
- [Ghidra Java requirements](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GettingStarted.md)
  and [decompiler API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html).
- Existing Python/LLVM/Unicorn tools: see the parent project's
  [dependency record](../../../browser-port/docs/DEPENDENCIES.md).

The input binaries and assets come only from the user's supplied local copy.
No third-party reconstructed game project or leaked source was imported.
See [CHANGELOG.md](CHANGELOG.md) and [AI_USAGE.md](AI_USAGE.md) for this workstream.
