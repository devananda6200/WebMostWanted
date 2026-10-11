# AI usage for source reconstruction

## 2026-10-11T03:27:48+05:30 — completed automatic export

Codex ran and inspected all five Ghidra analyses and exports, preserved their warnings and address indexes, and validated 27,112 function files plus 1,309,073 original-byte instruction records. It rehashed all 1,363 original files with no changes and documented limitations and the installed library export lookup sources. All analyses finished without timeout; human review is pending.

Correction: the first full validation scan was cancelled because repeated Windows path resolution was slow. Exact filename validation and reparse-point checks replaced that repeated work; the rerun passed. The raw decompiler hash uses signed arithmetic, so only the separately authored unsigned reconstruction is covered by the 1,264 Wasm comparisons. No full-game equivalence is claimed.

## 2026-10-11T03:18:23+05:30

Task: recover source-like code from the supplied game for future WebAssembly work.

Codex inspected repository rules and existing uncommitted work, authored the local extraction/export/validation tools, downloaded and checksum-verified official Ghidra, extracted binary evidence, and reconstructed one small byte-string hash routine. It preserved the existing browser-port work and original game inputs. No sub-agents were used.

Checks: 1,363-file SHA-256 inventory, PE extraction for five binaries, Python syntax checks, and 1,264 original-x86-versus-Node-Wasm return-value/input-preservation cases passed. Full Ghidra export and integrity validation are pending.

Corrections: resumed the slow tool download using validated HTTP ranges; added an explicit emulator return-address check and stale-export-summary protection.

Human review: pending. Automated decompilation is inferred, unverified source-like output; it is not exact original source or a complete browser port.
