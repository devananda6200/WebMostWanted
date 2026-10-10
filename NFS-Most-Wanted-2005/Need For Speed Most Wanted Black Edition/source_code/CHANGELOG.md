# Source reconstruction change log

## 2026-10-11T03:18:23+05:30 — initial recovery tools and limited Wasm proof

- Added local PE inventory/extraction, pinned Ghidra download, function/assembly exporter, headless runner, export validation, and source-recovery documentation.
- Reason: make a reproducible, address-linked starting point for the requested source reconstruction.
- Validation: inventoried and SHA-256 hashed 1,363 original files (3,025,210,311 bytes); extracted all five PE files; Python syntax checks pass; reconstructed hash return values and unchanged input match original x86 emulation in 1,264 Node Wasm cases. The reference must reach its return address. Official Ghidra archive checksum passed.
- State: Ghidra whole-program analysis/export is running. Java exporter and full export-integrity validation are pending. No complete recovered source or playable Wasm game is claimed. Human review pending.
