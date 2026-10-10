# Source reconstruction change log

## 2026-10-11T03:27:48+05:30 — full automatic export and integrity validation

- Completed Ghidra analysis and C-like export for all five supplied PE files: 27,112 recognized functions, zero decompilation failures, 1,951 functions with warnings/diagnostics. Saved all five analysis databases.
- Verified every one of 1,309,073 exported instruction records against original PE bytes, all function files/counts and raw extracted resources; rehashed all 1,363 originals and confirmed unchanged hashes, sizes and modification times.
- Recorded official tool provenance and 16 installed system-library files consulted for export names in `evidence/analysis_environment.json`. Windows library signatures are analysis aids, not recovered game source.
- Corrected a slow validator by replacing repeated deep-path resolution with exact address filenames, a resolved function directory and reparse-point checks. Cancelled the earlier slow scan, then completed the optimized validation successfully.
- Validation: Ghidra Java exporter ran successfully; Python tools and PowerShell runner executed; 1,264 focused hash Wasm/reference cases pass; original files unchanged. The export has no analysis timeouts.
- Limitations: this is inferred, unverified decompiler output; global/ABI/indirect-call recovery, assets, complete semantic checking and browser platform implementation remain. No exact original source, full game build or playable port. Human review pending.

## 2026-10-11T03:18:23+05:30 — initial recovery tools and limited Wasm proof

- Added local PE inventory/extraction, pinned Ghidra download, function/assembly exporter, headless runner, export validation, and source-recovery documentation.
- Reason: make a reproducible, address-linked starting point for the requested source reconstruction.
- Validation: inventoried and SHA-256 hashed 1,363 original files (3,025,210,311 bytes); extracted all five PE files; Python syntax checks pass; reconstructed hash return values and unchanged input match original x86 emulation in 1,264 Node Wasm cases. The reference must reach its return address. Official Ghidra archive checksum passed.
- State: Ghidra whole-program analysis/export is running. Java exporter and full export-integrity validation are pending. No complete recovered source or playable Wasm game is claimed. Human review pending.
