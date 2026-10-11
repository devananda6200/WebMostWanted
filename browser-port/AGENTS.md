# Browser port engineering

Read the parent AGENTS.md and RULES.md. The original installation is read-only.
Resolve its path from NFS_GAME_ROOT or ignored config.local.json; never embed a
machine path in implementation code. Never execute bundled installers or scripts.

- Source/tools belong in Git; original assets, executable-derived output, dumps,
  local toolchains, profiles, and large logs belong in ignored directories.
- Guest addresses are uint32 values, never host pointers. Validate memory access.
- Fail on unsupported required operations, recording guest address and CPU state.
- Keep translation rules in translator/, regenerate generated/; no manual patches
  to generated code. Browser gameplay must use Wasm and remain browser-local.
- Record measured outcomes in docs/VERIFIED_STATUS.md, executable identities in
  docs/BINARY_AUDIT.md, and the next exact command in docs/NEXT_TASK.md.
- Run focused differential tests after translation changes and server security
  tests after resource-serving changes. Add verified commands here as they exist.
- The integration owner maintains parent CHANGELOG.md, AI_USAGE.md, README.md,
  submission status, and commits. Delegated tasks must not commit independently.

Verified entry points from browser-port: scripts/setup.ps1, scripts/environment.ps1,
scripts/build.ps1, scripts/test.ps1, scripts/serve.ps1. Startup probe builds with
scripts/startup.ps1 and currently fails at a required compatibility barrier.
Python tests use unittest discovery (`-m unittest discover -s tests`), not an
assumed tests package. Reload browser after rebuild; restart server for new files.
`startup.ps1 -FromTrace` reuses only matching local execution evidence. Run
`python -m tools.startup_reference` after rebuilding startup to refresh the
prefix suite and its Wasm hash. Generated dispatch uses small page functions;
keep the per-instruction transaction in the outer loop. Win32 state models
one guest thread only; new threads must fail until scheduling is implemented.
`python -m tools.seed_initializers --count 64` adds bounded audited constructor
targets only after a matching untranslated-target fault. It does not execute or
skip constructors. Current startup defaults: 24,000 instructions / 2M dispatches.
Controlled CPU-state injection belongs only to authored synthetic fixtures,
never the original startup/race case. Preserve named oracle discrepancies.
`startup.ps1 -SeedFile` replays immutable `artifacts/startup-seeds/` snapshots;
do not replace that with thousands of command-line seeds. Native authored x87
probes use `python -m tools.native_fpu_reference` with a non-elevated token.
