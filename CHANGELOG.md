# Change log

Record each meaningful project change during the event, newest first. Update this file in the same commit as the change. Use a real timestamp with timezone, for example `YYYY-MM-DDTHH:MM:SS+05:30`.

## Event build log

## 2026-10-11T00:38:35+05:30 — audit, binary translation proof, and browser host

- Changed: Added browser-port tools, translator/runtime, PE fixture, differential
  tests, browser worker/WebGPU probes, read-only bounded asset server, PowerShell
  entry points, and architecture/audit/status/dependency documentation. Ignored
  original installation, local toolchain, generated game code, memory images,
  profiles, and diagnostic artifacts.
- Why: Establish executable identity and a tested translation pipeline before
  expanding original startup and race coverage.
- Validation: Audited 1,363 files and five PE identities without executing original
  binaries; native portable Emscripten/toolchain smoke passed; Node and browser
  passed 632 synthetic + 38 real-routine differential cases + four expected faults.
  Browser WebGPU AMD RDNA3 nonfallback device, Emdawn instance, worker, and COOP/COEP
  verified. Focused audit/server/prefix tests passed. Detailed local evidence is
  indexed in browser-port/docs/VERIFIED_STATUS.md.
- Corrections: Exported HEAPU8 explicitly; rejected unsupported prefixes; added
  fault rollback; fixed request-path normalization; reduced diagnostic DOM churn.
- Limitations: M1 verified for a limited instruction subset. Original startup
  reaches GetVersionExA then stops at the required API. No authentic menu, D3D9
  renderer, driving, completed race, native game reference run, or game FPS result.

## Template setup — 10 October 2026

- Changed: Added the event README, rules, agent guide, change log, AI usage record, submission checklist, Git ignore rules, and pull request checklist.
- Why: Give participants a consistent starting point for event rules, basic coding patterns, documented changes, and regular commits.
- Validation: Checked local Markdown links, event detail consistency, required documents, and diff whitespace before publishing.
- Limitations: Documentation scaffolding only; no participant project, application, or working demo is included. GitHub publication and template status are verified separately after creation.
