# Project submission

Complete this file during the hackathon and use it to prepare your submission through the method announced by the organizers. Do not submit your project to the template repository.

## Project

- **Project name:** WebMostWanted
- **Short description:** Local x86 binary-translation infrastructure toward a Most Wanted browser port. The current demo validates translated synthetic and game routines; it is not a playable race.
- **Code repository URL:** https://github.com/devananda6200/WebMostWanted (configured remote; this session's checkpoints are local unless separately recorded).
- **Final submitted implementation commit SHA:** Not submitted.
- **Working demo URL or local demo steps:** [Local setup/demo](browser-port/README.md); open http://127.0.0.1:8000/ and run translation tests.
- **Demo access requirements:** Local legitimate installation matching the audited SHA-256, Windows x64, Python/Git, initial tool downloads, and WebGPU browser. Game-derived artifacts are not published.

## Participants

Participate solo or in a team of up to 4. Remove unused rows.

| Participant name | GitHub handle | Contribution |
| --- | --- | --- |
| Not supplied | Not supplied | Human participation details must be completed before submission |

## Run and demonstrate

- **Prerequisites and versions:** [Pinned dependencies](browser-port/docs/DEPENDENCIES.md).
- **Install command:** In browser-port, `scripts/setup.ps1`.
- **Required environment variable names:** `NFS_GAME_ROOT`, or ignored `config.local.json` using `config.example.json`.
- **Start command:** `scripts/serve.ps1` after `scripts/build.ps1`.
- **Demo walkthrough:** Check browser environment; run translation tests; export local diagnostics; probe original startup to observe its actual compatibility barrier.
- **Checks performed and results:** [Verified status and evidence](browser-port/docs/VERIFIED_STATUS.md).
- **Known limitations or incomplete features:** No menu, playable race, legitimate finish/results, D3D9 rendering, or replay. Not ready as the requested game MVP.
- **Libraries, APIs, and public datasets used:** [Sources/licenses](browser-port/docs/DEPENDENCIES.md); original installation is a local private input, not a redistributed dataset.
- **AI usage record:** [AI_USAGE.md](AI_USAGE.md)
- **Development change log:** [CHANGELOG.md](CHANGELOG.md)

## Submission checklist

- [ ] The project implementation started from scratch at the event.
- [ ] I participated solo or with no more than 4 team members in total.
- [ ] Codex was used during development and its usage is documented.
- [ ] The code repository URL, short description, and working demo are provided.
- [ ] README setup and demo instructions match the submitted code.
- [ ] Actual checks and known limitations are documented.
- [ ] Meaningful changes are documented and committed throughout development.
- [ ] The final implementation is committed and pushed, and its SHA is recorded above.
- [ ] No credentials or private data are included in the repository or demo instructions.
- [ ] The organizers' announced submission method and timing have been followed.

Event reference: [DevDay Exchange Community: Kochi on Luma](https://luma.com/z10nz8gp). The event wraps up by **10:00 AM IST on 11 October 2026**.
