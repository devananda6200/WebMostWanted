# DevDay Exchange Community Hackathon: Kochi

A repository template for participants at the 10–11 October 2026 hackathon. It contains event rules and documentation scaffolding; build your project from scratch at the event.

**[Event and registration on Luma](https://luma.com/z10nz8gp)** · **[Event rules](RULES.md)** · **[Agent instructions](AGENTS.md)**

## Event details

| Detail | Information |
| --- | --- |
| Venue | JAIN University, Kochi |
| Location | [Open the venue map](https://maps.app.goo.gl/Eme7gR7NDXSNRANu5) |
| Rooms | 2008 and 2009 |
| Check-in | 10 October 2026, 6:00 PM IST |
| Kick-off | 10 October 2026, 6:30 PM IST |
| Wrap-up | 11 October 2026, by 10:00 AM IST |
| Participation | Solo or a team of up to 4 participants |
| Theme | Open — build anything you like |

Keep your approved Luma QR code ready for entry, and bring your laptop and charger. Eligible checked-in participants will receive Codex credits and OpenAI API credits.

## Use this template

1. Select **Use this template → Create a new repository** on GitHub. Create your own project repository and clone it.
2. Read [RULES.md](RULES.md) and [AGENTS.md](AGENTS.md) before building. Begin project implementation at the event.
3. Fill in the project overview below as you build. Use any suitable language or framework, keeping the implementation simple.
4. Record meaningful changes in [CHANGELOG.md](CHANGELOG.md) and your Codex usage in [AI_USAGE.md](AI_USAGE.md). Commit after completed milestones; aim for a meaningful checkpoint about every 30 minutes.
5. Complete [SUBMISSION.md](SUBMISSION.md) with your code repository, short project description, and working demo. Follow submission instructions announced by the organizers.

The initial template supplied documentation scaffolding only. The project implementation is described below. The documentation and commit cadence are repository workflow guidance; the event participation rules are in [RULES.md](RULES.md).

## Project: WebMostWanted

Implementation is in [browser-port](browser-port/README.md). This is a local
binary-translation research port of the supplied Most Wanted executable, with
an installation audit, x86-to-C++/Wasm tests, and browser host. **A playable race
has not been demonstrated.** Participant names have not been supplied.

From `browser-port`, run `scripts/setup.ps1`, configure the ignored local game
path, then run `scripts/build.ps1`, `scripts/test.ps1`, and `scripts/serve.ps1`.
The [project README](browser-port/README.md) gives complete setup/demo commands;
[verified status](browser-port/docs/VERIFIED_STATUS.md) distinguishes tested
translation from incomplete game initialization and rendering.

Stack: Python, pefile, Capstone, Unicorn reference execution, generated C++,
Emscripten 4.0.23, WebAssembly, browser workers, WebGPU/Emdawnwebgpu. Dependency
sources and licenses are recorded in [DEPENDENCIES.md](browser-port/docs/DEPENDENCIES.md).
Original assets and all game-derived outputs stay local and ignored by Git.

See [AI_USAGE.md](AI_USAGE.md) for AI assistance and [CHANGELOG.md](CHANGELOG.md) for the development record.
