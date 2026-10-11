# NFS Most Wanted 2005 — practical browser-port starting point

The implementation has advanced beyond this original starter. See [README.md](README.md) for the built private Chrome runtime and [verified results](docs/test-results.md) for its current limits. The original inventory instructions below remain useful.

## What this folder contains

- `inventory_game.py`: Read-only scanner for your real NFS Most Wanted 2005 directory. It generates a manifest; it does **not** extract, convert, copy, modify, or upload game files.
- `CODEX_MASTER_PROMPT.md`: Instructions for a Codex agent that can access your Windows game installation.

## Run the inventory on your Windows PC

In PowerShell (from this folder, with Python installed):

```powershell
py inventory_game.py --game-dir "C:\Users\festi\Downloads\WebMostWanted\NFS-Most-Wanted-2005\Need For Speed Most Wanted Black Edition" --out nfsmw_inventory.json
```

If `py` is not available, use `python`.

To also record SHA-256 of **every** data file (can take some time):

```powershell
py inventory_game.py --game-dir "C:\Users\festi\Downloads\WebMostWanted\NFS-Most-Wanted-2005\Need For Speed Most Wanted Black Edition" --out nfsmw_inventory.json --hash-all
```

## What happens next

Paste `CODEX_MASTER_PROMPT.md` into Codex, working in a folder that can read your installation. Give Codex access to this scanner and the generated inventory JSON.

References: https://github.com/veritr1x/nfsmw-recomp and https://github.com/veritr1x/recomp-kit.

This document describes the initial starter. The current local workspace also contains a compiled original-game browser runtime; complete race acceptance is tracked separately. Public delivery of copyrighted data requires appropriate distribution rights.
