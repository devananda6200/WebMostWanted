"""Stage an isolated private site; the upstream manual-import site remains intact."""
import json
from pathlib import Path
import shutil
import sys
from compact_wasm import compact

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / 'reference/nfsmw-recomp'


def main():
    site = ROOT / 'build/site'
    site.mkdir(parents=True, exist_ok=True)
    for path in (ROOT / 'web').iterdir():
        if path.is_file():
            shutil.copy2(path, site / path.name)
    sys.path.insert(0, str(REPO / 'kit/tools'))
    import game_config
    from web_launcher import game_entry, copy_web_build
    game = game_entry(game_config.load(REPO))
    (site / 'games.json').write_text(json.dumps([game], indent=2), encoding='utf-8')
    build = REPO / 'build/web/recomp'
    ready = all((build / f'SpeedRecomp.{suffix}').is_file() for suffix in ('js', 'wasm', 'data'))
    if ready:
        copy_web_build('nfsmw', build, site)
        compacted = compact(build / 'SpeedRecomp.wasm', site / 'nfsmw/SpeedRecomp.wasm')
        (ROOT / 'artifacts/wasm-compaction.json').write_text(json.dumps(compacted, indent=2), encoding='utf-8')
        player = site / 'nfsmw/index.html'
        html = player.read_text(encoding='utf-8')
        html = html.replace('</body>', '<script src="../runtime-diagnostics.js"></script>\n</body>')
        player.write_text(html, encoding='utf-8')
    (site / 'runtime.json').write_text(json.dumps(dict(ready=ready)), encoding='utf-8')
    print(f'Staged {site}; original-game WebAssembly build available: {ready}')


if __name__ == '__main__':
    main()
