"""Windows entry point for the upstream build; no generated game code is edited."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emsdk', required=True, type=Path)
    parser.add_argument('--regenerate', action='store_true')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    sdk = args.emsdk.resolve()
    node = next(sdk.glob('node/*/bin/node.exe'))
    config = ROOT / '.tools/emscripten.py'
    config.parent.mkdir(parents=True, exist_ok=True)
    values = dict(LLVM_ROOT=str(sdk / 'upstream/bin'), BINARYEN_ROOT=str(sdk / 'upstream'),
                  NODE_JS=str(node))
    config.write_text('\n'.join(f'{key} = {value!r}' for key, value in values.items()) + '\n', encoding='utf-8')
    env = dict(os.environ, EMSDK=str(sdk), EM_CONFIG=str(config),
               EM_CACHE=str(ROOT / '.tools/emscripten-cache'),
               EM_PORTS=str(ROOT / '.tools/emscripten-ports'),
               PYTHONUTF8='1', PYTHONUNBUFFERED='1')
    env['PATH'] = os.pathsep.join([str(Path(sys.executable).parent), str(sdk / 'upstream/emscripten'),
                                 str(node.parent), env.get('PATH', '')])
    repo = ROOT / 'reference/nfsmw-recomp'
    command = [sys.executable, '-u', 'tools/build.py', '--target', 'web', '--jobs', str(args.jobs)]
    if args.regenerate:
        command += ['--regenerate', '--allow-table-gaps', 'MSVC 7.1 switch shapes; upstream docs/analysis.md']
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    log = ROOT / f'artifacts/build-{stamp}.log'
    log.parent.mkdir(parents=True, exist_ok=True)
    record = dict(started_utc=stamp, command=command, cwd=str(repo), environment={k: env[k] for k in
                  ('EMSDK', 'EM_CONFIG', 'EM_CACHE', 'EM_PORTS', 'PYTHONUTF8')}, log=str(log))
    print(f'Build log: {log}', flush=True)
    with log.open('w', encoding='utf-8') as output:
        output.write(json.dumps(record) + '\n'); output.flush()
        process = subprocess.Popen(command, cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding='utf-8', errors='replace')
        for line in process.stdout:
            output.write(line); output.flush()
            print(line, end='', flush=True)
        record['exit_code'] = process.wait()
    record['finished_utc'] = datetime.now(timezone.utc).isoformat()
    (ROOT / 'artifacts/build-latest.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
    return record['exit_code']


if __name__ == '__main__':
    sys.exit(main())
