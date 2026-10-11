"""Manifest and loopback-only HTTP delivery for the user's private installation."""
import argparse
import hashlib
import json
import mimetypes
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

PINNED_SHA256 = '80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c'
GAME_DIRS = frozenset('CARS CREDITS FRONTEND GLOBAL LANGUAGES MEMCARD MOVIES NIS SOUND SUBTITLES TRACKS'.split())
GAME_FILES = frozenset(('speed.exe', '00000000.256'))
CHUNK_BYTES = 4 * 1024 * 1024


def safe_path(relative):
    if not isinstance(relative, str) or not relative or '\\' in relative or ':' in relative or '\x00' in relative:
        raise ValueError('Invalid relative path')
    path = PurePosixPath(relative)
    if path.is_absolute() or any(p in ('', '.', '..') for p in relative.split('/')):
        raise ValueError('Unsafe relative path')
    return path


def contained_file(root, relative):
    path = root.joinpath(*safe_path(relative).parts)
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError('File is outside the permitted root or missing')
    return path


def make_manifest(game):
    """Hash only runtime candidates, never source_code, installers, DLLs or saves."""
    game = game.resolve()
    files, folded = [], set()
    for base, dirs, names in os.walk(game, followlinks=False):
        parent = Path(base)
        dirs[:] = sorted(d for d in dirs if not (parent / d).is_symlink()
                         and (parent != game or d.upper() in GAME_DIRS))
        for name in sorted(names):
            path = parent / name
            if path.is_symlink() or (parent == game and name not in GAME_FILES):
                continue
            relative = path.relative_to(game).as_posix()
            contained_file(game, relative)
            if relative.casefold() in folded:
                raise ValueError(f'Case-insensitive collision: {relative}')
            folded.add(relative.casefold())
            before = path.stat()
            digest, chunks = hashlib.sha256(), []
            with path.open('rb') as stream:
                while data := stream.read(CHUNK_BYTES):
                    digest.update(data)
                    chunks.append(hashlib.sha256(data).hexdigest())
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError(f'Input changed while hashing: {relative}')
            files.append(dict(path=relative, size=before.st_size, sha256=digest.hexdigest(), chunks=chunks))
    files.sort(key=lambda f: f['path'])
    exe = next((f for f in files if f['path'] == 'speed.exe'), None)
    if not exe or exe['sha256'] != PINNED_SHA256:
        raise ValueError('speed.exe does not match the supported executable')
    if not GAME_DIRS.intersection(f['path'].split('/')[0] for f in files) >= {'CARS','FRONTEND','GLOBAL','SOUND','TRACKS'}:
        raise ValueError('Missing required game directory')
    payload = dict(schema=1, chunk_bytes=CHUNK_BYTES, executable_sha256=PINNED_SHA256,
                   total_bytes=sum(f['size'] for f in files), files=files)
    payload['version'] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return payload


def byte_range(value, size):
    if not value:
        return 0, size - 1, False
    match = re.fullmatch(r'bytes=(\d*)-(\d*)', value)
    if not match or not size or not any(match.groups()):
        raise ValueError('Unsatisfiable range')
    first, last = match.groups()
    if not first:
        suffix = int(last)
        if suffix <= 0:
            raise ValueError('Unsatisfiable suffix')
        start, end = max(0, size - suffix), size - 1
    else:
        start, end = int(first), min(int(last), size - 1) if last else size - 1
    if start >= size or end < start:
        raise ValueError('Unsatisfiable range')
    return start, end, True


def make_handler(game, site, manifest):
    files = {f['path']: f for f in manifest['files']}
    manifest_data = json.dumps(manifest, separators=(',', ':')).encode()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def end_headers(self):
            self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
            self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
            self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
            self.send_header('X-Content-Type-Options', 'nosniff')
            super().end_headers()

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            # Prevent DNS rebinding from exposing private game files.
            if self.headers.get('Host') not in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'):
                self.send_error(403)
                return
            origin = self.headers.get('Origin')
            if origin and origin != 'http://' + self.headers['Host']:
                self.send_error(403)
                return
            route = unquote(urlsplit(self.path).path)
            if route == '/asset-manifest.json':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(manifest_data)))
                self.end_headers()
                if self.command != 'HEAD':
                    self.wfile.write(manifest_data)
                return
            record = None
            prefix = '/assets/' + manifest['version'] + '/'
            try:
                if route.startswith(prefix):
                    relative = route[len(prefix):]
                    record = files.get(relative)
                    if not record:
                        raise ValueError('Not in manifest')
                    path = contained_file(game, relative)
                elif route.startswith('/assets/'):
                    raise ValueError('Unknown manifest version')
                else:
                    relative = route.lstrip('/') or 'index.html'
                    if any(p.startswith('.') for p in safe_path(relative).parts):
                        raise ValueError('Hidden file')
                    path = contained_file(site, relative)
                size = path.stat().st_size
                if record and size != record['size']:
                    self.send_error(409, 'Asset changed; regenerate manifest')
                    return
            except (ValueError, OSError):
                self.send_error(404)
                return
            etag = '"' + record['sha256'] + '"' if record else None
            range_header = self.headers.get('Range')
            if self.headers.get('If-Range') and self.headers['If-Range'] != etag:
                range_header = None
            try:
                start, end, partial = byte_range(range_header, size)
            except ValueError:
                self.send_response(416)
                self.send_header('Content-Range', f'bytes */{size}')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            self.send_response(206 if partial else 200)
            self.send_header('Content-Type', 'application/wasm' if path.suffix == '.wasm' else
                             mimetypes.guess_type(path.name)[0] or 'application/octet-stream')
            self.send_header('Content-Length', str(max(0, end - start + 1)))
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Cache-Control', 'no-store')
            if etag:
                self.send_header('ETag', etag)
            if partial:
                self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
            self.end_headers()
            if self.command == 'HEAD':
                return
            try:
                with path.open('rb') as stream:
                    stream.seek(start)
                    remaining = end - start + 1
                    while remaining > 0:
                        data = stream.read(min(256 * 1024, remaining))
                        if not data:
                            break
                        self.wfile.write(data)
                        remaining -= len(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('manifest', 'serve'))
    parser.add_argument('--game-dir', required=True, type=Path)
    parser.add_argument('--manifest', default='artifacts/asset-manifest.json', type=Path)
    parser.add_argument('--site', default='build/site', type=Path)
    parser.add_argument('--port', default=8080, type=int)
    args = parser.parse_args()
    if args.command == 'manifest':
        manifest = make_manifest(args.game_dir)
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        print(f"{len(manifest['files'])} files, {manifest['total_bytes']} bytes, version {manifest['version']}")
    else:
        manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
        server = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(args.game_dir, args.site, manifest))
        print(f'Private runtime: http://127.0.0.1:{server.server_port}/', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == '__main__':
    main()
