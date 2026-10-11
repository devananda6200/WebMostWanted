"""Read-only, loopback-only browser-port development server.

No game binary is executed. Assets are streamed in bounded chunks; large assets
require bounded byte-range requests so accidental full-installation fetches fail.
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
from pathlib import Path
import re
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

try:
    from .game_config import load_game_root
except ImportError:
    from game_config import load_game_root

CHUNK_BYTES = 64 * 1024
MAX_ASSET_REQUEST = 8 * 1024 * 1024
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
MIME_TYPES = {".wasm": "application/wasm", ".js": "text/javascript; charset=utf-8",
              ".mjs": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8"}


class RequestFailure(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & REPARSE)


def opened_path(descriptor: int) -> Path | None:
    """Resolve the opened handle to defeat Windows parent-junction replacement."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_name = kernel.GetFinalPathNameByHandleW
        get_name.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        get_name.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_name(msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise PermissionError("Cannot verify the opened resource path")
        name = buffer.value
        if name.startswith("\\\\?\\UNC\\"):
            name = "\\\\" + name[8:]
        elif name.startswith("\\\\?\\"):
            name = name[4:]
        return Path(name)
    proc_path = Path(f"/proc/self/fd/{descriptor}")
    if proc_path.exists():
        return proc_path.resolve(strict=True)
    return None


def path_parts(value: str) -> tuple[str, ...]:
    """Accept only unambiguous Windows relative resource paths."""
    if "\\" in value or ":" in value or "\x00" in value or value.startswith("/"):
        raise RequestFailure(400, "Invalid resource path")
    parts = tuple(value.split("/"))
    for part in parts:
        if not part or part in (".", "..") or part.endswith((".", " ")) or any(ord(c) < 32 for c in part):
            raise RequestFailure(400, "Invalid resource path component")
        if re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part):
            raise RequestFailure(400, "Reserved resource path component")
    return parts


class SafeMount:
    """A fixed case-insensitive file index; directories/reparse points are excluded."""
    def __init__(self, root: Path, *, optional: bool = False):
        self.root = root.absolute()
        self.files: dict[str, tuple[str, ...]] = {}
        self.total_bytes = 0
        self.skipped_links = 0
        if optional and not self.root.exists():
            return
        if not self.root.is_dir() or is_link(self.root):
            raise ValueError(f"Resource root must be a regular directory: {self.root}")
        self.canonical_root = self.root.resolve(strict=True)
        self._scan(self.root, ())

    def _scan(self, directory: Path, prefix: tuple[str, ...]) -> None:
        with os.scandir(directory) as entries:
            for entry in entries:
                entry_path = Path(entry.path)
                if is_link(entry_path):
                    self.skipped_links += 1
                    continue
                parts = prefix + (entry.name,)
                if entry.is_dir(follow_symlinks=False):
                    self._scan(entry_path, parts)
                elif entry.is_file(follow_symlinks=False):
                    # Files with names the browser cannot address safely stay private.
                    try:
                        path_parts("/".join(parts))
                    except RequestFailure:
                        continue
                    key = "/".join(parts).casefold()
                    if key in self.files:
                        raise ValueError(f"Ambiguous case-insensitive resource name: {key}")
                    self.files[key] = parts
                    self.total_bytes += entry.stat(follow_symlinks=False).st_size

    def open(self, name: str):
        requested = path_parts(name)
        parts = self.files.get("/".join(requested).casefold())
        if parts is None:
            raise RequestFailure(404, "Resource not found in startup index; restart server after adding files")
        path = self.root
        # Recheck every component in case a file was replaced since indexing.
        for part in (None, *parts):
            if part is not None:
                path = path / part
            if is_link(path):
                raise RequestFailure(403, "Linked/reparse resources are forbidden")
        try:
            path.resolve(strict=True).relative_to(self.canonical_root)
        except ValueError as error:
            raise RequestFailure(403, "Resource escaped its configured root") from error
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        stream = os.fdopen(descriptor, "rb")
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & REPARSE):
            stream.close()
            raise RequestFailure(403, "Only regular files may be read")
        try:
            actual = opened_path(stream.fileno())
            if actual is not None:
                actual.relative_to(self.canonical_root)
        except (ValueError, OSError) as error:
            stream.close()
            raise RequestFailure(403, "Opened resource escaped its configured root") from error
        return stream, info.st_size, path.suffix.lower()


def byte_range(value: str | None, size: int) -> tuple[int, int, bool]:
    if value is None:
        return 0, size, False
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
    if not match or not any(match.groups()) or size == 0:
        raise RequestFailure(416, "Only one satisfiable bytes range is supported")
    first, last = match.groups()
    if first:
        start, end = int(first), min(int(last) + 1, size) if last else size
    else:
        length = int(last)
        start, end = max(0, size - length), size
    if start >= size or end <= start:
        raise RequestFailure(416, "Unsatisfiable bytes range")
    return start, end, True


class PortServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, project_root: Path, game_root: Path, port: int = 8000):
        self.mounts = {
            "assets": SafeMount(game_root),
            "browser": SafeMount(project_root / "browser"),
            "renderer": SafeMount(project_root / "renderer", optional=True),
            "build": SafeMount(project_root / "build", optional=True),
        }
        super().__init__(("127.0.0.1", port), PortHandler)


class PortHandler(BaseHTTPRequestHandler):
    server: PortServer
    server_version = "BrowserPortReadOnly/1"
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        super().end_headers()

    def do_HEAD(self):
        self._get(head=True)

    def do_GET(self):
        self._get(head=False)

    def _read_only(self):
        self.close_connection = True
        self._json(405, {"error": "This server only supports GET and HEAD"}, head=False,
                   extra={"Allow": "GET, HEAD", "Connection": "close"})

    do_POST = _read_only
    do_PUT = _read_only
    do_PATCH = _read_only
    do_DELETE = _read_only
    do_OPTIONS = _read_only

    def _error(self, status: int, message: str, *, head: bool, size: int | None = None):
        self._json(status, {"error": message}, head=head,
                   extra={"Content-Range": f"bytes */{size}"} if status == 416 and size is not None else {})

    def _json(self, status: int, value: dict, *, head: bool, extra: dict | None = None):
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, content in (extra or {}).items():
            self.send_header(name, content)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _get(self, *, head: bool):
        size = None
        try:
            # BaseHTTPRequestHandler normalizes a leading // before do_GET;
            # reject the original ambiguous target rather than accepting it.
            original_target = self.requestline.split()[1]
            if original_target.startswith("//"):
                raise RequestFailure(400, "Ambiguous request path")
            port = self.server.server_port
            allowed_hosts = {f"localhost:{port}", f"127.0.0.1:{port}"}
            if self.headers.get("Host", "").lower() not in allowed_hosts:
                raise RequestFailure(403, "Host must be this loopback development server")
            origin = self.headers.get("Origin")
            if origin and origin not in {f"http://{host}" for host in allowed_hosts}:
                raise RequestFailure(403, "Cross-origin asset requests are forbidden")
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                raise RequestFailure(403, "Cross-site asset requests are forbidden")
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or re.search(r"%(?![0-9a-fA-F]{2})", parsed.path):
                raise RequestFailure(400, "Malformed request path")
            path = unquote(parsed.path, encoding="utf-8", errors="strict")
            if path == "/api/status":
                assets = self.server.mounts["assets"]
                self._json(200, {"schema": 1, "read_only": True, "native_game_process_started": False,
                                "asset_files": len(assets.files), "asset_bytes": assets.total_bytes,
                                "skipped_links": assets.skipped_links, "asset_request_limit": MAX_ASSET_REQUEST,
                                "build_files": sorted(self.server.mounts["build"].files),
                                "gameplay_status": "Not demonstrated"}, head=head)
                return
            if path == "/":
                path = "/browser/index.html"
            parts = path_parts(path.removeprefix("/"))
            if len(parts) < 2 or parts[0] not in self.server.mounts:
                raise RequestFailure(404, "Unknown resource mount")
            mount = self.server.mounts[parts[0]]
            with_stream, size, suffix = mount.open("/".join(parts[1:]))
            with with_stream as stream:
                start, end, partial = byte_range(self.headers.get("Range"), size)
                if parts[0] == "assets" and end - start > MAX_ASSET_REQUEST and not head:
                    raise RequestFailure(413, f"Asset request exceeds {MAX_ASSET_REQUEST} bytes; use smaller Range requests")
                self.send_response(206 if partial else 200)
                self.send_header("Content-Type", MIME_TYPES.get(suffix, mimetypes.types_map.get(suffix, "application/octet-stream")))
                self.send_header("Content-Length", str(end - start))
                self.send_header("Accept-Ranges", "bytes")
                if partial:
                    self.send_header("Content-Range", f"bytes {start}-{end - 1}/{size}")
                self.end_headers()
                if not head:
                    stream.seek(start)
                    remaining = end - start
                    while remaining:
                        block = stream.read(min(CHUNK_BYTES, remaining))
                        if not block:
                            self.close_connection = True
                            break
                        self.wfile.write(block)
                        remaining -= len(block)
        except RequestFailure as error:
            self._error(error.status, str(error), head=head, size=size)
        except (FileNotFoundError, NotADirectoryError):
            self._error(404, "Resource no longer exists", head=head)
        except (UnicodeError, ValueError):
            self._error(400, "Malformed resource path", head=head)
        except PermissionError:
            self._error(403, "Resource access denied", head=head)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except OSError:
            self._error(403, "Resource could not be read safely", head=head)

    def log_message(self, format, *args):
        # Do not print original filesystem paths or query strings.
        message = (format % args).split("?", 1)[0]
        print(f"[{self.log_date_time_string()}] {message.encode('unicode_escape').decode('ascii')}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        server = PortServer(project_root, load_game_root(project_root), args.port)
    except (ValueError, OSError) as error:
        parser.exit(2, f"Cannot serve resources: {error}\n")
    print(f"Browser port: http://127.0.0.1:{server.server_port}/ (read-only assets, no native game)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
