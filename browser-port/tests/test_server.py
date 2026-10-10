"""Resource-serving security and bounded-I/O regressions. Uses temporary data."""
from __future__ import annotations

from http.client import HTTPConnection
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools.serve import MAX_ASSET_REQUEST, PortServer, RequestFailure, SafeMount, byte_range, path_parts


class RangeTests(unittest.TestCase):
    def test_byte_ranges(self):
        self.assertEqual(byte_range(None, 10), (0, 10, False))
        self.assertEqual(byte_range("bytes=2-4", 10), (2, 5, True))
        self.assertEqual(byte_range("bytes=2-100", 10), (2, 10, True))
        self.assertEqual(byte_range("bytes=8-", 10), (8, 10, True))
        self.assertEqual(byte_range("bytes=-3", 10), (7, 10, True))
        self.assertEqual(byte_range("bytes=-100", 10), (0, 10, True))

    def test_unsatisfiable_and_multirange(self):
        for value in ("bytes=10-", "bytes=-0", "bytes=3-2", "bytes=0-1,4-5", "bytes=-", "items=0-2"):
            with self.subTest(value=value), self.assertRaises(RequestFailure) as error:
                byte_range(value, 10)
            self.assertEqual(error.exception.status, 416)
        with self.assertRaises(RequestFailure):
            byte_range("bytes=0-", 0)

    def test_windows_path_ambiguities_rejected(self):
        for value in ("../secret", "a/../secret", "a/./b", "a//b", "a\\b", "/secret", "file:stream", "NUL", "CON.txt", "x. ", "x.", "x\x00y"):
            with self.subTest(value=value), self.assertRaises(RequestFailure):
                path_parts(value)


class PresentationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node is needed for presentation regression")
    def test_large_test_evidence_has_a_compact_view_without_losing_raw_data(self):
        module_url = (Path(__file__).resolve().parents[1] / "browser" / "diagnostic-view.js").as_uri()
        script = """
import { compactSummary, visibleEvents } from MODULE_URL;
import assert from 'node:assert/strict';
const raw = 'RAW_CPU_DATA'.repeat(10000);
const results = Array.from({length: 674}, (_, i) => ({id: `case-${i}`, suite: 'fixture', passed: true, cpu: raw, mismatches: []}));
const tests = {state: 'tested', total: 674, passed: 674, elapsedMs: 1234, results, manifest: {toolchain: '4.0.23', artifact_sha256: {'fixture.wasm': 'a'.repeat(64)}}};
const diagnostics = {environment: {}, server: null, tests, startup: null, events: results.map(result => ({time: '2026-10-11', type: 'test-case', ...result}))};
diagnostics.events.push({time: '2026-10-11', type: 'test-complete', result: tests});
const summary = JSON.stringify(compactSummary(diagnostics));
const visible = visibleEvents(diagnostics.events);
assert.equal(visible.split('\\n').length, 15);
assert(!visible.includes('RAW_CPU_DATA'));
assert(!summary.includes('RAW_CPU_DATA'));
assert(summary.length < 4000);
assert(visible.length < 5000);
assert.equal(diagnostics.events.length, 675);
assert.equal(diagnostics.tests.results.length, 674);
assert.equal(diagnostics.events[0].cpu, raw);
console.log(JSON.stringify({summaryBytes: summary.length, visibleBytes: visible.length, retainedEvents: diagnostics.events.length}));
""".replace("MODULE_URL", json.dumps(module_url))
        result = subprocess.run([shutil.which("node"), "--input-type=module", "-e", script], text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.game = self.root / "game"
        for path in (self.project / "browser", self.project / "build", self.project / "renderer", self.game / "Tracks"):
            path.mkdir(parents=True)
        (self.project / "browser" / "index.html").write_text("<h1>Host</h1>", encoding="utf-8")
        (self.project / "browser" / "main.js").write_text("export const check = 1;", encoding="utf-8")
        (self.project / "build" / "translated.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
        (self.project / "config.local.json").write_text("PRIVATE-CONFIG", encoding="utf-8")
        (self.game / "Tracks" / "Race.BIN").write_bytes(b"0123456789")
        (self.game / "empty.bin").write_bytes(b"")
        with (self.game / "large.bin").open("wb") as stream:
            stream.truncate(MAX_ASSET_REQUEST + 1)
        self.server = PortServer(self.project, self.game, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, path="/", method="GET", headers=None):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_index_headers_and_wasm_mime(self):
        status, headers, body = self.request()
        self.assertEqual(status, 200)
        self.assertIn(b"Host", body)
        self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertEqual(headers["Cross-Origin-Embedder-Policy"], "require-corp")
        self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        status, headers, body = self.request("/build/translated.wasm")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/wasm")
        self.assertEqual(body, b"\x00asm\x01\x00\x00\x00")

    def test_case_insensitive_range_and_head(self):
        status, headers, body = self.request("/assets/TRACKS/race.bin", headers={"Range": "bytes=2-5"})
        self.assertEqual((status, body), (206, b"2345"))
        self.assertEqual(headers["Content-Range"], "bytes 2-5/10")
        status, headers, body = self.request("/assets/tracks/RACE.BIN", method="HEAD")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(headers["Content-Length"], "10")

    def test_ranges_invalid_and_empty(self):
        status, headers, _ = self.request("/assets/Tracks/Race.BIN", headers={"Range": "bytes=99-"})
        self.assertEqual(status, 416)
        self.assertEqual(headers["Content-Range"], "bytes */10")
        self.assertEqual(self.request("/assets/empty.bin")[:1], (200,))
        self.assertEqual(self.request("/assets/empty.bin", headers={"Range": "bytes=0-"})[0], 416)

    def test_large_assets_require_bounded_ranges(self):
        self.assertEqual(self.request("/assets/large.bin")[0], 413)
        self.assertEqual(self.request("/assets/large.bin", headers={"Range": "bytes=0-"})[0], 413)
        status, _, body = self.request("/assets/large.bin", headers={"Range": "bytes=0-3"})
        self.assertEqual((status, body), (206, b"\0\0\0\0"))
        status, headers, body = self.request("/assets/large.bin", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Length"], str(MAX_ASSET_REQUEST + 1))
        self.assertEqual(body, b"")

    def test_traversal_and_private_files(self):
        for path in ("/assets/../config.local.json", "/assets/%2e%2e/config.local.json", "/assets/Tracks%5c..%5csecret", "/assets/Tracks/Race.BIN:secret", "/assets/%00", "/assets/%ZZ", "/assets/%ff", "//assets/Tracks/Race.BIN"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 400)
        for path in ("/config.local.json", "/tools/serve.py", "/assets", "/assets/Tracks", "/assets/not-found"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)

    def test_host_origin_and_fetch_site_restricted(self):
        for headers in ({"Host": "external.example"}, {"Origin": "https://external.example"}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("/api/status", headers=headers)[0], 403)

    def test_no_writes_and_no_directory_listings(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                self.assertEqual(self.request("/assets/Tracks/Race.BIN", method=method)[0], 405)
        self.assertEqual((self.game / "Tracks" / "Race.BIN").read_bytes(), b"0123456789")
        self.assertNotEqual(self.request("/assets/")[0], 200)

    def test_status_hides_local_paths(self):
        status, _, body = self.request("/api/status")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["read_only"])
        self.assertFalse(data["native_game_process_started"])
        self.assertEqual(data["asset_files"], 3)
        self.assertNotIn(str(self.root).encode(), body)

    def test_reparse_rechecked_after_indexing(self):
        from tools import serve
        original = serve.is_link
        with patch.object(serve, "is_link", side_effect=lambda path: path.name == "Tracks" or original(path)):
            self.assertEqual(self.request("/assets/Tracks/Race.BIN")[0], 403)

    def test_opened_handle_containment_rechecked(self):
        with patch("tools.serve.opened_path", return_value=self.project / "config.local.json"):
            self.assertEqual(self.request("/assets/Tracks/Race.BIN")[0], 403)

    def test_actual_symlinks_never_indexed(self):
        link = self.game / "external"
        try:
            os.symlink(self.project, link, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"Platform cannot create unprivileged test symlink: {error}")
        mount = SafeMount(self.game)
        self.assertEqual(mount.skipped_links, 1)
        self.assertNotIn("external/config.local.json", mount.files)

    @unittest.skipUnless(shutil.which("node"), "Node is needed for real async asset-client integration")
    def test_async_asset_client_reads_seeks_caches_and_reports_errors(self):
        module_url = (Path(__file__).resolve().parents[1] / "browser" / "asset-client.js").as_uri()
        script = """
import { ReadOnlyAssets, normalizeAssetPath } from MODULE_URL;
import assert from 'node:assert/strict';
const assets = new ReadOnlyAssets(BASE_URL, {blockBytes: 4, cacheBytes: 8});
assert.equal(normalizeAssetPath('.\\\\TRACKS\\\\sub\\\\..\\\\Race.BIN'), 'tracks/race.bin');
for (const bad of ['../private', 'C:\\\\private', '//server/file', 'nul:stream']) assert.throws(() => normalizeAssetPath(bad));
const {handle, size} = await assets.open('TRACKS\\\\Race.BIN');
assert.equal(size, 10);
assert.equal(new TextDecoder().decode(await assets.read(handle, 6)), '012345');
assets.seek(handle, -3, 1);
assert.equal(new TextDecoder().decode(await assets.read(handle, 4)), '3456');
assert.equal(assets.measurements().bytesFetched, 8);
assets.seek(handle, -2, 2);
assert.equal(new TextDecoder().decode(await assets.read(handle, 8)), '89');
assert.equal((await assets.read(handle, 1)).length, 0);
assets.seek(handle, 100, 0);
assert.equal((await assets.read(handle, 1)).length, 0);
assert(assets.measurements().peakCachedBytes <= 8);
assets.seek(handle, 0);
const pending = assets.read(handle, 4);
assert.throws(() => assets.seek(handle, 0), /pending read/);
await assert.rejects(() => assets.read(handle, 1), /pending read/);
await pending;
assets.close(handle);
await assert.rejects(() => assets.read(handle, 1), /Invalid asset handle/);
await assert.rejects(() => assets.open('missing.bin'), /HTTP 404/);
console.log(JSON.stringify(assets.measurements()));
""".replace("MODULE_URL", json.dumps(module_url)).replace("BASE_URL", json.dumps(f"http://127.0.0.1:{self.server.server_port}/assets/"))
        result = subprocess.run([shutil.which("node"), "--input-type=module", "-e", script], text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertLessEqual(json.loads(result.stdout)["peakCachedBytes"], 8)


if __name__ == "__main__":
    unittest.main()
