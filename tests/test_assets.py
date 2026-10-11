import hashlib
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from tools.assets import byte_range, contained_file, make_handler, safe_path


class AssetTests(unittest.TestCase):
    def test_ranges(self):
        self.assertEqual(byte_range('bytes=2-4', 10), (2, 4, True))
        self.assertEqual(byte_range('bytes=7-', 10), (7, 9, True))
        self.assertEqual(byte_range('bytes=-3', 10), (7, 9, True))
        self.assertEqual(byte_range('bytes=0-99', 10), (0, 9, True))
        for invalid in ['bytes=10-', 'bytes=8-2', 'bytes=-0', 'bytes=1-2,4-5', 'bytes=-', 'other']:
            with self.assertRaises(ValueError):
                byte_range(invalid, 10)

    def test_paths(self):
        for invalid in ['/etc/passwd', '../speed.exe', 'C:/speed.exe', 'CARS\\file', 'CARS//file', './file', 'CARS/../file']:
            with self.assertRaises(ValueError):
                safe_path(invalid)
        self.assertEqual(str(safe_path('CARS/BMWM3/GEOMETRY.BIN')), 'CARS/BMWM3/GEOMETRY.BIN')

    def test_http(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game, site = root / 'game', root / 'site'
            game.mkdir(); site.mkdir()
            (game / 'sample.bin').write_bytes(b'0123456789')
            (game / 'secret.bin').write_bytes(b'not allowed')
            (site / 'index.html').write_text('private launcher')
            (site / 'game.wasm').write_bytes(b'\0asm')
            digest = hashlib.sha256(b'0123456789').hexdigest()
            manifest = dict(version='v1', files=[dict(path='sample.bin', size=10, sha256=digest)])
            server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(game, site, manifest))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def get(path, headers=None, method='GET'):
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port)
                conn.request(method, path, headers=headers or {})
                response = conn.getresponse()
                result = response.status, dict(response.getheaders()), response.read()
                conn.close()
                return result
            try:
                status, headers, body = get('/assets/v1/sample.bin', {'Range': 'bytes=3-6'})
                self.assertEqual((status, body), (206, b'3456'))
                self.assertEqual(headers['Content-Range'], 'bytes 3-6/10')
                self.assertEqual(headers['Cross-Origin-Opener-Policy'], 'same-origin')
                self.assertEqual(headers['Cross-Origin-Embedder-Policy'], 'require-corp')
                self.assertEqual(get('/game.wasm')[1]['Content-Type'], 'application/wasm')
                self.assertEqual(get('/assets/v1/sample.bin', method='HEAD')[2], b'')
                self.assertEqual(get('/assets/v1/sample.bin', {'Range': 'bytes=99-'})[0], 416)
                self.assertEqual(get('/assets/v1/sample.bin', {'Range': 'bytes=0-1', 'If-Range': 'wrong'})[0], 200)
                for path in ['/assets/v1/secret.bin', '/assets/v1/../secret.bin', '/assets/v1/%2e%2e/secret.bin', '/assets/v0/sample.bin']:
                    self.assertEqual(get(path)[0], 404)
                self.assertEqual(get('/', {'Host': 'attacker.example'})[0], 403)
                self.assertEqual(get('/', {'Origin': 'https://attacker.example'})[0], 403)
                self.assertEqual(json.loads(get('/asset-manifest.json')[2]), manifest)
                (game / 'sample.bin').write_bytes(b'changed')
                self.assertEqual(get('/assets/v1/sample.bin')[0], 409)
            finally:
                server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
