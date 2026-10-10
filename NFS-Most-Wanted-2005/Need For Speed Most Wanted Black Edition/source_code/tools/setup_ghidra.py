"""Download the pinned official portable Ghidra release; verify before extracting."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import shutil
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NAME = "ghidra_12.1.4_PUBLIC_20260921.zip"
URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/" + NAME
SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
SIZE = 569649598


def download(archive):
    # Range requests permit a slow/interrupted portable-tool download to resume.
    partial = archive.with_suffix(".partial")
    prefix = partial.stat().st_size if partial.exists() else 0
    if prefix > SIZE:
        raise ValueError("Partial archive exceeds the published release size")
    request = urllib.request.Request(URL, headers={"User-Agent": "local-game-recovery", "Range": "bytes=0-0"})
    with urllib.request.urlopen(request, timeout=120) as response:
        if response.status != 206 or response.headers.get("Content-Range") != f"bytes 0-0/{SIZE}":
            raise ValueError("Release server did not honor the range request")
        direct_url = response.url
    spans = [(start, min(start + 32 * 1024 * 1024, SIZE) - 1) for start in range(prefix, SIZE, 32 * 1024 * 1024)]

    def part(span):
        start, end = span
        output = archive.parent / f"ghidra-part-{start}-{end}.bin"
        expected = end - start + 1
        if output.exists() and output.stat().st_size == expected:
            return output
        request = urllib.request.Request(direct_url, headers={"Range": f"bytes={start}-{end}"})
        with urllib.request.urlopen(request, timeout=120) as response, output.open("wb") as stream:
            if response.status != 206 or response.headers.get("Content-Range") != f"bytes {start}-{end}/{SIZE}":
                raise ValueError("Mismatched range response")
            shutil.copyfileobj(response, stream, 1024 * 1024)
        if output.stat().st_size != expected:
            raise ValueError("Incomplete range download")
        print(f"Downloaded bytes {start}-{end}", flush=True)
        return output

    with ThreadPoolExecutor(max_workers=8) as pool:
        parts = list(pool.map(part, spans))
    assembled = archive.with_suffix(".assembled")
    with assembled.open("wb") as stream:
        if prefix:
            with partial.open("rb") as source:
                shutil.copyfileobj(source, stream)
        for item in parts:
            with item.open("rb") as source:
                shutil.copyfileobj(source, stream)
    assembled.replace(archive)
    # Keep parts until the complete archive has passed the published checksum.
    return ([partial] if partial.exists() else []) + parts


def main():
    tools = ROOT / ".tools"
    tools.mkdir(exist_ok=True)
    archive = tools / NAME
    parts = []
    if not archive.exists():
        parts = download(archive)
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != SHA256:
        raise ValueError(f"Ghidra checksum mismatch: {digest}")
    for item in parts:
        item.unlink()
    destination = tools / "ghidra_12.1.4_PUBLIC"
    marker = tools / "ghidra-install.json"
    if not marker.exists():
        with zipfile.ZipFile(archive) as source:
            for entry in source.infolist():
                target = (tools / entry.filename).resolve()
                if not target.is_relative_to(tools.resolve()):
                    raise ValueError(f"Unsafe archive path: {entry.filename}")
            source.extractall(tools)
    if not (destination / "support" / "analyzeHeadless.bat").is_file():
        raise ValueError("Expected Ghidra launcher missing after extraction")
    marker.write_text(json.dumps({"url": URL, "sha256": digest, "version": "12.1.4"}, indent=2) + "\n")
    print(destination, flush=True)


if __name__ == "__main__":
    main()
