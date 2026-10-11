"""Remove DWARF-only custom sections without changing executable Wasm sections."""
import argparse
import hashlib
import json
from pathlib import Path


def leb(stream):
    value = 0
    raw = bytearray()
    for shift in range(0, 35, 7):
        byte = stream.read(1)
        if not byte:
            raise ValueError('Truncated Wasm section length')
        raw += byte
        value |= (byte[0] & 127) << shift
        if not byte[0] & 128:
            return value, bytes(raw)
    raise ValueError('Invalid Wasm section length')


def sections(path):
    with path.open('rb') as stream:
        if stream.read(8) != b'\0asm\x01\0\0\0':
            raise ValueError('Expected a version 1 WebAssembly module')
        end = path.stat().st_size
        while stream.tell() < end:
            start = stream.tell()
            section_id = stream.read(1)[0]
            size, _ = leb(stream)
            payload = stream.tell()
            if payload + size > end:
                raise ValueError('Wasm section extends beyond the file')
            name = ''
            if section_id == 0:
                name_size, _ = leb(stream)
                if stream.tell() + name_size > payload + size:
                    raise ValueError('Invalid custom section name')
                name = stream.read(name_size).decode('utf-8', errors='strict')
            yield start, payload + size - start, section_id, name
            stream.seek(payload + size)


def digest_sections(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for start, size, _, name in sections(path):
            if name.startswith('.debug_'):
                continue
            stream.seek(start)
            while size:
                block = stream.read(min(size, 1024 * 1024))
                if not block:
                    raise ValueError('Truncated module')
                digest.update(block)
                size -= len(block)
    return digest.hexdigest()


def compact(source, destination):
    if source.resolve() == destination.resolve():
        raise ValueError('Preserve the upstream debugging artifact; use a different output')
    temporary = destination.with_suffix('.wasm.tmp')
    removed = []
    with source.open('rb') as src, temporary.open('wb') as dst:
        dst.write(src.read(8))
        for start, size, section_id, name in sections(source):
            if section_id == 0 and name.startswith('.debug_'):
                removed.append(dict(name=name, bytes=size))
                continue
            src.seek(start)
            while size:
                block = src.read(min(size, 1024 * 1024))
                if not block:
                    raise ValueError('Truncated module')
                dst.write(block)
                size -= len(block)
    before = digest_sections(source)
    after = digest_sections(temporary)
    if before != after:
        raise ValueError('Executable/custom-section preservation check failed')
    temporary.replace(destination)
    return dict(source_bytes=source.stat().st_size, output_bytes=destination.stat().st_size,
                removed=removed, preserved_sections_sha256=after, verified=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    print(json.dumps(compact(args.source, args.destination), indent=2))
