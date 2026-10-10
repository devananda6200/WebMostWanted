"""Pinned, workspace-local compiler tools. Never alter machine configuration."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SDK_VERSION = "4.0.23"
SDK_COMMIT = "c0bb220cb6e6f4e0fabb6f6db9efd53390ef5e56"
SDK_RELEASE = "aaa43392544d695232b70eda706d751f18980c2a"
SDK = ROOT / ".tools" / f"emsdk-{SDK_VERSION}"


def require_file(path: Path) -> Path:
    if not path.is_file():
        raise FileNotFoundError(f"Missing tool: {path}. Run scripts/setup.ps1 first.")
    return path


def clang_path() -> Path:
    return require_file(SDK / "upstream/bin/clang.exe")


def linker_path() -> Path:
    return require_file(SDK / "upstream/bin/lld.exe")


def linker_command() -> list[str]:
    """Select LLD's COFF driver explicitly; the executable is not lld-link.exe."""
    return [str(linker_path()), "-flavor", "link"]


def node_path() -> Path:
    return require_file(SDK / "node/22.16.0_64bit/bin/node.exe")


def emcc_command(cxx: bool = False) -> list[str]:
    script = SDK / "upstream/emscripten" / ("em++.py" if cxx else "emcc.py")
    return [sys.executable, str(require_file(script))]


def toolchain_env() -> dict[str, str]:
    env = os.environ.copy()
    env["EM_CONFIG"] = str(require_file(SDK / ".emscripten"))
    env["EMSDK"] = str(SDK)
    env["EMSDK_NODE"] = str(node_path())
    # All compiler caches and downloaded ports stay in ignored project storage.
    env["EM_CACHE"] = str(ROOT / ".tools" / f"emscripten-cache-{SDK_VERSION}")
    env["EM_PORTS"] = str(ROOT / ".tools" / f"emscripten-ports-{SDK_VERSION}")
    return env


def compile_wasm(
    sources: str | Path | list[str | Path],
    output: str | Path,
    extra_args: list[str] | None = None,
    *,
    cxx: bool | None = None,
) -> subprocess.CompletedProcess:
    """Compile generated code; caller supplies exports, runtime and ABI flags."""
    if isinstance(sources, (str, Path)):
        sources = [sources]
    paths = [Path(item) for item in sources]
    if cxx is None:
        cxx = any(path.suffix.lower() in {".cc", ".cpp", ".cxx"} for path in paths)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [*emcc_command(cxx), *(str(path) for path in paths),
               *(extra_args or []), "-o", str(output)]
    return subprocess.run(command, cwd=ROOT, env=toolchain_env(), check=True)


def setup() -> None:
    """Download only the pinned official portable SDK, activated locally."""
    if sys.platform != "win32":
        raise RuntimeError("This entry point is pinned to Windows x64. WSL is not used.")
    SDK.parent.mkdir(parents=True, exist_ok=True)
    if not SDK.exists():
        subprocess.run(["git", "clone", "--depth", "1", "--branch", SDK_VERSION,
                        "https://github.com/emscripten-core/emsdk.git", str(SDK)],
                       check=True)
    actual = subprocess.check_output(["git", "-C", str(SDK), "rev-parse", "HEAD"],
                                     text=True).strip()
    if actual != SDK_COMMIT:
        raise RuntimeError(f"Refusing unexpected SDK manager commit: {actual}")
    status = subprocess.check_output(["git", "-C", str(SDK), "status", "--porcelain",
                                      "--untracked-files=no"], text=True).strip()
    if status:
        raise RuntimeError("SDK manager tracked files have changes; inspect them before setup.")
    subprocess.run([sys.executable, str(SDK / "emsdk.py"), "install", SDK_VERSION],
                   cwd=ROOT, check=True)
    # No --permanent/--system flags: .emscripten belongs to the local SDK.
    subprocess.run([sys.executable, str(SDK / "emsdk.py"), "activate", SDK_VERSION],
                   cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   text=True)
    print(f"Local SDK {SDK_VERSION} ready: {SDK}")


def probe(command: list[str], *, env: dict[str, str] | None = None) -> dict:
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                                timeout=30, check=False)
        def decode(value: bytes) -> str:
            return value.decode("utf-16-le" if b"\x00" in value else "utf-8",
                                errors="replace").strip()
        return {"command": command, "exit_code": result.returncode,
                "stdout": decode(result.stdout), "stderr": decode(result.stderr)}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command": command, "error": str(exc)}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def environment() -> dict:
    report = {"captured_at_utc": datetime.now(timezone.utc).isoformat(),
              "platform": platform.platform(), "machine": platform.machine(),
              "python": sys.version, "python_executable": sys.executable,
              "sdk_version": SDK_VERSION, "sdk_manager_commit": SDK_COMMIT,
              "sdk_release": SDK_RELEASE, "sdk_directory": str(SDK),
              "architecture": "native Windows tools; no WSL dependency",
              "dependencies": {}, "checks": {}}
    for package in ("pefile", "capstone", "unicorn"):
        try:
            report["dependencies"][package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            report["dependencies"][package] = None
    commands = {"git": ["git", "--version"], "wsl": ["wsl", "--list", "--verbose"]}
    if (SDK / ".emscripten").is_file():
        commands.update({"emcc": [*emcc_command(), "--version"],
                         "clang": [str(clang_path()), "--version"],
                         "clang_targets": [str(clang_path()), "--print-targets"],
                         "lld": [*linker_command(), "--version"],
                         "node": [str(node_path()), "--version"]})
    for name, command in commands.items():
        report["checks"][name] = probe(command, env=toolchain_env() if name == "emcc" else None)
    report["download_sha256"] = {
        path.name: {"bytes": path.stat().st_size, "sha256": sha256(path)}
        for path in sorted((SDK / "downloads").glob("*.zip"))
    }
    report["tool_sha256"] = {
        str(path.relative_to(SDK)): sha256(path)
        for path in (SDK / "upstream/bin/clang.exe", SDK / "upstream/bin/lld.exe",
                     SDK / "upstream/emscripten/emcc.py", SDK / "emsdk.py")
        if path.is_file()
    }
    # Record browser availability; actual browser/GPU validation is separate.
    report["browser_candidates"] = [str(path) for path in (
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
    ) if path.is_file()]
    dest = ROOT / "artifacts/environment.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Environment evidence: {dest}")
    return report


def smoke() -> dict:
    """Toolchain smoke only. This does not claim binary translation or gameplay."""
    directory = ROOT / "build/toolchain-smoke"
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "wasm.c"
    source.write_text("int answer(void) { return 6 * 7; }\n", encoding="utf-8")
    common = ["-O1", "--no-entry", "-sMODULARIZE=1", "-sEXPORT_ES6=1",
              "-sENVIRONMENT=node,web,worker", "-sASSERTIONS=2"]
    output = directory / "wasm.mjs"
    compile_wasm(source, output, [*common, '-sEXPORTED_FUNCTIONS=["_answer"]'])
    js = ("import fs from 'node:fs';import create from './wasm.mjs';"
          "const m=await create({wasmBinary:fs.readFileSync(new URL('./wasm.wasm',import.meta.url))});"
          "if(m._answer()!==42)throw Error('Wasm result diverged');"
          "console.log(JSON.stringify({answer:m._answer()}));")
    runner = directory / "run.mjs"
    runner.write_text(js, encoding="utf-8")
    reference = probe([str(node_path()), str(runner)])
    if reference.get("exit_code") != 0:
        raise RuntimeError(f"Wasm execution smoke failed: {reference}")
    gpu_source = directory / "webgpu.c"
    gpu_source.write_text(
        "#include <webgpu/webgpu.h>\n"
        "int binding_probe(void) {\n"
        "  WGPUInstance instance = wgpuCreateInstance(0);\n"
        "  if (!instance) return 0;\n"
        "  wgpuInstanceRelease(instance); return 1;\n"
        "}\n", encoding="utf-8")
    compile_wasm(gpu_source, directory / "webgpu.mjs", [*common,
        "--use-port=emdawnwebgpu", '-sEXPORTED_FUNCTIONS=["_binding_probe"]'])
    report = {"sdk_version": SDK_VERSION, "wasm_execution": reference,
              "emdawnwebgpu": {"compile_and_link": "passed", "port": "--use-port=emdawnwebgpu",
                               "browser_execution": "unverified by this smoke command"},
              "scope": "toolchain and binding validation only; no translated binary or game execution"}
    dest = ROOT / "artifacts/toolchain-smoke.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Toolchain smoke evidence: {dest}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["setup", "environment", "smoke"])
    args = parser.parse_args()
    {"setup": setup, "environment": environment, "smoke": smoke}[args.action]()


if __name__ == "__main__":
    main()
