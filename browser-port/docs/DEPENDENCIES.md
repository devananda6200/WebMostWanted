# Dependencies and provenance

This project is new implementation source. General-purpose tools below are
downloaded into ignored `.tools/` or `.venv/`; no game executable, resource,
memory dump, or generated game code is sent to these services.

## Native Windows build arrangement

The inspected machine has Windows AMD64, Python 3.11.0, Git 2.53.0.windows.2,
Chrome and Edge. WSL lists only the stopped `docker-desktop` distribution, so
the build uses native Windows tools. Installed Visual Studio MSVC tools were
found, but the reproducible fixture build uses the SDK's Clang and LLD.

The portable SDK is local to `.tools/emsdk-4.0.23`. Setup uses no installer,
no administrator rights, no persistent PATH changes, no `--system`, and no
`--permanent` activation. `tools/toolchain.py` passes an explicit local
`EM_CONFIG`, `EM_CACHE`, and `EM_PORTS` to each build process.

| Component | Pinned identity | Purpose | License/source |
| --- | --- | --- | --- |
| emsdk | 4.0.23; manager commit `c0bb220cb6e6f4e0fabb6f6db9efd53390ef5e56` | Portable compiler SDK download and local configuration | [MIT, official repository](https://github.com/emscripten-core/emsdk/tree/4.0.23) |
| Emscripten | 4.0.23; compiler commit `7a5d93b50f6a3a35e85a0d2fc9e667b8498e6aed`; release `aaa43392544d695232b70eda706d751f18980c2a` | Compile generated C/C++ to Wasm | [MIT or Illinois/NCSA](https://github.com/emscripten-core/emscripten/blob/4.0.23/LICENSE) |
| LLVM Clang / LLD | bundled 22.0.0git, commit `5243501cca02d7e54294d4bb5de0a85b06c40b7d` | Assemble original x86 test binary, COFF linking, Wasm compilation | [Apache-2.0 with LLVM exceptions; repository subcomponents retain applicable notices](https://llvm.org/docs/DeveloperPolicy.html#copyright-license-and-patents) |
| Node.js | SDK's 22.16.0 | Execute Wasm differential tests and compiler JS tools | [MIT, bundled notices](https://github.com/nodejs/node/blob/v22.16.0/LICENSE) |
| SDK Python | SDK's 3.13.3 | SDK-bundled helper runtime; project tools use `.venv` Python | [PSF license and bundled notices](https://github.com/python/cpython/blob/v3.13.3/LICENSE) |
| pefile | 2024.8.26 | Parse actual PE files and map binary sections | [MIT](https://github.com/erocarrera/pefile/blob/master/LICENSE) |
| Capstone | 5.0.7 | Decode x86 operands/instructions for explicit translation rules | [BSD 3-Clause](https://github.com/capstone-engine/capstone/blob/5.0.7/LICENSE.TXT) |
| Unicorn | 2.1.4 | Bounded reference execution only, in local Python tests | [Core GPLv2](https://github.com/unicorn-engine/unicorn/blob/2.1.4/COPYING); Python bindings have BSD terms. Not linked into or delivered with the browser runtime. |
| Emdawnwebgpu | SDK remote port `v20251002.162335`; Dawn `01940842b667a7812d0e4ca0ef4367fbec294241` | `webgpu.h` C bindings on browser WebGPU | [Dawn BSD 3-Clause](https://dawn.googlesource.com/dawn/+/01940842b667a7812d0e4ca0ef4367fbec294241/LICENSE), with Emscripten-origin files MIT or Illinois/NCSA as stated in the port |

The inspected Capstone and pefile package licenses agree with those sources.
Unicorn's package metadata alone is insufficient: the core `COPYING` is GPLv2.
No third-party library source is copied into this project's implementation.
The native SDK contains third-party notices for its bundled components.

## WebGPU binding choice

[Current Emscripten WebGPU documentation](https://emscripten.org/docs/porting/multimedia_and_graphics/WebGPU-support.html)
routes C/C++ code through Emdawnwebgpu. The
[Dawn port instructions](https://github.com/google/dawn/blob/main/src/emdawnwebgpu/pkg/README.md)
require Emscripten 4.0.10 or newer for remote ports. The selected 4.0.23 SDK
vendors a pinned remote port; compilation and linking both use
`--use-port=emdawnwebgpu`, never the obsolete `-sUSE_WEBGPU` setting.

The SDK remote port verifies the package with SHA-512:

```text
ed15672c2c495a77c764929e6979f4e155bf8b9c46dee5b0f234f3208a708bc2b846d89eef345b725d03454b56d549531f48fc84ff2afe7627d14115893b0fb0
```

The C API is chosen for the probe because Dawn-specific and C++ headers have
weaker API stability guarantees. A successful binding compile is not evidence
of Direct3D compatibility, game rendering, browser adapter availability, or
race execution. The browser host records its separate adapter/device checks.

## Reproduce and inspect

Run these PowerShell commands from `browser-port/`:

```powershell
.\scripts\setup.ps1
.\scripts\environment.ps1
.\.venv\Scripts\python.exe -m tools.toolchain smoke
```

The setup script creates only the local virtual environment and portable SDK.
`-SkipPythonDependencies` preserves the existing environment during SDK-only
setup. SDK setup refuses a manager checkout with a different commit or tracked
modifications. [Official installation instructions](https://emscripten.org/docs/getting_started/downloads.html)
and [SDK command documentation](https://emscripten.org/docs/tools_reference/emsdk.html)
describe this version-pinned download mechanism.

`artifacts/environment.json` records observed executable versions, registered
Clang targets, dependency versions, compiler SHA-256 hashes, browser paths and
WSL state. `artifacts/toolchain-smoke.json` records toolchain smoke outcomes.
`build/toolchain-smoke/` contains reproducible generated smoke sources and
their outputs. Its arithmetic source-to-Wasm smoke is explicitly **not** the
binary-translation acceptance test; that test must consume a compiled PE.

Python callers use `emcc_command()`, `toolchain_env()`, `compile_wasm(...)`,
`clang_path()` and `linker_command()` from `tools.toolchain`. The latter selects
the COFF driver as `lld.exe -flavor link`; this SDK has no `lld-link.exe`.
