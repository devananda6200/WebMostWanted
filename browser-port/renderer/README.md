# Rendering boundary

`webgpu.js` requests a real WebGPU adapter and device, configures the canvas,
submits one clear pass, waits for submission, and records validation/device-loss
errors. The clear is an infrastructure test. It renders no game geometry and is
not evidence of a menu or race.

The toolchain smoke artifact separately compiles Emdawnwebgpu's C interface using
Emscripten 4.0.23 and its pinned `emdawnwebgpu` v20251002.162335 port (Dawn source
revision `01940842b667a7812d0e4ca0ef4367fbec294241`). The browser worker invokes
`_binding_probe()` when that artifact is present; its returned value is recorded
under `environment.emdawn`. This proves C binding instance creation/release only.
The JS probe supplies the independent adapter/device check. No obsolete
`-sUSE_WEBGPU` compiler flag is used.

Direct3D 9 device/COM compatibility, state tracking, resource conversion, shader
translation and original-game draw submission remain unimplemented. Required
game graphics calls must fail explicitly until implemented; an initialization
clear must never be reported as a translated game frame.

Sources checked while implementing this host:

- [Emscripten WebGPU support](https://emscripten.org/docs/porting/multimedia_and_graphics/WebGPU-support.html)
- [Official Emdawnwebgpu package instructions](https://github.com/google/dawn/blob/main/src/emdawnwebgpu/pkg/README.md)
- [WebGPU specification](https://gpuweb.github.io/gpuweb/)
