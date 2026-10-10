// Browser-service validation only. No Direct3D operations are translated here.
export async function initializeWebGPU(canvas, record) {
  if (!globalThis.isSecureContext) throw new Error("WebGPU requires a secure or localhost context");
  if (!navigator.gpu) throw new Error("WebGPU is unavailable in this browser");
  const adapter = await navigator.gpu.requestAdapter();
  if (!adapter) throw new Error("WebGPU did not provide an adapter");
  const device = await adapter.requestDevice();
  let intentionallyDestroyed = false;
  device.addEventListener("uncapturederror", event => record("webgpu-validation-error", {message: event.error.message}));
  device.lost.then(info => {
    if (!intentionallyDestroyed) record("webgpu-device-lost", {reason: info.reason, message: info.message});
  });
  const context = canvas.getContext("webgpu");
  if (!context) {
    device.destroy();
    throw new Error("Canvas WebGPU context creation failed");
  }
  const format = navigator.gpu.getPreferredCanvasFormat();
  device.pushErrorScope("validation");
  context.configure({device, format, alphaMode: "opaque"});
  const encoder = device.createCommandEncoder({label: "Infrastructure initialization clear"});
  const pass = encoder.beginRenderPass({colorAttachments: [{view: context.getCurrentTexture().createView(), clearValue: {r: 0.035, g: 0.065, b: 0.07, a: 1}, loadOp: "clear", storeOp: "store"}]});
  pass.end();
  device.queue.submit([encoder.finish()]);
  await device.queue.onSubmittedWorkDone();
  const error = await device.popErrorScope();
  if (error) {
    device.destroy();
    throw new Error(`WebGPU initialization validation: ${error.message}`);
  }
  const info = adapter.info || {};
  const observation = {
    adapter: {vendor: info.vendor, architecture: info.architecture, device: info.device, description: info.description},
    fallback: adapter.isFallbackAdapter ?? info.isFallbackAdapter ?? null,
    format, width: canvas.width, height: canvas.height,
    features: [...device.features], maxBufferSize: device.limits.maxBufferSize,
    rendered: "Infrastructure clear; no original game draw calls",
  };
  record("webgpu-ready", observation);
  return {observation, dispose() { intentionallyDestroyed = true; context.unconfigure(); device.destroy(); }};
}
