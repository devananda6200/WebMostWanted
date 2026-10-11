// Presentation is deliberately small. Raw events, CPU snapshots and all test
// comparisons stay in __portDiagnostics and the exported JSON evidence.
const clipped = (value, length = 240) => String(value ?? "").slice(0, length);
const hex = value => value === undefined ? undefined : `0x${(Number(value) >>> 0).toString(16)}`;

function testSummary(test) {
  if (!test) return null;
  return {state: test.state, passed: test.passed, total: test.total,
    elapsedMs: test.elapsedMs, peakModuleWasmMemoryBytes: test.peakModuleWasmMemoryBytes,
    error: test.error ? clipped(test.error) : undefined,
    failures: (test.results || []).filter(result => !result.passed).slice(0, 3).map(result => ({
      suite: result.suite, id: result.id, fault: result.fault?.message,
      firstMismatch: result.mismatches?.[0],
    }))};
}

function startupSummary(startup) {
  if (!startup) return null;
  return {state: startup.state, error: startup.error ? clipped(startup.error) : undefined,
    steps: startup.steps, elapsedMs: startup.elapsedMs, eip: hex(startup.cpu?.eip),
    fault: startup.fault ? {code: startup.fault.code, address: hex(startup.fault.address), message: clipped(startup.fault.message)} : undefined,
    wasmMemoryBytes: startup.wasmMemoryBytes, authenticMenuDemonstrated: startup.authenticMenuDemonstrated};
}

export function compactSummary(diagnostics) {
  const environment = diagnostics.environment || {};
  const gpu = environment.webgpu;
  const build = diagnostics.build || diagnostics.tests?.manifest;
  return {
    environment: {secureContext: environment.secureContext, crossOriginIsolated: environment.crossOriginIsolated,
      webAssembly: environment.webAssembly, workers: environment.workers, sharedArrayBuffer: environment.sharedArrayBuffer,
      webgpu: typeof gpu === "object" ? {adapter: gpu.adapter, fallback: gpu.fallback, format: gpu.format, error: gpu.error} : gpu,
      emdawn: environment.emdawn, storage: environment.storage},
    assets: diagnostics.server ? {readOnly: diagnostics.server.read_only, files: diagnostics.server.asset_files,
      totalBytes: diagnostics.server.asset_bytes, maxRequestBytes: diagnostics.server.asset_request_limit} : null,
    build: build ? {builtAt: build.built_at_utc, toolchain: build.toolchain,
      inputSHA256: (build.suites || []).map(suite => ({suite: suite.id, sha256: suite.input_sha256})),
      wasmSHA256: build.artifact_sha256} : null,
    progress: diagnostics.progress || null,
    tests: testSummary(diagnostics.tests), startup: startupSummary(diagnostics.startup),
    retainedEvents: diagnostics.events.length,
    evidence: "Full processor state and comparison results are available in Export diagnostics.",
  };
}

export function compactEvent(event) {
  const result = {time: event.time, type: event.type};
  if (event.type === "test-case") {
    Object.assign(result, {suite: event.suite, id: event.id, passed: event.passed,
      steps: event.steps, elapsedMs: event.elapsedMs, mismatchCount: event.mismatches?.length,
      fault: event.fault?.message ? clipped(event.fault.message) : undefined});
  } else if (event.type === "test-complete") {
    Object.assign(result, {passed: event.result.passed, total: event.result.total, elapsedMs: event.result.elapsedMs});
  } else if (event.type === "startup-complete") {
    result.observation = startupSummary(event.result);
  } else {
    for (const key of ["message", "operation", "module", "wasmSHA256", "hashVerified", "code", "down", "asset_files", "bytes", "address", "crossOriginIsolated"]) {
      if (event[key] !== undefined) result[key] = typeof event[key] === "string" ? clipped(event[key]) : event[key];
    }
    if (event.type === "binding-complete") result.returned = event.result?.returned;
  }
  return result;
}

export function visibleEvents(events) {
  return events.slice(-15).map(event => JSON.stringify(compactEvent(event))).join("\n");
}
