// Every _run() executes ahead-of-time translated x86 in Wasm. JavaScript owns
// isolated case setup/observation only; it does not interpret x86 instructions.
const MAX_CHUNK = 10000;
const keys = new Set();
let running = false;
const send = (type, data = {}) => self.postMessage({type, ...data});
const nextTurn = () => new Promise(resolve => setTimeout(resolve, 0));
const unsigned = value => Number(value) >>> 0;

function buildURL(name) {
  if (typeof name !== "string" || !/^[a-zA-Z0-9_./-]+$/.test(name) || name.startsWith("/") || name.split("/").some(part => !part || part === ".." || part === ".")) {
    throw new Error("Invalid relative build artifact name");
  }
  return new URL(`/build/${name}`, self.location.origin).href;
}

async function readJSON(name) {
  const response = await fetch(buildURL(name), {cache: "no-store"});
  if (!response.ok) throw new Error(`${name} is unavailable (HTTP ${response.status}). Build this artifact, then restart the local server.`);
  return response.json();
}

async function loadModule(name, artifactHashes = {}) {
  const moduleURL = buildURL(name);
  const {default: createModule} = await import(moduleURL);
  if (typeof createModule !== "function") throw new Error("Expected an Emscripten ES module factory");
  const wasmName = name.replace(/\.(?:m?js)$/, ".wasm");
  const expectedHash = artifactHashes[wasmName];
  let wasmBinary;
  let actualHash = null;
  if (expectedHash) {
    const response = await fetch(buildURL(wasmName), {cache: "no-store"});
    if (!response.ok) throw new Error(`Wasm artifact is unavailable: ${wasmName} HTTP ${response.status}`);
    wasmBinary = new Uint8Array(await response.arrayBuffer());
    const digest = await crypto.subtle.digest("SHA-256", wasmBinary);
    actualHash = Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, "0")).join("");
    if (actualHash !== expectedHash.toLowerCase()) throw new Error(`Wasm artifact identity mismatch: ${wasmName}`);
  }
  const module = await createModule({
    locateFile: filename => buildURL(filename),
    ...(wasmBinary ? {wasmBinary} : {}),
    print: message => send("wasm-stdout", {message}),
    printErr: message => send("wasm-stderr", {message}),
  });
  for (const name of ["_reset", "_memory_base", "_memory_size", "_map_region", "_set_reg", "_get_reg", "_set_eip", "_get_eip", "_set_flags", "_get_flags", "_run", "_fault_code", "_fault_address", "_fault_text", "_set_xmm", "_get_xmm", "_get_fpu_control", "_get_fpu_status", "_get_fpu_depth", "_set_fpu_control", "_set_fpu_status", "UTF8ToString"]) {
    if (typeof module[name] !== "function") throw new Error(`Translated module is missing ${name}`);
  }
  if (!(module.HEAPU8 instanceof Uint8Array)) throw new Error("Translated module does not expose its Wasm byte heap");
  send("wasm-ready", {module: name, wasmMemoryBytes: module.HEAPU8.byteLength, guestMemoryBytes: module._memory_size(), wasmSHA256: actualHash, hashVerified: Boolean(expectedHash)});
  return module;
}

function guestBytes(module, address, size) {
  if (!Number.isSafeInteger(address) || !Number.isSafeInteger(size) || address < 0 || size < 0 || address + size > unsigned(module._memory_size())) {
    throw new Error(`Guest-memory range is out of bounds: address=0x${unsigned(address).toString(16)}, size=${size}`);
  }
  const start = unsigned(module._memory_base()) + address;
  if (start + size > module.HEAPU8.length) throw new Error("Guest memory mapping exceeds Wasm heap");
  return module.HEAPU8.subarray(start, start + size);
}

function mapRegions(module, regions) {
  if (!Array.isArray(regions) || !regions.length) throw new Error("Case has no guest-memory regions");
  for (const region of regions) {
    guestBytes(module, region.address, region.size);
    const mapped = module._map_region(region.address, region.size, region.permissions);
    if (mapped !== 1 || module._fault_code()) {
      throw new Error(`Guest map failed: ${module.UTF8ToString(module._fault_text())}`);
    }
  }
}

async function initializeCase(module, test, image = null) {
  module._reset();
  if (typeof module._configure_platform === "function") module._configure_platform(image?.address || 0);
  else if (typeof module._win32_reset === "function") module._win32_reset(image?.address || 0);
  mapRegions(module, test.regions);
  if (image) {
    const response = await fetch(buildURL(image.url || image.path), {cache: "no-store"});
    if (!response.ok) throw new Error(`Startup memory image is missing: HTTP ${response.status}`);
    const length = Number(response.headers.get("Content-Length"));
    if (!Number.isSafeInteger(length) || length < 1) throw new Error("Startup memory image has no valid length");
    guestBytes(module, image.address, length);
    const reader = response.body.getReader();
    let offset = 0;
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      if (offset + value.length > length) {await reader.cancel(); throw new Error("Startup image exceeded its declared length");}
      guestBytes(module, image.address + offset, value.length).set(value);
      offset += value.length;
    }
    if (offset !== length) throw new Error("Startup image ended before its declared length");
    const digest = await crypto.subtle.digest("SHA-256", guestBytes(module, image.address, length));
    const sha256 = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
    if (image.sha256 && sha256 !== image.sha256) throw new Error("Startup image SHA-256 does not match its build manifest");
    send("image-loaded", {url: image.url || image.path, address: image.address, bytes: offset, sha256, hashVerified: Boolean(image.sha256)});
  }
  for (const write of test.writes || []) {
    if (!Array.isArray(write.bytes) || write.bytes.some(value => !Number.isInteger(value) || value < 0 || value > 255)) throw new Error("Case memory writes must contain byte values");
    guestBytes(module, write.address, write.bytes.length).set(write.bytes);
  }
  if (!Array.isArray(test.registers) || test.registers.length !== 8) throw new Error("Case must initialize all eight general registers");
  test.registers.forEach((value, index) => module._set_reg(index, value));
  for (let register = 0; register < (test.xmm || []).length; register++) {
    test.xmm[register].forEach((value, lane) => module._set_xmm(register, lane, value));
  }
  module._set_flags(test.eflags);
  module._set_eip(test.entry);
  if (test.fsBase !== undefined) {
    if (typeof module._set_fs_base !== "function") throw new Error("This case requires the FS segment-base export");
    module._set_fs_base(test.fsBase);
  }
  if (test.fpuControl !== undefined) module._set_fpu_control(test.fpuControl);
  if (test.fpuStatus !== undefined) module._set_fpu_status(test.fpuStatus);
}

function cpuState(module) {
  return {registers: Array.from({length: 8}, (_, index) => unsigned(module._get_reg(index))), eip: unsigned(module._get_eip()), eflags: unsigned(module._get_flags()), xmm: Array.from({length: 8}, (_, register) => Array.from({length: 4}, (_, lane) => unsigned(module._get_xmm(register, lane)))), fpu: {control: module._get_fpu_control(), status: module._get_fpu_status(), depth: module._get_fpu_depth()}};
}

async function execute(module, test) {
  const limit = test.maxSteps ?? 100000;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10000000) throw new Error("Case maxSteps must be in 1..10000000");
  const began = performance.now();
  let issued = 0;
  let code = 0;
  while (issued < limit) {
    const budget = Math.min(MAX_CHUNK, limit - issued);
    code = module._run(budget, test.stop);
    issued += budget;
    if (code !== 0) break;
    // Yield between deterministic instruction budgets to receive input/stop
    // messages. This does not change guest state or hide a deadlock.
    await nextTurn();
  }
  if (![0, 1, 2].includes(code)) throw new Error(`Unexpected translated execution status ${code}`);
  const trace = typeof module._get_trace_count === "function" && typeof module._get_trace === "function"
    ? Array.from({length: Math.min(256, module._get_trace_count())}, (_, index) => unsigned(module._get_trace(Math.max(0, module._get_trace_count()-256)+index))) : null;
  return {code, budgetIssued: issued, steps: typeof module._get_steps === "function" ? module._get_steps() : null,
    trace, elapsedMs: performance.now() - began, cpu: cpuState(module),
    fault: code === 2 ? {code: module._fault_code(), address: unsigned(module._fault_address()), message: module.UTF8ToString(module._fault_text())} : null};
}

function compareCase(module, test, execution) {
  const mismatches = [];
  if (test.expectedFault !== undefined) {
    if (execution.code !== 2 || execution.fault?.code !== test.expectedFault) mismatches.push({field: "expectedFault", expected: test.expectedFault, actual: execution.fault?.code ?? execution.code});
    for (const block of test.unchangedOnFault || []) {
      const bytes = guestBytes(module, block.address, block.bytes.length);
      for (let i = 0; i < bytes.length; i++) if (bytes[i] !== block.bytes[i]) mismatches.push({field: "faultRollback", address: block.address+i, expected: block.bytes[i], actual: bytes[i]});
    }
    for (const [field, expected] of Object.entries(test.expectedFpuOnFault || {})) {
      if (execution.cpu.fpu[field] !== expected) mismatches.push({field: `x87.${field}`, expected, actual: execution.cpu.fpu[field]});
    }
    (test.expectedRegistersOnFault || []).forEach((expected, index) => {
      if (execution.cpu.registers[index] !== expected) mismatches.push({field: `registers[${index}]`, expected, actual: execution.cpu.registers[index]});
    });
    return mismatches;
  }
  const expected = test.expected;
  if (!expected || !Array.isArray(expected.registers) || expected.registers.length !== 8) throw new Error(`Case ${test.id} has no complete CPU reference`);
  if (execution.code !== 1) mismatches.push({field: "execution", expected: "reference stop address", actual: execution.code === 2 ? execution.fault : "instruction budget exhausted"});
  expected.registers.forEach((value, index) => {
    if (unsigned(value) !== execution.cpu.registers[index]) mismatches.push({field: `registers[${index}]`, expected: unsigned(value), actual: execution.cpu.registers[index]});
  });
  const mask = unsigned(expected.flagsMask ?? 0xffffffff);
  if (expected.fpuControl !== undefined && expected.fpuControl !== execution.cpu.fpu.control) mismatches.push({field: "x87.control", expected: expected.fpuControl, actual: execution.cpu.fpu.control});
  if (expected.fpuStatus !== undefined && expected.fpuStatus !== execution.cpu.fpu.status) mismatches.push({field: "x87.status", expected: expected.fpuStatus, actual: execution.cpu.fpu.status});
  if (unsigned(expected.eflags & mask) !== unsigned(execution.cpu.eflags & mask)) mismatches.push({field: "eflags", mask, expected: unsigned(expected.eflags), actual: execution.cpu.eflags});
  for (let register = 0; register < (expected.xmm || []).length; register++) {
    expected.xmm[register].forEach((value, lane) => {
      if (unsigned(value) !== execution.cpu.xmm[register][lane]) mismatches.push({field: `xmm[${register}][${lane}]`, expected: unsigned(value), actual: execution.cpu.xmm[register][lane]});
    });
  }
  for (const block of expected.memory || []) {
    const bytes = guestBytes(module, block.address, block.bytes.length);
    for (let index = 0; index < bytes.length; index++) {
      if (bytes[index] !== block.bytes[index]) {
        mismatches.push({field: "memory", address: block.address + index, expected: block.bytes[index], actual: bytes[index]});
        if (mismatches.length >= 100) return mismatches;
      }
    }
  }
  return mismatches;
}

async function tests() {
  const suiteStarted = performance.now();
  send("phase", {message: "Loading translation manifest and reference cases…"});
  const manifest = await readJSON("manifest.json");
  if (manifest.schema !== 1 || (manifest.kind && manifest.kind !== "differential-tests")) throw new Error("Unsupported differential-test manifest");
  send("build-loaded", {manifest});
  const suites = manifest.suites || [{id: "default", module: manifest.module, cases: manifest.cases}];
  if (!Array.isArray(suites) || !suites.length) throw new Error("No test suites in build manifest");
  const results = [];
  let peakWasmMemoryBytes = 0;
  for (const item of suites) {
    const suite = await readJSON(item.cases);
    if (suite.schema !== 1 || !Array.isArray(suite.cases) || !suite.cases.length) throw new Error("No binary differential tests in cases artifact");
    if (item.faultCases) {
      const faults = await readJSON(item.faultCases);
      if (faults.schema !== 1 || !Array.isArray(faults.cases)) throw new Error("Invalid expected-fault cases artifact");
      suite.cases.push(...faults.cases);
    }
    const module = await loadModule(item.module, manifest.artifact_sha256);
    peakWasmMemoryBytes = Math.max(peakWasmMemoryBytes, module.HEAPU8.byteLength);
    for (const test of suite.cases) {
      send("phase", {message: `Executing binary case: ${item.id}/${test.id}`});
      await initializeCase(module, test, item.image || null);
      const execution = await execute(module, test);
      const mismatches = compareCase(module, test, execution);
      const result = {suite: item.id, id: test.id, passed: mismatches.length === 0, ...execution, mismatches};
      results.push(result);
      send("test-case", result);
      await nextTurn();
    }
  }
  send("test-complete", {result: {state: "tested", manifest, total: results.length, passed: results.filter(result => result.passed).length, results, elapsedMs: performance.now() - suiteStarted, peakModuleWasmMemoryBytes: peakWasmMemoryBytes, gameplayDemonstrated: false}});
}

async function startup() {
  send("phase", {message: "Loading startup manifest; missing artifacts produce an explicit failure…"});
  const manifest = await readJSON("startup.json");
  if (manifest.schema !== 1 || (manifest.kind && manifest.kind !== "startup-probe") || !manifest.case) throw new Error("Unsupported startup manifest; expected schema 1 with case");
  const module = await loadModule(manifest.module, manifest.artifact_sha256);
  // Mapped PE image bytes precede isolated state writes. No native execution.
  await initializeCase(module, manifest.case, manifest.image);
  const execution = await execute(module, manifest.case);
  const stack = execution.cpu.registers[4];
  if (stack + 48 <= unsigned(module._memory_size())) {
    const bytes = guestBytes(module, stack, 48);
    const words = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    execution.stackWords = Array.from({length: 12}, (_, index) => words.getUint32(index * 4, true));
  }
  if (execution.fault && execution.fault.address < unsigned(module._memory_size())) {
    const address = Math.max(0, execution.fault.address - 16);
    const length = Math.min(64, unsigned(module._memory_size()) - address);
    execution.faultMemory = {address, bytes: Array.from(guestBytes(module, address, length))};
  }
  send("startup-complete", {result: {state: execution.code === 1 ? "stopped-at-observation" : execution.code === 2 ? "guest-fault" : "budget-exhausted", manifest, ...execution, wasmMemoryBytes: module.HEAPU8.byteLength, authenticMenuDemonstrated: false, playableRaceDemonstrated: false}});
}

async function bindingProbe() {
  const moduleURL = buildURL("toolchain-smoke/webgpu.mjs");
  const {default: createModule} = await import(moduleURL);
  const module = await createModule({locateFile: filename => buildURL(`toolchain-smoke/${filename}`)});
  if (typeof module._binding_probe !== "function") throw new Error("Emdawn binding probe export is missing");
  const result = module._binding_probe();
  if (result !== 1) throw new Error(`Emdawn instance creation returned ${result}`);
  send("binding-complete", {result: {returned: result, scope: "Pinned Emdawn C WebGPU instance creation/release; device verified separately through browser API"}});
}

self.onmessage = async ({data}) => {
  if (data.type === "input") {
    if (data.down) keys.add(data.code); else keys.delete(data.code);
    send("worker-input", {code: data.code, down: data.down, heldKeys: keys.size, gameplayConnected: false});
    return;
  }
  if (data.type === "release-input") {keys.clear(); return;}
  if (data.type === "binding") {
    try {await bindingProbe();}
    catch (error) {send("binding-failure", {message: error.message, stack: error.stack});}
    return;
  }
  if (!["tests", "startup"].includes(data.type)) {send("failure", {message: "Unsupported worker request"}); return;}
  if (running) {send("failure", {message: "Worker is already executing", operation: data.type}); return;}
  running = true;
  try {await (data.type === "tests" ? tests() : startup());}
  catch (error) {send("failure", {operation: data.type, message: error.message, stack: error.stack});}
  finally {running = false;}
};
send("worker-ready", {webAssembly: typeof WebAssembly !== "undefined", crossOriginIsolated: self.crossOriginIsolated});
