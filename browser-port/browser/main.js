import {initializeWebGPU} from "/renderer/webgpu.js";
import {compactSummary, visibleEvents} from "/browser/diagnostic-view.js";

const element = id => document.getElementById(id);
const diagnostics = {schema: 1, startedAt: new Date().toISOString(), userAgent: navigator.userAgent, events: [], environment: {}, server: null, tests: null, startup: null};
// Read-only-by-convention observation surface for local browser automation.
window.__portDiagnostics = diagnostics;
let worker = null;
let gpu = null;
let checking = false;
let busy = false;
let redrawTimer = null;
let pendingStatus = {message: "Inspecting local build…", error: false};

function scheduleView() {
  if (redrawTimer !== null) return;
  // Coalesce presentation updates only. Guest execution/worker scheduling is
  // independent; no complete CPU-state arrays are copied into the live DOM.
  redrawTimer = setTimeout(() => {
    redrawTimer = null;
    element("status").textContent = pendingStatus.message;
    element("status").classList.toggle("error", pendingStatus.error);
    element("events").textContent = visibleEvents(diagnostics.events);
    element("summary").textContent = JSON.stringify(compactSummary(diagnostics), null, 2);
  }, 100);
}

function record(type, data = {}) {
  diagnostics.events.push({time: new Date().toISOString(), type, ...data});
  scheduleView();
}

function status(message, error = false) {
  pendingStatus = {message, error};
  scheduleView();
}

function setBusy(value) {
  busy = value;
  element("tests").disabled = value;
  element("startup").disabled = value;
  element("stop").disabled = !value;
}

function createWorker() {
  if (worker) worker.terminate();
  worker = new Worker("/browser/worker.js", {type: "module", name: "translated-x86"});
  worker.onmessage = ({data}) => {
    if (data.type === "test-complete") {
      diagnostics.tests = data.result;
      diagnostics.progress.state = "finished";
      setBusy(false);
      status(`${data.result.passed}/${data.result.total} binary differential tests passed. Gameplay remains unverified.`, data.result.passed !== data.result.total);
    } else if (data.type === "startup-complete") {
      diagnostics.startup = data.result;
      setBusy(false);
      const message = data.result.fault
        ? `Startup stopped after ${data.result.steps} dispatches: ${data.result.fault.message}.`
        : `Translated startup probe: ${data.result.state}. See guest diagnostics.`;
      status(message, data.result.state !== "stopped-at-observation");
    } else if (data.type === "test-case") {
      diagnostics.progress.completed++;
      diagnostics.progress.passed += Number(data.passed);
      diagnostics.progress.failed += Number(!data.passed);
      diagnostics.progress.lastCase = `${data.suite}/${data.id}`;
    } else if (data.type === "build-loaded") {
      diagnostics.build = data.manifest;
    } else if (data.type === "failure") {
      if (data.operation === "startup") diagnostics.startup = {state: "failed", error: data.message};
      if (data.operation === "tests") diagnostics.tests = {state: "failed", error: data.message};
      if (data.operation === "tests" && diagnostics.progress) diagnostics.progress.state = "failed";
      setBusy(false);
      status(data.message, true);
    } else if (data.type === "phase") {
      status(data.message);
    } else if (data.type === "binding-complete") {
      diagnostics.environment.emdawn = data.result;
    } else if (data.type === "binding-failure") {
      diagnostics.environment.emdawn = {error: data.message};
    }
    record(data.type, data);
  };
  worker.onerror = event => {
    setBusy(false);
    status(`Worker error: ${event.message}`, true);
    record("worker-error", {message: event.message, filename: event.filename, line: event.lineno});
  };
  worker.onmessageerror = () => {setBusy(false); record("worker-message-error"); status("Worker message could not be decoded", true);};
}

async function checkEnvironment() {
  if (checking) return;
  checking = true;
  element("environment").disabled = true;
  try {
    diagnostics.environment = {secureContext: isSecureContext, crossOriginIsolated, webAssembly: typeof WebAssembly !== "undefined", sharedArrayBuffer: typeof SharedArrayBuffer !== "undefined", workers: typeof Worker !== "undefined", webgpu: "checking"};
    if (navigator.storage?.estimate) {
      const storage = await navigator.storage.estimate();
      diagnostics.environment.storage = {usageBytes: storage.usage, quotaBytes: storage.quota};
    }
    const response = await fetch("/api/status", {cache: "no-store"});
    if (!response.ok) throw new Error(`Read-only resource server returned HTTP ${response.status}`);
    diagnostics.server = await response.json();
    record("server-ready", diagnostics.server);
    if (diagnostics.server.build_files.includes("toolchain-smoke/webgpu.mjs")) worker?.postMessage({type: "binding"});
    else diagnostics.environment.emdawn = {state: "No compiled binding probe in server index"};
    if (!diagnostics.environment.webAssembly) throw new Error("WebAssembly is unavailable");
    if (!diagnostics.environment.workers) throw new Error("Web Workers are unavailable");
    if (!crossOriginIsolated) throw new Error("Cross-origin isolation failed; check COOP/COEP headers");
    if (gpu) gpu.dispose();
    gpu = await initializeWebGPU(element("screen"), record);
    diagnostics.environment.webgpu = gpu.observation;
    status("Browser services ready. Run binary translation tests or the startup probe.");
    record("environment-ready");
  } catch (error) {
    diagnostics.environment.webgpu = {error: error.message};
    status(error.message, true);
    record("environment-error", {message: error.message, stack: error.stack});
  } finally {
    checking = false;
    element("environment").disabled = false;
  }
}

function start(operation) {
  if (busy) return;
  if (operation === "tests") {
    diagnostics.tests = {state: "running"};
    diagnostics.progress = {state: "running", completed: 0, passed: 0, failed: 0, lastCase: null};
  }
  createWorker();
  setBusy(true);
  status(operation === "tests" ? "Loading binary translation tests…" : "Loading translated startup probe…");
  worker.postMessage({type: operation});
}

element("environment").addEventListener("click", checkEnvironment);
element("tests").addEventListener("click", () => start("tests"));
element("startup").addEventListener("click", () => start("startup"));
element("stop").addEventListener("click", () => {
  worker?.terminate(); worker = null; setBusy(false);
  if (diagnostics.progress?.state === "running") {
    diagnostics.progress.state = "stopped";
    diagnostics.tests.state = "stopped";
  }
  record("worker-terminated-by-user");
  status("Worker stopped. Incomplete execution is not a passed test.");
});
element("export").addEventListener("click", () => {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([JSON.stringify(diagnostics, null, 2)], {type: "application/json"}));
  link.download = `browser-port-diagnostics-${Date.now()}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});
element("screen").addEventListener("click", () => element("screen").focus());
for (const type of ["keydown", "keyup"]) {
  element("screen").addEventListener(type, event => {
    if (event.code === "Escape") {element("screen").blur(); return;}
    event.preventDefault();
    worker?.postMessage({type: "input", code: event.code, down: type === "keydown", repeat: event.repeat, timestamp: performance.now()});
    record("input-observed", {code: event.code, down: type === "keydown", workerPresent: Boolean(worker), gameplayConnected: false});
  });
}
element("screen").addEventListener("blur", () => worker?.postMessage({type: "release-input"}));
window.addEventListener("error", event => record("window-error", {message: event.message, filename: event.filename, line: event.lineno}));
window.addEventListener("unhandledrejection", event => record("unhandled-rejection", {message: String(event.reason), stack: event.reason?.stack}));
createWorker();
checkEnvironment();
