/* Optional, read-only observations of the running browser host. */
if (new URLSearchParams(location.search).has('diagnostics')) {
  const panel = document.createElement('pre');
  panel.id = 'runtime-diagnostics';
  panel.style.cssText = 'position:fixed;bottom:0;left:0;margin:0;padding:8px;background:#000b;color:#bfe;font:12px monospace;pointer-events:none;max-width:100vw;max-height:30vh;overflow:hidden;white-space:pre-wrap';
  document.body.append(panel);
  const state = { started: new Date().toISOString(), frames: 0, timers: 0,
    longTasks: 0, longestTaskMs: 0, maxFrameGapMs: 0, input: [], errors: [] };
  let previous = performance.now();
  let frameWindow = 0;
  let timerWindow = 0;
  let sampleStart = previous;
  function frame(now) {
    state.frames++;
    frameWindow++;
    state.maxFrameGapMs = Math.max(state.maxFrameGapMs, now - previous);
    previous = now;
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
  try {
    new PerformanceObserver(list => {
      for (const entry of list.getEntries()) {
        state.longTasks++;
        state.longestTaskMs = Math.max(state.longestTaskMs, entry.duration);
      }
    }).observe({ type: 'longtask', buffered: true });
  } catch {}
  for (const type of ['keydown', 'keyup', 'pointerdown', 'pointerup']) {
    document.addEventListener(type, event => {
      state.input.push({ type, code: event.code, trusted: event.isTrusted,
        time: Math.round(performance.now()), target: event.target.id });
      state.input = state.input.slice(-10);
    }, true);
  }
  window.addEventListener('error', e => state.errors.push(e.message));
  window.addEventListener('unhandledrejection', e => state.errors.push(String(e.reason)));
  setInterval(() => {
    state.timers++;
    timerWindow++;
    const elapsed = (performance.now() - sampleStart) / 1000;
    if (elapsed < 5) return;
    state.rafHz = +(frameWindow / elapsed).toFixed(2);
    state.timerHz = +(timerWindow / elapsed).toFixed(2);
    state.visibility = document.visibilityState;
    state.focused = document.hasFocus();
    state.canvas = { width: canvas.width, height: canvas.height };
    state.lastLog = log.slice(-5);
    panel.textContent = JSON.stringify(state, null, 2);
    frameWindow = timerWindow = 0;
    sampleStart = performance.now();
  }, 100);
}
