// Replay layer over the unchanged demo UI: a persistent REPLAY badge with the real measured time of the
// step being replayed, presenter keys, and a terminal-output panel. Talks only to /replay/* on localhost.
(() => {
  const badge = document.createElement("div");
  badge.id = "replay-badge";
  badge.style.cssText = "position:fixed;right:16px;bottom:14px;z-index:50;background:#2a1d0c;border:2px solid #ffc857;color:#ffc857;border-radius:8px;padding:8px 14px;font:600 .9rem 'Segoe UI',system-ui,sans-serif;max-width:46vw;line-height:1.35";
  document.body.appendChild(badge);
  const term = document.createElement("pre");
  term.id = "replay-terminal";
  term.style.cssText = "display:none;position:fixed;left:16px;right:16px;bottom:70px;max-height:55vh;overflow:auto;z-index:49;background:#0a0e12;border:1px solid #26313d;border-radius:8px;padding:12px 16px;color:#e8eef5;font:.95rem Consolas,'DejaVu Sans Mono',monospace;white-space:pre-wrap";
  document.body.appendChild(term);
  let st = null, termStep = null;
  const call = async (p) => { try { const r = await fetch(`/replay/${p}?t=${Date.now()}`); return await r.json(); } catch { return null; } };
  const fmt = (x) => (x == null ? "—" : `${Number(x).toFixed(1)} s`);
  async function refresh() {
    st = await call("status");
    if (!st) { badge.innerHTML = "REPLAY · server not reachable"; return; }
    const cur = st.current;
    const s = cur ? st.steps[cur] : null;
    let line;
    if (!cur) line = `before step 1 — press <b>1</b> to start`;
    else if (s && s.state === "running") line = `step ${cur} ${st.replay_paused ? "PAUSED" : "playing"} · live: <b>${fmt(st.real_seconds)}</b> on a GTX 1650, replayed compressed to ${fmt(st.replay_window_s)} (${Math.round((st.replay_progress || 0) * 100)} %)`;
    else line = `step ${cur} shown · live it took <b>${fmt(s && s.seconds)}</b>`;
    badge.innerHTML = `<span style="letter-spacing:.12em">● REPLAY</span> of a recorded run (${st.run_id}) — ${line}<br><span style="color:#9fb0c2;font-weight:400">1–6 jump · n/→ next · p/← prev · space pause · t terminal · s screens</span>`;
    if (term.style.display !== "none" && cur && termStep !== cur) {
      termStep = cur;
      try { term.textContent = await (await fetch(`/replay/terminal/${cur}?t=${Date.now()}`)).text(); } catch { term.textContent = "(no terminal capture)"; }
    }
  }
  const screens = ["review", "tamper", "flow", "discover"];
  const screenKey = { review: "1", tamper: "2", flow: "3", discover: "4" };
  let screenIdx = 0;
  function cycleScreen() {
    screenIdx = (screenIdx + 1) % screens.length;
    // the UI's own key handler switches screens on 1–4; dispatch that key to it directly
    document.dispatchEvent(new KeyboardEvent("keydown", { key: screenKey[screens[screenIdx]], bubbles: false }));
  }
  window.addEventListener("keydown", (e) => {
    if (e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA")) return;
    const k = e.key;
    let handled = true;
    if (/^[1-6]$/.test(k)) call(`goto/${k}`);
    else if (k === "n" || k === "ArrowRight") call("next");
    else if (k === "p" || k === "ArrowLeft") call("prev");
    else if (k === " ") call("pause");
    else if (k === "t") { term.style.display = term.style.display === "none" ? "block" : "none"; termStep = null; }
    else if (k === "s") cycleScreen();
    else handled = false;
    if (handled) { e.preventDefault(); e.stopImmediatePropagation(); setTimeout(refresh, 50); }
  }, true);
  refresh();
  setInterval(refresh, 500);
})();
