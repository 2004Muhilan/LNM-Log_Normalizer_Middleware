// The live sequence's main screen. Presentation only: it polls the files demo/live/run-live.sh writes under /state/live/ and
// shows (1) whether the generators and the consumer are up, (2) the phase list, (3) ONLY what the running phase needs.
// The two write paths are the ones that already existed: the Tier 1 "onboard" decision and the operator's dropdown choices,
// both POSTed to /live/assert, which appends a line to a queue file the script reads. No phase is driven from here.
(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const get = async (p, text) => { try { const r = await fetch(`/state/live/${p}?t=${Date.now()}`); if (!r.ok) return null; return text ? await r.text() : await r.json(); } catch { return null; } };
  const post = (body) => fetch("/live/assert", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).catch(() => {});
  const LABEL = { A: "New source: quarantine, wait for a human", B: "Onboarding: certificates, answers", C: "Flowing: two connectors in, two out", D: "Consumer dies and comes back",
                  E: "Drift: heals itself, with an alert", F: "The two columns it would not guess", G: "Backfill from the evidence log", H: "Accounting", I: "Whitespace drift: nothing heals it" };
  const LEAVES = ["time", "src_endpoint.ip", "dst_endpoint.ip", "src_endpoint.port", "dst_endpoint.port", "action_id", "connection_info.protocol_name", "connection_info.protocol_num",
                  "traffic.bytes_out", "traffic.bytes_in", "src_endpoint.zone", "dst_endpoint.zone", "start_time", "end_time"];
  let detailKey = "";

  const kv = (pairs) => `<div class="kv">${pairs.map(([lab, val, red, id]) => `<div><div class="lab">${lab}</div><div class="big ${red ? "red" : ""}" ${id ? `id="${id}"` : ""}>${val}</div></div>`).join("")}</div>`;

  function operatorPanel(pend, sess) {   // certificate cards + one row per column; dropdowns only when the run is interactive
    const certs = Object.values((sess && sess.certificates) || {});
    const cards = certs.map((c) => `<div class="cert ${c.resolution ? "resolved" : ""}"><b class="mono">${esc(c.field.path)}</b> — ${esc((c.evidence.discriminator || {}).ambiguity_class || c.status)}
      <div class="mono muted">${(c.field.sample_values || []).slice(0, 3).map(esc).join("   ")}</div>
      <div>${c.resolution ? `answered: <b>${esc(c.resolution.resolved_to)}</b> (${esc(c.resolution.provenance)})` : "cannot be decided from the bytes: " + (c.ranked_candidates || []).map((r) => `<b>${esc(r.attribute)}</b>`).join(" or ")}</div></div>`).join("");
    const rows = (pend.fields || []).map((f) => {
      const cert = (pend.open_certificates || []).find((c) => c.field === f.field);
      const prov = (f.provenance || [])[0] || "";
      const opts = [...new Set([...(cert ? cert.candidates : []), ...LEAVES])];
      const ctl = pend.interactive && !pend.done && prov !== "operator_assertion" && !/vendor|propagat/.test(prov) ? `<select data-field="${esc(f.field)}"><option value="">choose…</option>${opts.map((o) => `<option>${esc(o)}</option>`).join("")}</select> <button data-assert="${esc(f.field)}">assert</button>` : "";
      const evidenced = prov && prov !== "model_proposal";
      return `<tr><td class="mono">${esc(f.field)}</td><td class="mono muted">${(f.samples || []).slice(0, 2).map(esc).join("  ")}</td><td>${evidenced ? `<b>${esc((f.mapped || [])[0])}</b>` : `<span class="muted">${esc((f.mapped || [])[0] || "—")}</span>`}</td><td>${esc(evidenced ? prov : prov ? "model says (not evidence)" : "nobody has said")}</td><td>${ctl}</td></tr>`;
    }).join("");
    const blocked = (pend.blockers || []).length;
    return `<div class="${blocked ? "red" : ""}" style="font-weight:700;margin-bottom:10px">${blocked ? `${blocked} mandatory field(s) still without evidence — nothing is promoted` : "every mandatory field has evidence"}</div>
      ${cards}<table><tr><th>column</th><th>samples</th><th>means</th><th>on whose word</th><th></th></tr>${rows}</table>
      ${pend.interactive && !pend.done ? `<p><button class="primary" id="promote">promote</button></p>` : ""}`;
  }

  async function detail(st, w, con, phase) {
    const pend = await get("pending.json");
    if (phase === "A") {
      const need = pend && pend.decision_needed;
      return { key: "A" + !!need, live: { "a-q": w ? w.quarantined_total : 0, "a-p": w ? w.usable_total : 0 }, html: `${kv([["lines quarantined — bytes kept", w ? w.quarantined_total : 0, false, "a-q"], ["parsed", w ? w.usable_total : 0, false, "a-p"], ["guessed", 0]])}
        <h2>An unrecognised source is sending. Nothing happens until a human decides.</h2>${need ? `<p><button class="primary" id="onboard">onboard this source</button></p>` : ""}`, keep: !!need };
    }
    if (phase === "B" || phase === "F") {
      if (!pend || !pend.session) return { key: phase + "wait", html: `<h2>${phase === "B" ? "The model is labelling the columns…" : "Waiting for the operator's answers…"}</h2>` };
      const sess = await get(`${pend.session}/session.json`);
      return { key: phase + JSON.stringify([pend, sess && Object.values(sess.certificates || {}).map((c) => c.status)]), html: operatorPanel(pend, sess), keep: true };
    }
    if (phase === "C") return { key: "C" + (con ? con.rows : ""), html: kv([["in: syslog TCP + HTTP POST", w ? w.usable_total : 0], ["out: HTTP POST → database rows", con ? con.rows : 0]]) + `<h2>Parsed, normalized to OCSF, delivered.</h2>` };
    if (phase === "D") {
      const gaps = ((await get("gaps.json", true)) || "").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l).record; } catch { return null; } }).filter((r) => r && r.kind.startsWith("egress_"));
      const ahead = w && con ? Math.max(0, w.usable_total - con.rows) : 0;
      return { key: "D" + ahead + gaps.length, html: kv([["ULPF is ahead of the database by", ahead, ahead > 12], ["ULPF still ingesting", w ? w.usable_total : 0], ["database rows", con ? con.rows : 0]]) +
        gaps.map((g) => `<div class="cert"><b>${g.kind === "egress_stalled" ? "Outage recorded in the evidence log" : "Delivery resumed — recorded in the evidence log"}</b><div class="muted">${esc(String(g.detail || "").slice(0, 150))}</div></div>`).join("") };
    }
    if (phase === "E") {
      const al = await get("autoheal/alert-latest.json");
      const ps = w && w.parse_success != null ? Math.round(100 * w.parse_success) + "%" : "…";
      const head = kv([["parse success, last 40 lines", ps, w && w.fired]]) + (w && w.fired ? `<h2 class="red">DRIFT DETECTED — the format changed</h2>` : "");
      if (!al) return { key: "E" + ps + (w && w.fired), html: head + `<p class="muted">healing runs by itself: no prompt</p>` };
      return { key: "E" + ps + al.at, html: head + `<div class="cert"><h2>ALERT — ${esc(al.outcome)}</h2>
        <p><b>Promoted automatically, on evidence that already existed (${(al.auto_promoted || []).length}):</b><br><span class="mono">${(al.auto_promoted || []).map((m) => esc(m.attribute)).join(", ")}</span></p>
        <p><b>Withheld — no evidence, so no guess; the operator is asked (${(al.withheld || []).length}):</b><br>${(al.withheld || []).map((x) => `<span class="mono">${esc(x.field)}</span>: ${esc(x.why_withheld)}`).join("<br>")}</p>
        <p class="muted">pack ${esc((al.pack || {}).pack_id)} v${esc((al.pack || {}).pack_version)} loaded without a restart · the change is a record in the evidence log · rollback is one command</p></div>` };
    }
    if (phase === "G" || phase === "H") {
      const sm = await get("summary.json");
      return { key: phase + (con ? con.rows : "") + !!sm, html: sm ? kv([["lines generated", sm.generated], ["evidence records", sm.frames], ["database rows", sm.rows]]) + `<h2>${sm.ok ? "Nothing lost. Nothing guessed." : "THE ACCOUNTING DOES NOT BALANCE"}</h2>`
        : kv([["database rows", con ? con.rows : 0]]) + `<h2>Everything quarantined earlier is replayed from the evidence log.</h2>` };
    }
    if (phase === "I") {
      const pw = await get("parse-drop/watch.json");
      const ps = pw && pw.parse_success != null ? Math.round(100 * pw.parse_success) + "%" : "…";
      return { key: "I" + ps, html: kv([["parse success", ps, pw && pw.fired]]) + `<h2>${pw && pw.fired ? "Routed, then refused by the parser. Re-onboarding cannot fix this one: it needs a human." : "One trailing space per line…"}</h2>` };
    }
    return { key: "none", html: "" };
  }

  async function tick() {
    const [st, g1, g2, w, con] = await Promise.all([get("status.json"), get("generator.json"), get("generator-http.json"), get("watch.json"), get("consumer.json")]);
    const now = Date.now() / 1000, phases = (st && st.phases) || {};
    const running = Object.keys(phases).find((k) => phases[k].state === "running");
    const failed = Object.keys(phases).find((k) => phases[k].state === "failed");
    const over = !running && (phases.H || {}).state === "done";
    const gens = [g1, g2].filter(Boolean);
    const genDone = gens.length && gens.every((g) => g.stopped), genUp = gens.length && gens.every((g) => g.stopped || now - g.at < 3);
    const conUp = con && now - con.at < 3;
    const drifted = gens.some((g) => g.format === 2);
    $("gen").className = "status" + (st && !genUp ? " down" : "");
    $("gen").innerHTML = `<div class="name">Generators — syslog TCP + HTTP POST${drifted ? " · firmware 2.0" : ""}</div><div class="state">${!st ? "—" : genDone ? "FINISHED" : genUp ? "UP" : "DOWN"}</div><div>${gens.reduce((n, g) => n + g.sent, 0)} lines sent</div>`;
    $("con").className = "status" + (st && !conUp && !over ? " down" : "");
    $("con").innerHTML = `<div class="name">Consumer — database</div><div class="state">${!st ? "—" : conUp ? "UP" : over ? "STOPPED" : "DOWN"}</div><div>${con ? con.rows : 0} rows</div>`;
    $("phases").innerHTML = !st ? '<div class="pending"><span>not started — bash demo/live/run-live.sh</span></div>' : Object.keys(LABEL).map((k) => {
      const s = (phases[k] || {}).state || "pending";
      return `<div class="${s}"><span>${k}  ${LABEL[k]}</span><span>${s === "pending" ? "" : s}</span></div>`;
    }).join("");
    const d = failed ? { key: "fail" + failed, html: `<h2 class="red">Phase ${failed} failed: ${esc(phases[failed].note || "")}</h2>` } : await detail(st, w, con, running || (over ? "H" : null));
    const live = () => { for (const [id, v] of Object.entries(d.live || {})) { const e = $(id); if (e) e.textContent = v; } };
    if (d.key === detailKey) { live(); return; }   // rebuilt only when its content changes, so a button or an open dropdown survives the polling
    detailKey = d.key;
    $("detail").innerHTML = d.html;
    const ob = $("onboard"); if (ob) ob.onclick = () => { ob.disabled = true; ob.textContent = "decision recorded"; post({ onboard: true }); };
    for (const b of document.querySelectorAll("button[data-assert]")) b.onclick = () => { const sel = document.querySelector(`select[data-field="${b.dataset.assert}"]`); if (sel && sel.value) post({ field: b.dataset.assert, attribute: sel.value }); };
    const pb = $("promote"); if (pb) pb.onclick = () => { pb.disabled = true; post({ promote: true }); };
  }
  tick(); setInterval(tick, 600);
})();
