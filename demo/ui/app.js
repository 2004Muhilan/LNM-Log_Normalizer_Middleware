// ULPF demo UI. Read-only: polls the files the demo scripts write under /state/ and renders them.
// No framework, no network beyond localhost, no opinion — if a file is missing the screen says so.
(() => {
  const $ = (id) => document.getElementById(id);
  const screens = { review: "s-review", tamper: "s-tamper", flow: "s-flow", discover: "s-discover", live: "s-live" };
  const stepScreen = { 1: "discover", 2: "review", 3: "review", 4: "review", 5: "flow", 6: "tamper" };
  let active = "review";
  let follow = true;
  let lastStatus = null;

  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const fmtS = (x) => (x == null ? "" : `${Number(x).toFixed(1)}s`);
  async function getJSON(path) { try { const r = await fetch(`/state/${path}?t=${Date.now()}`); if (!r.ok) return null; return await r.json(); } catch { return null; } }
  async function getText(path) { try { const r = await fetch(`/state/${path}?t=${Date.now()}`); if (!r.ok) return null; return await r.text(); } catch { return null; } }
  function show(name) { active = name; for (const [k, id] of Object.entries(screens)) $(id).classList.toggle("active", k === name); renderSteps(lastStatus); if (typeof tick === "function") tick(); }

  // ---------------------------------------------------------------- header: steps and timings
  function renderSteps(st) {
    const el = $("steps");
    if (!st) { el.innerHTML = '<span class="st">no state yet — run demo/reset.sh</span>'; return; }
    const titles = { 1: "Discovery", 2: "Onboard live", 3: "Unresolved", 4: "Propagation", 5: "Mixed stream", 6: "Tamper" };
    el.innerHTML = [1, 2, 3, 4, 5, 6].map((n) => {
      const s = (st.steps || {})[n] || {};
      const cls = ["st", s.state || "", stepScreen[n] === active ? "active" : ""].join(" ");
      const t = s.state === "done" ? `<span class="t">${fmtS(s.seconds)}</span>` : s.state === "running" ? '<span class="t blink">running…</span>' : "";
      return `<span class="${cls}" data-screen="${stepScreen[n]}">${n} ${titles[n]}${t}</span>`;
    }).join("");
    for (const e of el.querySelectorAll(".st[data-screen]")) e.onclick = () => { follow = false; show(e.dataset.screen); };
  }

  // ---------------------------------------------------------------- screen 1: certificate review
  function certCard(c, resolvedTo) {
    const status = c.resolution ? "resolved" : c.status;
    const cands = (c.ranked_candidates || []).map((r) => {
      const win = c.resolution && c.resolution.resolved_to === r.attribute;
      return `<div class="cand ${win ? "winner" : ""}"><span class="rank">${r.rank}.</span><span class="attr">${esc(r.attribute)}</span><span class="tag ${r.proposed_by === "model" ? "model" : r.proposed_by === "enumeration" ? "enum" : "config"}">${esc(r.proposed_by)}</span></div>`;
    }).join("");
    const ev = c.evidence || {};
    const disc = ev.discriminator ? `${ev.discriminator.status}${ev.discriminator.discriminator_id ? " (" + ev.discriminator.discriminator_id + ")" : ""}` : "";
    const enumN = c.enumeration ? `${(c.enumeration.candidates || []).length} candidates, ${(c.enumeration.survivors || []).length} survivors` : "";
    const res = c.resolution ? `<div class="ok" style="margin-top:8px;font-size:1.1rem">→ <b>${esc(c.resolution.resolved_to)}</b> <span class="tag config">${esc(c.resolution.provenance)}</span> via ${esc(c.resolution.discriminator_id)}</div>` : "";
    const unres = c.unresolved_reason && !c.resolution ? `<div class="warn" style="margin-top:8px">UNRESOLVED: ${esc(c.unresolved_reason)} — no guess is made</div>` : "";
    return `<div class="panel cert ${status}">
      <div style="display:flex;justify-content:space-between;align-items:baseline"><span class="path">${esc(c.field.path)} <span class="dim" style="font-size:.9rem">slot ${c.context.slot_index + 1} · ${esc(c.context.token_class)}</span></span><span class="tag ${status}">${esc(status)}</span></div>
      <div class="dim mono" style="font-size:.9rem;margin:4px 0 8px">${(c.field.sample_values || []).slice(0, 3).map(esc).join(" · ")}</div>
      ${cands}
      <div class="dim" style="font-size:.85rem;margin-top:6px">evidence: type ${esc(ev.type_validity)} · structural ${esc(ev.structural && ev.structural.status)} · held-out ${esc(ev.held_out_consistency)} · discriminator ${esc(disc)}<br>enumeration: ${esc(enumN)}</div>
      ${unres}${res}</div>`;
  }
  function slotRows(session) {
    const plan = session && session.plan;
    if (!plan || !plan.slots) return "";
    return plan.slots.map((s) => {
      const part = (s.parts || [])[0] || {};
      const m = (part.mappings || [])[0] || {};
      const prov = m.provenance || {};
      const cat = prov.category || (s.proposed_by === "model" ? "model_proposal" : s.proposed_by || "");
      const tag = cat === "model_proposal" ? "model" : cat === "vendor_schema_or_device_configuration" ? "config" : "enum";
      return `<tr><td class="num">${s.index + 1}</td><td class="mono">${esc(part.field || "")}</td><td>${esc(m.attribute || "—")}</td><td><span class="tag ${tag}">${esc(cat || "—")}</span></td><td class="dim" style="font-size:.85rem">${esc(prov.discriminator_id || s.proposed_by || "")}</td></tr>`;
    }).join("");
  }
  async function renderReview() {
    const before = await getJSON("step2/session-before.json");
    const after = await getJSON("step2/session-after.json");
    const result = await getJSON("step2/result.json");
    const st = lastStatus && lastStatus.steps ? lastStatus.steps["2"] : null;
    const el = $("review");
    if (!before) {
      el.innerHTML = st && st.state === "running"
        ? `<div class="panel"><div class="big warn">onboarding… the model is labelling the slots</div><div class="dim">six unseen Squid lines → structure induced → ${esc((st.title || "").replace("Live onboarding ", ""))} → certificates</div></div>`
        : '<div class="empty">step 2 has not run</div>';
      return;
    }
    const src = after || before;
    const certs = Object.values(src.certificates || {});
    const req = before.pending_request || {};
    const metrics = (result && result.metrics) || (after && after.metrics) || before.metrics || {};
    const prov = before.proposal_provenance || {};
    const head = `<div class="panel"><div class="kpi">
      <div class="k"><div class="lab">source</div><div class="big">${esc(before.source_id)}</div></div>
      <div class="k"><div class="lab">samples · slots</div><div class="big">${before.sample_count} · ${before.structure ? before.structure.arity : "?"}</div></div>
      <div class="k"><div class="lab">proposal by</div><div class="big" style="font-size:1.5rem">${esc(prov.provider || "?")}${prov.model_id ? "<br><span class='dim' style='font-size:1rem'>" + esc(prov.model_id) + "</span>" : ""}</div></div>
      <div class="k"><div class="lab">certificates</div><div class="big">${certs.length}</div></div>
      <div class="k"><div class="lab">evidence requests · operator responses</div><div class="big">${metrics.evidence_requests ?? "?"} · ${metrics.operator_responses ?? "?"}</div></div>
      <div class="k"><div class="lab">state</div><div class="big ${src.state === "promoted" || (after && after.verdict && after.verdict.promotable) ? "ok" : "warn"}" style="font-size:1.5rem">${esc((after && after.verdict && after.verdict.promotable) ? "promotable" : src.state)}</div></div>
    </div></div>`;
    const reqHtml = req.text ? `<div class="panel request"><h3>The one request</h3><div style="font-size:1.15rem">${esc(req.text)}</div><div class="dim" style="margin-top:6px">discriminator <b>${esc(req.discriminator_id)}</b> · resolves ${(req.resolves || []).length} fields · ${(req.alternatives || []).length} alternatives ranked below it</div></div>` : "";
    const ansHtml = after ? `<div class="panel answer"><h3>The operator's answer (device configuration)</h3><div class="mono">${esc(result ? result.logformat : "")}</div>${result && result.verify ? `<div class="ok" style="margin-top:8px">${esc(result.verify)}</div>` : ""}</div>` : `<div class="panel dim">waiting for the operator's answer…</div>`;
    const beforeRows = slotRows(before), afterRows = after ? slotRows(after) : "";
    el.innerHTML = head + `<div class="grid2"><div>${reqHtml}${certs.map((c) => certCard(c)).join("")}</div><div>${ansHtml}
      <div class="panel"><h3>Field provenance — before the answer</h3><table><tr><th class="num">#</th><th>field</th><th>OCSF attribute</th><th>provenance</th><th></th></tr>${beforeRows}</table></div>
      ${after ? `<div class="panel"><h3>Field provenance — after the answer</h3><table><tr><th class="num">#</th><th>field</th><th>OCSF attribute</th><th>provenance</th><th></th></tr>${afterRows}</table></div>` : ""}
      ${result ? `<div class="panel dim" style="font-size:.9rem">pack <b>${esc(result.pack_id)}</b> signed by ${esc(result.signed_by)} · model_hash ${esc(String(result.model_hash).slice(0, 26))}… · proposal ${fmtS(result.proposal_seconds)}</div>` : ""}
    </div></div>`;
    const u3 = await getJSON("step3/unresolved.json");
    if (u3) {
      const live = (u3.live || []).map((u) => `<tr><td class="mono">${esc(u.field)}</td><td><span class="tag model">${esc(u.proposed)}</span></td><td class="dim" style="font-size:.85rem">${esc(u.reason)}</td><td>${u.after ? `<b class="ok">${esc(u.after.attribute || "unmapped")}</b> <span class="tag config">${esc(u.after.provenance || "")}</span>` : "—"}</td></tr>`).join("");
      const fx = (u3.fixture || []).map((c) => `<div class="cert unresolved panel" style="margin-top:10px"><span class="path">${esc(c.field.path)}</span> <span class="tag unresolved">unresolved</span><div>${(c.ranked_candidates || []).map((r) => `<span class="cand"><span class="rank">${r.rank}.</span><span class="attr">${esc(r.attribute)}</span></span>`).join(" ")}</div><div class="warn">${esc(c.unresolved_reason)} — no guess is made</div><div class="dim" style="font-size:.85rem">P3 fixture path: two candidates the library cannot separate</div></div>`).join("");
      el.innerHTML += `<div class="panel" style="border-left:6px solid var(--bad)"><h3>No guess, two forms — pos_2 is Squid's duration column</h3><table><tr><th>field</th><th>model's lone label</th><th>why it is not accepted</th><th>after the answer</th></tr>${live}</table>${fx}</div>`;
    }
    const p4 = await getJSON("step4/result.json");
    if (p4) el.innerHTML += `<div class="panel" style="border-left:6px solid var(--acc)"><h3>Propagation — the 11-slot family from the same source</h3><div class="kpi"><div class="k"><div class="lab">slots resolved without a request</div><div class="big">${(p4.propagated_slots || []).length}</div></div><div class="k"><div class="lab">evidence requests</div><div class="big">${p4.evidence_requests}</div></div><div class="k"><div class="lab">operator responses</div><div class="big ok">${p4.operator_responses}</div></div><div class="k"><div class="lab">promoted</div><div class="big ${p4.promoted ? "ok" : "bad"}">${p4.promoted ? "yes" : "no"}</div></div><div class="k"><div class="lab">still pending (retained certificate)</div><div class="big" style="font-size:1.4rem">${esc((p4.pending_request_resolves || []).join(", ") || "none")}</div></div></div></div>`;
  }

  // ---------------------------------------------------------------- screen 2: tamper
  function hexView(hex, text, flipIdx, cls) {
    const bytes = hex.match(/../g) || [];
    return `<div class="hex mono">${bytes.map((b, i) => i === flipIdx ? `<span class="${cls}">${b}</span>` : b).join(" ")}</div><div class="hex mono dim">${Array.from(text).map((ch, i) => { const c = ch.charCodeAt(0); const s = c < 32 || c > 126 ? "·" : esc(ch); return i === flipIdx ? `<span class="${cls}">${s}</span>` : s; }).join("")}</div>`;
  }
  async function renderTamper() {
    const r = await getJSON("step6/result.json");
    const el = $("tamper");
    const st = lastStatus && lastStatus.steps ? lastStatus.steps["6"] : null;
    if (!r) { el.innerHTML = st && st.state === "running" ? '<div class="panel"><div class="big warn">committing, exporting, tampering…</div></div>' : '<div class="empty">step 6 has not run</div>'; return; }
    const t = r.tamper; const flip = t.offset - t.window_start;
    const okB = /VERIFY: OK/.test(r.verify_before), okA = /VERIFY: OK/.test(r.verify_after);
    el.innerHTML = `<div class="grid2">
      <div class="panel"><h3>Sealed segment ${esc(t.file)} — before</h3>${hexView(t.before_hex, t.before_text, flip, "flip0")}<div class="verdict ${okB ? "ok" : "bad"}">${okB ? "VERIFY: OK" : "VERIFY: FAIL"} <span class="dim" style="font-size:1rem">— every segment root recomputed, chain and signatures checked</span></div></div>
      <div class="panel"><h3>After one byte flipped at offset ${t.offset}: 0x${t.original_byte.toString(16).padStart(2, "0")} → 0x${t.tampered_byte.toString(16).padStart(2, "0")}</h3>${hexView(t.after_hex, t.after_text, flip, "flip")}<div class="verdict ${okA ? "bad" : "ok"}">VERIFY: FAIL <span class="dim" style="font-size:1rem">— the verifier names the leaf:</span></div><div class="big bad" style="font-size:1.3rem">${esc(r.tampered_leaf || "")}</div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h3>The witness — a container with only ulpf-verify and the public key, no network</h3><pre class="out">${esc(r.witness_event)}</pre><h3>…and the silence gap record, exported and verified the same way</h3><pre class="out">${esc(r.witness_gap)}</pre></div>
      <div class="panel"><h3>Checkpoint ${esc(r.checkpoint_id)} <span class="tag enum">${esc(r.commit_mode)}</span></h3><pre class="out">${esc(r.verify_after)}</pre><h3>Gap records after the tamper</h3><pre class="out">${esc(r.gaps_after)}</pre></div>
    </div>`;
  }

  // ---------------------------------------------------------------- screen 3: live flow
  async function renderFlow() {
    const el = $("flow");
    const st = lastStatus && lastStatus.steps ? lastStatus.steps["5"] : null;
    const out = await getText("step5/out.jsonl");
    const q = await getText("step5/q.jsonl");
    const prog = await getJSON("step5/progress.json");
    const stats = await getJSON("step5/stats.json");
    const gaps = await getText("step5/gaps.json");
    if (out == null && !st) { el.innerHTML = '<div class="empty">step 5 has not run</div>'; return; }
    const fam = {}; let emitted = 0;
    for (const line of (out || "").split("\n")) { if (!line) continue; emitted++; try { const l = JSON.parse(line)._lineage; const k = `${l.parser_id} / ${l.family_id}`; fam[k] = (fam[k] || 0) + 1; } catch {} }
    const reasons = {}; let quarantined = 0;
    for (const line of (q || "").split("\n")) { if (!line) continue; quarantined++; try { const r = JSON.parse(line); reasons[r.stage] = (reasons[r.stage] || 0) + 1; } catch {} }
    const gapRecs = (gaps || "").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    const total = prog ? prog.total : 0, sent = prog ? prog.sent_a + prog.sent_b : 0;
    const maxF = Math.max(1, ...Object.values(fam));
    el.innerHTML = `<div class="panel"><div class="kpi">
      <div class="k"><div class="lab">frames sent</div><div class="big">${sent}${total ? `<span class="dim" style="font-size:1.2rem"> / ${total}</span>` : ""}</div></div>
      <div class="k"><div class="lab">emitted (OCSF)</div><div class="big ok">${emitted}</div></div>
      <div class="k"><div class="lab">quarantined</div><div class="big warn">${quarantined}</div></div>
      <div class="k"><div class="lab">drift signals</div><div class="big warn">${stats ? stats.drift_signals : reasons.routing_drift || 0}</div></div>
      <div class="k"><div class="lab">ML tuples</div><div class="big">${stats ? stats.ml_records : emitted}</div></div>
      <div class="k"><div class="lab">gap records</div><div class="big ${gapRecs.length ? "bad" : ""}">${gapRecs.length}</div></div>
      <div class="k"><div class="lab">peers</div><div class="big">${stats ? stats.peers : (gapRecs.length ? "2" : "…")}</div></div>
    </div></div>
    <div class="grid2">
      <div class="panel"><h3>Routed per family (the DAG: envelope → surface → anchors → arity; no parser tried)</h3>${Object.entries(fam).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="family"><span class="mono">${esc(k)}</span><span>${v}</span></div><div class="barwrap"><div class="bar" style="width:${(100 * v / maxF).toFixed(0)}%"></div></div>`).join("") || '<div class="dim">waiting for events…</div>'}</div>
      <div><div class="panel"><h3>Quarantine (bytes retained, never dropped)</h3>${Object.entries(reasons).map(([k, v]) => `<div class="family"><span>${esc(k)}</span><span>${v}</span></div>`).join("") || '<div class="dim">none yet</div>'}${stats ? `<div class="dim" style="margin-top:8px">candidate-set sizes after L4: ${esc(JSON.stringify(stats.candidate_set_sizes))}</div>` : ""}</div>
      <div class="panel"><h3>Gap records — absence as evidence</h3>${gapRecs.map((g) => `<div class="family"><span><b class="${g.record.kind === "silence" ? "bad" : "ok"}">${esc(g.record.kind)}</b> peer ${esc(g.record.peer)}${g.record.silence_ms ? ` · ${g.record.silence_ms} ms` : ""}</span><span class="dim">leaf ${g.leaf_index} of ${esc(g.segment_id)} · ${g.committed ? "committed" : "uncommitted"}</span></div>`).join("") || '<div class="dim">peer B will fall silent…</div>'}</div></div>
    </div>`;
  }

  // ---------------------------------------------------------------- screen 4: discovery
  async function renderDiscover() {
    const d = await getJSON("step1/discovery.json");
    const el = $("discover");
    if (!d) { el.innerHTML = '<div class="empty">step 1 has not run</div>'; return; }
    const rows = d.map((f) => `<tr><td class="num">${f.rank}</td><td class="num">${f.count}</td><td class="num">${(100 * f.share).toFixed(1)}%</td><td><div class="barwrap" style="width:180px"><div class="bar" style="width:${(100 * f.share / d[0].share).toFixed(0)}%"></div></div></td><td>${esc(f.l1)}</td><td>${esc(f.l2)}</td><td class="mono">${esc((f.anchors || []).join(" ") || "—")}${Object.keys(f.drift || {}).length ? ` <span class="tag unresolved">drift</span>` : ""}</td><td class="mono dim" style="font-size:.85rem">${esc(String(f.sample).slice(0, 70))}</td></tr>`).join("");
    el.innerHTML = `<div class="panel"><table><tr><th class="num">#</th><th class="num">events</th><th class="num">share</th><th></th><th>envelope</th><th>surface</th><th>anchor · arity</th><th>sample</th></tr>${rows}</table><div class="dim" style="margin-top:8px">clustered by the router's own surface — no parser, no pack; the order is the order to onboard in</div></div>`;
  }


  // ---------------------------------------------------------------- screen 5: the live pipeline (generator -> ULPF -> consumer)
  let assertKey = "";
  async function postAssert(body) { try { await fetch("/live/assert", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); } catch (e) { console.error(e); } }
  async function renderLive() {
    const [st, gen, gen2, w, con, pend, gapsTxt, alert] = await Promise.all([getJSON("live/status.json"), getJSON("live/generator.json"), getJSON("live/generator-http.json"), getJSON("live/watch.json"),
      getJSON("live/consumer.json"), getJSON("live/pending.json"), getText("live/gaps.json"), getJSON("live/autoheal/alert-latest.json")]);
    const top = $("live-top"), asr = $("live-assert");
    if (!st) { top.innerHTML = '<div class="empty">the live sequence has not run — bash demo/live/run-live.sh</div>'; asr.innerHTML = ""; assertKey = ""; return; }
    const phases = Object.entries(st.phases || {}).map(([k, p]) => `<span class="st ${p.state || ""}" title="${esc(p.title || "")}">${esc(k)} ${esc((p.title || "").split(/[:—(]/)[0].trim().slice(0, 30))}${p.state === "done" ? `<span class="t">${fmtS(p.seconds)}</span>` : p.state === "running" ? '<span class="t blink">running…</span>' : ""}</span>`).join("");
    const cur = (st.phases || {})[st.current] || {};
    const ps = w && w.parse_success != null ? Math.round(100 * w.parse_success) : null;
    const fired = w && w.fired;
    const topSig = w && w.signals && ((w.signals[w.dominant_signal] || [])[0]);
    const events = ((w && w.events) || []).slice(-3).map((e) => `<div class="${e.state === "fired" ? "bad" : "ok"}" style="font-size:.9rem">${esc(e.message)}</div>`).join("");
    const gaps = (gapsTxt || "").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    const gapRows = gaps.slice(-6).map((g) => `<div class="family"><span><b class="${g.record.kind === "egress_stalled" ? "bad" : g.record.kind.startsWith("pack_") ? "warn" : "ok"}">${esc(g.record.kind)}</b> <span class="dim" style="font-size:.85rem">${esc(String(g.record.detail || "").slice(0, 120))}</span></span><span class="dim">leaf ${g.leaf_index} · ${esc(g.segment_id)}</span></div>`).join("");
    const conDown = !con || (Date.now() / 1000 - con.at > 3);
    const lag = w && con ? Math.max(0, w.usable_total - con.rows) : 0;
    const genBox = (g, name, how) => g ? `<div class="family"><span><b>${name}</b> <span class="dim" style="font-size:.85rem">${how}</span></span><span>${g.format === 2 ? '<span class="tag unresolved">firmware 2.0</span> ' : ""}${g.sent} sent${g.backlog ? ` · <span class="warn">${g.backlog} queued</span>` : ""}</span></div>` : "";
    const box = (title, sub, body, cls) => `<div class="panel" style="flex:1;min-width:0;${cls || ""}"><h3>${title}</h3><div class="dim" style="font-size:.85rem;margin-bottom:6px">${sub}</div>${body}</div>`;
    const arrow = (a, b) => `<div style="align-self:center;text-align:center;padding:0 6px;min-width:120px"><div style="font-size:2rem;line-height:1">⇉</div><div class="dim" style="font-size:.8rem">${a}<br>${b}</div></div>`;
    const ing = ((st.runtime || {}).ingress || []), eg = ((st.runtime || {}).egress || []);
    top.innerHTML = `<div class="panel"><nav class="steps">${phases}</nav><div style="margin-top:6px;font-size:1.05rem">${esc(cur.title || "")}${cur.note ? ` — <span class="dim">${esc(cur.note)}</span>` : ""}</div></div>
      <div style="display:flex;gap:0;align-items:stretch">
        ${box("Generator apps (flowgen ×2)", "outside the pipeline · each knows a host and a port", `${genBox(gen, "flowtap sensor A", "syslog / TCP, RFC 6587")}${genBox(gen2, "flowtap sensor B", "HTTP POST")}<div class="mono dim" style="font-size:.78rem;margin-top:6px;word-break:break-all">${esc((gen || {}).last_line || "")}</div>` || '<div class="dim">not started</div>')}
        ${arrow("ingress connectors", ing.map(esc).join(" · ") || "—")}
        ${box("ULPF runtime — one process, no restarts", `packs: ${esc(((st.runtime || {}).packs || []).join(" · ") || "—")}`, w ? `<div class="kpi"><div class="k"><div class="lab">evidence records</div><div class="big">${w.frames_total}</div></div><div class="k"><div class="lab">usable</div><div class="big ok">${w.usable_total}</div></div><div class="k"><div class="lab">quarantined (bytes kept)</div><div class="big warn">${w.quarantined_total}</div></div><div class="k"><div class="lab">parse success · last ${w.window}</div><div class="big ${fired ? "bad" : "ok"}">${ps == null ? "…" : ps + "%"}</div></div></div><div class="barwrap" style="margin-top:6px"><div class="bar" style="width:${ps || 0}%;${fired ? "background:var(--bad)" : ""}"></div></div>${fired ? `<div class="bad" style="margin-top:6px"><b>DRIFT MONITOR FIRED</b> — ${esc(w.dominant_signal)}${topSig ? `: <span class="mono" style="font-size:.78rem">${esc(topSig.key)}</span> (${topSig.events})` : ""}</div>` : ""}` : '<div class="dim">not started</div>', fired ? "border-left:6px solid var(--bad)" : "")}
        ${arrow("egress connectors", eg.map(esc).join(" · ") || "—")}
        ${box(`sink — consumer app ${conDown ? '<span class="tag unresolved">DOWN</span>' : '<span class="tag resolved">up</span>'}`, `outside the pipeline · SQLite · its own page: <a href="http://127.0.0.1:8790/" target="_blank" style="color:var(--acc)">127.0.0.1:8790</a>`, con ? `<div class="kpi"><div class="k"><div class="lab">rows in SQLite</div><div class="big ${conDown ? "bad" : "ok"}">${con.rows}</div></div><div class="k"><div class="lab">ULPF is ahead by</div><div class="big ${lag > 12 ? "warn" : ""}">${lag}</div></div></div><div class="dim" style="font-size:.8rem;margin-top:4px">${Object.entries(con.by_family || {}).map(([k, v]) => `${esc(k)}: ${v}`).join(" · ")} · duplicates ignored ${con.duplicates_ignored}</div>${(con.latest || []).slice(0, 3).map((r) => `<div class="mono dim" style="font-size:.75rem">${esc(r.src)} → ${esc(r.dst)} · action ${esc(r.action_id)} · t=${esc(r.time)}</div>`).join("")}` : '<div class="dim">not started</div>', conDown ? "border-left:6px solid var(--bad)" : "")}
      </div>
      <div class="grid2"><div class="panel"><h3>Drift monitor (detection; healing policy below)</h3>${events || '<div class="dim">watching…</div>'}</div>
      <div class="panel"><h3>Evidence-log records that are not events — outages and pack changes are leaves too</h3>${gapRows || '<div class="dim">none yet</div>'}</div></div>
      ${alert ? `<div class="panel" style="border-left:6px solid var(--warn)"><h3>ALERT — ${esc(alert.alert)} · ${esc(alert.policy_version)} · ${esc(alert.at)}</h3><div style="font-size:1.1rem">${esc(alert.outcome)}</div>
        <div class="grid2" style="margin-top:6px"><div><div class="lab dim">promoted automatically — on evidence that already existed</div>${(alert.auto_promoted || []).map((m) => `<span class="tag config" style="margin:2px">${esc(m.field)} → ${esc(m.attribute)}</span>`).join(" ")}<div class="dim" style="font-size:.85rem;margin-top:4px">source binding: ${esc(JSON.stringify((alert.source_binding || {}).drifted_from))} ⊆ known · pack ${esc((alert.pack || {}).pack_id)} v${esc((alert.pack || {}).pack_version)} <span class="mono">${esc(String((alert.pack || {}).sha256 || "").slice(0, 23))}…</span></div></div>
        <div><div class="lab dim">withheld — nobody has evidence; the operator is asked, nothing is guessed</div>${(alert.withheld || []).map((x) => `<div><span class="tag ambiguous">${esc(x.field)}</span> <span class="dim" style="font-size:.9rem">${esc(x.why_withheld)}</span></div>`).join("") || '<span class="ok">nothing</span>'}<div class="mono dim" style="font-size:.75rem;margin-top:4px">rollback: ${esc(((alert.rollback || {}).command || "").replace(/\/home\/[^ ]*\/live\//g, "…/live/"))}</div></div></div></div>` : ""}`;
    // the operator's panel: rebuilt only when its content changes, so an open dropdown survives the polling
    const sess = pend && pend.session ? await getJSON(`live/${pend.session}/session.json`) : null;
    const key = JSON.stringify([pend, sess && Object.values(sess.certificates || {}).map((c) => [c.certificate_id, c.status])]);
    if (key === assertKey) return;
    assertKey = key;
    if (pend && pend.decision_needed) {
      const d = pend.decision_needed;
      asr.innerHTML = `<div class="panel request" style="border-left:6px solid var(--warn)"><h3>Tier 1 — the one decision only a human can make</h3><div style="font-size:1.15rem">${esc(d.question)}</div>
        <div class="mono dim" style="margin:6px 0">${esc(d.signature)} · ${d.events}+ lines quarantined</div><button id="live-onboard" style="font-size:1.1rem">onboard this source (recorded as operator op-014)</button>
        <div class="dim" style="font-size:.85rem;margin-top:6px">nothing is learned from traffic that merely arrived; after this decision onboarding runs by itself, and stops only where a field is ambiguous</div></div>`;
      $("live-onboard").onclick = () => postAssert({ onboard: true });
      return;
    }
    if (!pend || !sess) { asr.innerHTML = ""; return; }
    const certs = Object.values(sess.certificates || {});
    const leafs = ["time", "start_time", "end_time", "src_endpoint.ip", "dst_endpoint.ip", "src_endpoint.port", "dst_endpoint.port", "action_id", "connection_info.protocol_name", "traffic.bytes_in", "traffic.bytes_out", "traffic.bytes", "traffic.packets", "src_endpoint.zone", "dst_endpoint.zone"];
    const rows = (pend.fields || []).map((f) => {
      const cert = (pend.open_certificates || []).find((c) => c.field === f.field);
      const prov = (f.provenance || [])[0] || "";
      const opts = [...new Set([...(cert ? cert.candidates : []), ...(f.mapped || []), ...leafs])];
      const ctl = pend.interactive && !pend.done && prov !== "operator_assertion" ? `<select data-field="${esc(f.field)}"><option value="">choose…</option>${opts.map((o) => `<option>${esc(o)}</option>`).join("")}</select> <button data-assert="${esc(f.field)}">assert</button>` : "";
      return `<tr><td class="mono">${esc(f.field)}</td><td class="mono dim" style="font-size:.85rem">${(f.samples || []).map(esc).join(" · ")}</td><td>${esc((f.mapped || [])[0] || "—")}</td><td><span class="tag ${prov === "operator_assertion" ? "config" : prov === "model_proposal" ? "model" : "enum"}">${esc(prov || "—")}</span></td><td>${cert ? `<span class="tag ambiguous">${esc(cert.class || cert.status)}</span>` : ""}</td><td>${ctl}</td></tr>`;
    }).join("");
    const blockers = (pend.blockers || []).map((b) => `<div class="warn">${esc(b)}</div>`).join("") || '<div class="ok">nothing mandatory is blocked</div>';
    asr.innerHTML = `<div class="grid2"><div><div class="panel request"><h3>Operator assertion — ${esc(pend.session)} (no vendor document exists for this source)</h3>${blockers}
        <table style="margin-top:8px"><tr><th>field</th><th>samples</th><th>mapped to</th><th>provenance</th><th>certificate</th><th></th></tr>${rows}</table>
        ${pend.interactive && !pend.done ? `<button id="live-promote" style="margin-top:10px;font-size:1.05rem">promote (fill the rest from the operator's notes)</button>` : ""}
        <div class="dim" style="font-size:.85rem;margin-top:6px">each assertion is recorded per field with the operator's id, provenance <b>operator_assertion</b>, inside the signed pack — weaker than a vendor document, and labelled so</div></div></div>
      <div>${certs.map((c) => certCard(c)).join("")}</div></div>`;
    for (const b of asr.querySelectorAll("button[data-assert]")) b.onclick = () => { const sel = asr.querySelector(`select[data-field="${b.dataset.assert}"]`); if (sel && sel.value) postAssert({ field: b.dataset.assert, attribute: sel.value }); };
    const pb = $("live-promote"); if (pb) pb.onclick = () => postAssert({ promote: true });
  }

  // ---------------------------------------------------------------- loop
  async function tick() {
    const st = await getJSON("status.json");
    lastStatus = st;
    const lv = await getJSON("live/status.json");
    const liveRunning = lv && lv.updated && (!st || !st.updated || lv.updated > st.updated) && Object.values(lv.phases || {}).some((p) => p.state === "running");
    if (follow && liveRunning) { if (active !== "live") show("live"); }
    else if (follow && st && st.current && stepScreen[st.current] && stepScreen[st.current] !== active && active !== "live") show(stepScreen[st.current]);
    renderSteps(st);
    try {
      if (active === "review") await renderReview();
      else if (active === "tamper") await renderTamper();
      else if (active === "flow") await renderFlow();
      else if (active === "live") await renderLive();
      else await renderDiscover();
    } catch (e) { console.error(e); }
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "1") { follow = false; show("review"); }
    if (e.key === "2") { follow = false; show("tamper"); }
    if (e.key === "3") { follow = false; show("flow"); }
    if (e.key === "4") { follow = false; show("discover"); }
    if (e.key === "5") { follow = false; show("live"); }
    if (e.key === "f" || e.key === "F") { follow = !follow; $("foot").textContent = (follow ? "following the running step · " : "manual · ") + "keys: 1 review · 2 tamper · 3 flow · 4 discovery · 5 live pipeline · F follow"; }
  });
  show("review");
  tick();
  setInterval(tick, 700);
})();
