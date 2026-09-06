"""P4 spike — measure the model provider per model, per machine, per case, per mode.

  python learning/tools/spike.py run --models qwen3.5-4b-q4_k_m ... --cases squid-native ... --modes whole per-slot \
         --machine desktop-5060ti --ngl auto [--gpu|--cpu] [--repeat 3] [--server http://...] [--limit-lines 12]
  python learning/tools/spike.py grammar --models qwen3.5-4b-q4_k_m      # does the projected parser-spec grammar compile?
  python learning/tools/spike.py summarize [--results spike/results]      # markdown tables from every result file

Every result file records the machine (CPU, RAM, GPU, VRAM), the backend (GPU offload split parsed from
the server log, or cpu), the model digest, the decoding configuration, and per-slot judgements against
the case's ground truth. A latency figure is meaningful only together with the machine that produced it.
Servers are started per model as Docker containers from the `ulpf-llama` image (one CUDA build for
sm_75 and sm_120) unless --server points at a running llama-server.
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "learning"))
sys.path.insert(0, str(ROOT / "learning" / "tools"))

import models as weights  # noqa: E402
from ulpf_learn.analyze import analyze  # noqa: E402
from ulpf_learn.enumerate_ import enumerate_candidates  # noqa: E402
from ulpf_learn.induce import induce  # noqa: E402
from ulpf_learn.library import Library  # noqa: E402
from ulpf_learn.model import emission  # noqa: E402
from ulpf_learn.model.client import LlamaClient  # noqa: E402
from ulpf_learn.model.provider import ModelProvider  # noqa: E402
from ulpf_learn.model.structure_from_spec import structure_from_spec  # noqa: E402
from ulpf_learn.session import plan_from_proposal  # noqa: E402

CASES = ROOT / "spike" / "cases"
RESULTS = ROOT / "spike" / "results"
CONTAINER = "ulpf-spike-llama"  # per-port suffix added in Server so two spikes (e.g. GPU and CPU) can run side by side


# ---------------------------------------------------------------- machine
def machine_info() -> dict:
    info = {"hostname": socket.gethostname(), "platform": platform.platform(), "cpu": None, "ram_gb": None, "gpu": None, "vram_mb": None, "driver": None}
    try:
        for l in Path("/proc/cpuinfo").read_text().splitlines():
            if l.startswith("model name"):
                info["cpu"] = l.split(":", 1)[1].strip()
                break
        for l in Path("/proc/meminfo").read_text().splitlines():
            if l.startswith("MemTotal"):
                info["ram_gb"] = round(int(l.split()[1]) / 1048576, 1)
                break
    except OSError:
        pass
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=20)
        if out.returncode == 0 and out.stdout.strip():
            name, mem, drv = [x.strip() for x in out.stdout.strip().splitlines()[0].split(",")]
            info.update(gpu=name, vram_mb=int(float(mem)), driver=drv)
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return info


# ---------------------------------------------------------------- server
class Server:
    def __init__(self, model: dict, cache: Path, gpu: bool, ngl: str, port: int = 8080, image: str = "ulpf-llama", ctx: int = 16384,
                 cuda_cache: str | None = None):
        self.model, self.cache, self.gpu, self.ngl, self.port, self.image, self.ctx = model, cache, gpu, ngl, port, image, ctx
        self.cuda_cache = cuda_cache
        self.log = ""
        self.name = f"{CONTAINER}-{port}"

    def start(self) -> "Server":
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        cmd = ["docker", "run", "-d", "--name", self.name, "-p", f"{self.port}:8080", "-v", f"{self.cache}:/models:ro"]
        if self.gpu:
            cmd += ["--gpus", "all"]
            if self.cuda_cache:
                # images that carry PTX (not SASS) for this GPU JIT-compile it on first load; a named volume
                # keeps the driver's compute cache across container starts so that happens once per machine
                cmd += ["-v", f"{self.cuda_cache}:/root/.nv/ComputeCache"]
        # --verbose: the load summary (offloaded N/M layers, buffer sizes, fit projection) is only logged
        # at that level in this build; the log is captured once at readiness, before any generation.
        cmd += [self.image, "-m", f"/models/{self.model['file']}", "--parallel", "1", "--ctx-size", str(self.ctx), "--seed", "0",
                "--n-gpu-layers", (self.ngl if self.gpu else "0"), "--jinja", "--no-warmup", "--verbose"]
        if not self.gpu:
            cmd += ["--device", "none"]
        self.vram_before = vram_used_mib()
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(r.stderr)
        return self

    def wait(self, client: LlamaClient, seconds: float = 1800) -> None:
        t0 = time.time()
        while time.time() - t0 < seconds:
            st = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", self.name], capture_output=True, text=True).stdout.strip()
            if st != "true":
                raise RuntimeError("server container exited:\n" + self.logs()[-3000:])
            try:
                if client._get("/health").get("status") == "ok":
                    self.log = self.logs()
                    self.vram_after = vram_used_mib()
                    return
            except Exception:  # noqa: BLE001
                pass
            time.sleep(2)
        raise RuntimeError("server not ready in time:\n" + self.logs()[-3000:])

    def logs(self) -> str:
        r = subprocess.run(["docker", "logs", self.name], capture_output=True, text=True)
        return r.stdout + r.stderr

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)

    def offload(self) -> dict:
        """What llama.cpp actually did: layers offloaded, device buffer sizes, KV placement."""
        log = self.log or self.logs()
        # LAST match: llama.cpp's -fit probes several splits and logs each; the final line is what runs
        # (found on the laptop: the first probe said 33/33, the server ran 22/33)
        offs = re.findall(r"offloaded (\d+)/(\d+) layers to GPU", log)
        off = re.match(r"(\d+)/(\d+)", f"{offs[-1][0]}/{offs[-1][1]}") if offs else None
        bufs = {m.group(1): float(m.group(2)) for m in re.finditer(r"(\w+) model buffer size\s*=\s*([\d.]+) MiB", log)}
        kv = {m.group(1): float(m.group(2)) for m in re.finditer(r"(\w+) KV buffer size\s*=\s*([\d.]+) MiB", log)}
        dev = re.search(r"using device (\w+) \(([^)]+)\)", log)
        proj = re.search(r"projected to use (\d+) MiB of device memory vs\. (\d+) MiB of free", log)
        vb, va = getattr(self, "vram_before", None), getattr(self, "vram_after", None)
        return {"layers_on_gpu": int(off.group(1)) if off else 0, "layers_total": int(off.group(2)) if off else None,
                "model_buffers_mib": bufs, "kv_buffers_mib": kv, "device": dev.group(2) if dev else ("cpu" if not self.gpu else "unknown"),
                "projected_device_mib": int(proj.group(1)) if proj else None, "free_device_mib_at_start": int(proj.group(2)) if proj else None,
                "vram_used_delta_mib": (va - vb) if (va is not None and vb is not None) else None,
                "fits_in_vram": bool(off) and off.group(1) == off.group(2)}


def vram_used_mib() -> int | None:
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=20)
        return int(float(out.stdout.strip().splitlines()[0])) if out.returncode == 0 and out.stdout.strip() else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


# ---------------------------------------------------------------- cases
def _asa_payloads(lines: list[bytes], ids: set[str]) -> list[bytes]:
    pat = re.compile(rb"(%(?:ASA|FTD|PIX)-(?:[a-z]+-)?\d-(\d{6}).*)$")
    out = []
    for l in lines:
        m = pat.search(l)
        if m and m.group(2).decode() in ids:
            out.append(m.group(1).rstrip(b"\r"))
    return out


def load_case(cid: str, limit: int) -> tuple[dict, object, list[bytes]]:
    case = json.loads((CASES / f"{cid}.json").read_text(encoding="utf-8"))
    src = case["source"]
    if src["kind"] == "golden":
        lines = [l.rstrip(b"\r") for l in (ROOT / src["samples"]).read_bytes().split(b"\n") if l.strip()][:limit]
        return case, induce(lines), lines
    raw: list[bytes] = []
    for rel in src["corpus"]:
        raw += [l.rstrip(b"\r") for l in (ROOT / rel).read_bytes().split(b"\n") if l.strip()]
    kind = src["payload"]
    if kind.startswith("asa:"):
        payloads = _asa_payloads(raw, {kind.split(":", 1)[1]})
    elif kind == "panos":
        payloads = []
        for l in raw:
            m = re.search(rb"\b\d,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},", l)
            if m:
                payloads.append(l[m.start():])
    elif kind == "fortigate":
        payloads = [re.sub(rb"^<\d+>", b"", l) for l in raw]
    else:
        raise ValueError(kind)
    spec = (ROOT / src["spec"]).read_bytes()
    structure, kept = structure_from_spec(spec, payloads[:limit])
    return case, structure, kept


# ---------------------------------------------------------------- judging
def judge(case: dict, structure, prop, lib: Library) -> dict:
    truth = case["truth"]
    uid = case["event_class_uid"]
    by = {s.slot_index: s for s in prop.slots}
    rows, n_truth, n_correct, n_labelled, n_typeok, n_over = [], 0, 0, 0, 0, 0
    out_of_class, in_class_truth = 0, 0
    for s in structure.slots:
        name = s.name or f"pos_{s.index + 1}"
        sp = by.get(s.index)
        rank1 = sp.candidates[0] if sp and sp.candidates else None
        label = rank1 or (sp.note if sp and sp.note in (emission.UNMAPPED, emission.COMPOUND) else ("unmapped" if sp and sp.unmapped_name else None))
        accepted = truth.get(name)
        row = {"slot": s.index + 1, "field": name, "class": s.token_class, "proposal": sp.candidates if sp else [], "label": label, "truth": accepted}
        if rank1:
            n_labelled += 1
            surv = enumerate_candidates(prop.event_class_uid, s.token_class, s.samples).survivors
            row["type_compatible"] = rank1 in surv
            n_typeok += row["type_compatible"]
        if accepted is not None:
            n_truth += 1
            acc = set(a if a is not None else "unmapped" for a in accepted)
            ok = (label in acc) or (label == "compound" and "compound" in acc)
            if label is None and "unmapped" in acc:
                ok = True   # abandoned/unproposed where unmapped is acceptable
            row["correct"] = ok
            n_correct += ok
            if rank1 and acc == {"unmapped"}:
                n_over += 1
            # the anchored rule's residual: truth sits in a library class but rank-1 is not a member of any class holding the truth
            truth_attrs = [a for a in accepted if a not in (None, "compound")]
            truth_classes = {name_ for a in truth_attrs for name_, _ in lib.rivals(a, [a]) if lib.member(a, name_)}
            if truth_classes and prop.event_class_uid == uid:
                in_class_truth += 1
                if rank1 and not any(lib.member(rank1, c) for c in truth_classes):
                    out_of_class += 1
                    row["out_of_class"] = True
        rows.append(row)
    # certificate shape: run the analyzer exactly as the session would
    plan = plan_from_proposal(structure, prop, case["id"])
    an = analyze(plan, lib)
    cert_by_slot = {c["context"]["slot_index"]: c for c in an.certificates}
    shape = {}
    for field_name, cls in case.get("expected_certificates", {}).items():
        idx = next((s.index for s in structure.slots if (s.name or f"pos_{s.index + 1}") == field_name), None)
        c = cert_by_slot.get(idx)
        shape[field_name] = {"expected": cls, "got": (c["evidence"]["discriminator"].get("ambiguity_class") if c and c["status"] == "ambiguous" else (c["status"] if c else None))}
    return {
        "event_class_correct": prop.event_class_uid == uid, "event_class_proposed": prop.event_class_uid,
        "slots": len(structure.slots), "labelled": n_labelled, "type_compatible_rate": (n_typeok / n_labelled) if n_labelled else None,
        "scored": n_truth, "agreement": (n_correct / n_truth) if n_truth else None, "over_mapped": n_over,
        "out_of_class_rate": (out_of_class / in_class_truth) if in_class_truth else None, "in_class_truth_slots": in_class_truth,
        "certificates": len(an.certificates), "certificate_shape": shape,
        "shape_preserved": all(v["got"] == v["expected"] for v in shape.values()) if shape else None,
        "request": bool(an.request), "rows": rows,
    }


# ---------------------------------------------------------------- run
def _run_record(tr) -> dict:
    return {"raw_outputs": tr.raw_outputs, "wall_ms": tr.wall_ms, "prompt_tokens": tr.prompt_tokens, "predicted_tokens": tr.predicted_tokens,
            "iterations": tr.iterations, "calls": tr.calls, "refuted_by_iteration": tr.refuted_by_iteration, "abandoned": tr.abandoned,
            "schema_invalid": tr.schema_invalid, "think_leak": tr.think_leak, "class_answer": tr.class_answer}


def run(a) -> None:
    man = weights.load(ROOT / "models" / "manifest.json")
    cache = Path(a.cache)
    lib = Library()
    mi = machine_info()
    RESULTS.joinpath(a.machine).mkdir(parents=True, exist_ok=True)
    for mid in a.models:
        m = weights.entry(man, mid)
        digest = "sha256:" + weights.verify(cache / m["file"], m)
        client = LlamaClient(a.server or f"http://127.0.0.1:{a.port}")
        srv = None
        if not a.server:
            srv = Server(m, cache, a.gpu, a.ngl, a.port, a.image, a.ctx, a.cuda_cache).start()
            srv.wait(client)
        backend = "cpu" if not a.gpu else f"cuda ngl={a.ngl}"
        off = srv.offload() if srv else {}
        print(f"== {mid} on {a.machine} [{backend}] offload={off.get('layers_on_gpu')}/{off.get('layers_total')} fits={off.get('fits_in_vram')}", flush=True)
        for mode in a.modes:
            for cid in a.cases:
                out = RESULTS / a.machine / f"{mid}__{'cpu' if not a.gpu else 'gpu'}__{cid}__{mode}.json"
                if a.resume and out.exists() and "error" not in json.loads(out.read_text(encoding="utf-8")):
                    print(f"  {cid:18s} {mode:8s} (resume: kept existing result)", flush=True)
                    continue
                case, structure, lines = load_case(cid, a.limit_lines)
                prov = ModelProvider(client, mid, digest, mode=mode, max_iterations=a.max_iterations, backend=backend)
                prov.set_samples(lines)
                runs = []
                try:
                    for rep in range(a.repeat):
                        prop = prov.propose(structure)
                        tr = prov.last_trace
                        runs.append(_run_record(tr))
                except Exception as e:  # noqa: BLE001 — one case must not end the run; the error is the result
                    out.write_text(json.dumps({"machine": a.machine, "machine_info": mi, "model_id": mid, "model_hash": digest, "backend": backend, "offload": off,
                                               "case": cid, "mode": mode, "error": f"{type(e).__name__}: {str(e)[:1500]}"}, indent=1) + "\n", encoding="utf-8")
                    print(f"  {cid:18s} {mode:8s} ERROR {type(e).__name__}: {str(e)[:200]}", flush=True)
                    continue
                first = runs[0]
                j = judge(case, structure, prop, lib)  # judged on the last run; byte-identity below says whether runs differ
                distinct = len({json.dumps(r["raw_outputs"]) for r in runs})
                rec = {
                    "machine": a.machine, "machine_info": mi, "model_id": mid, "model_hash": digest, "backend": backend, "offload": off,
                    "case": cid, "mode": mode, "event_class_uid": case["event_class_uid"], "lines": len(lines), "slots": structure.arity,
                    "wall_ms": [r["wall_ms"] for r in runs], "wall_s_first": round(first["wall_ms"] / 1000, 1),
                    "prompt_tokens": first["prompt_tokens"], "predicted_tokens": first["predicted_tokens"], "iterations": first["iterations"], "calls": first["calls"],
                    "refuted_by_iteration": first["refuted_by_iteration"], "abandoned": first["abandoned"], "schema_invalid": first["schema_invalid"], "think_leak": first["think_leak"],
                    "class_answer": first["class_answer"], "repeat": a.repeat, "byte_identical": distinct == 1, "distinct_outputs": distinct,
                    "provenance": prov.provenance(), "judgement": j, "raw_outputs": first["raw_outputs"],
                    "llama_server_log_tail": (srv.log[-4000:] if srv else ""),
                }
                out.write_text(json.dumps(rec, indent=1, default=str) + "\n", encoding="utf-8")
                print(f"  {cid:18s} {mode:8s} wall={rec['wall_s_first']:7.1f}s it={rec['iterations']} class_ok={j['event_class_correct']} "
                      f"typeok={j['type_compatible_rate']} agree={j['agreement'] and round(j['agreement'], 2)} shape={j['shape_preserved']} "
                      f"ooc={j['out_of_class_rate']} identical={rec['byte_identical']}", flush=True)
        if srv:
            srv.stop()


def grammar(a) -> None:
    """Does llama.cpp compile a grammar from (a) our emission schemas and (b) the projected parser-spec
    contract? Measured against a running server, per model (grammar handling is model-independent but
    the tokenizer is not)."""
    man = weights.load(ROOT / "models" / "manifest.json")
    cache = Path(a.cache)
    schema = json.loads((ROOT / "contracts" / "parser-spec.schema.json").read_text(encoding="utf-8"))
    projected, dropped = emission.project_for_grammar(schema)
    for mid in a.models:
        m = weights.entry(man, mid)
        client = LlamaClient(a.server or f"http://127.0.0.1:{a.port}")
        srv = None
        if not a.server:
            srv = Server(m, cache, a.gpu, a.ngl, a.port, a.image, a.ctx, a.cuda_cache).start()
            srv.wait(client)
        res = {"model_id": mid, "dropped_keywords": {k: len(v) for k, v in dropped.items()}, "dropped_pointers": dropped}
        for name, sch in (("class", emission.class_schema()), ("proposal-4002-10", emission.proposal_schema(4002, 10)),
                          ("slot-3", emission.slot_schema(["time", "start_time", "end_time"])), ("parser-spec-projected", projected), ("parser-spec-raw", schema)):
            ok, msg = client.grammar_compiles(sch)
            res[name] = {"compiles": ok, "error": msg[:600]}
            print(f"  {mid} {name:24s} compiles={ok} {msg[:160]}", flush=True)
        (RESULTS / a.machine).mkdir(parents=True, exist_ok=True)
        (RESULTS / a.machine / f"grammar__{mid}.json").write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
        if srv:
            srv.stop()


WHOLESPEC_SYSTEM = """You write parser specifications for log lines in a declarative JSON DSL. The DSL's closed op set is: literal, regex, csv, kv, positional, quoted, optional, repeated, decode, coerce. Answer with one JSON document only, exactly following the schema you are given. Positional formats use {"op":"positional","delimiter":{"whitespace_run":true},"leading_delimiter":"reject","trailing_delimiter":"reject","tail":null,"slots":[...]} with one cell per whitespace-separated token: {"field":"<name>","kind":"semantic","class":"<integer|float|ipv4|url|word|text>"}. Regexes are RE2 with (?P<name>...) groups listed in captures. Every byte of the line must be consumed."""


def wholespec(a) -> None:
    """The plan's literal P4 deliverable, measured as an experiment: the model emits a parser spec for
    the sample lines under the projected parser-spec grammar. The output is then validated against the
    FULL contract (the conditionals the grammar could not express), compiled by the reference executor,
    and run over the samples. Reported: grammar compiled?, contract-valid?, compiles?, lines parsed."""
    import jsonschema
    from ulpf_contracts import validate_document
    from ulpf_learn import dslexec
    from ulpf_learn.model import prompt as pr

    man = weights.load(ROOT / "models" / "manifest.json")
    cache = Path(a.cache)
    schema = json.loads((ROOT / "contracts" / "parser-spec.schema.json").read_text(encoding="utf-8"))
    projected, _ = emission.project_for_grammar(schema)
    for mid in a.models:
        m = weights.entry(man, mid)
        digest = "sha256:" + weights.verify(cache / m["file"], m)
        client = LlamaClient(a.server or f"http://127.0.0.1:{a.port}")
        srv = None
        if not a.server:
            srv = Server(m, cache, a.gpu, a.ngl, a.port, a.image, a.ctx, a.cuda_cache).start()
            srv.wait(client)
        for cid in a.cases:
            case, structure, lines = load_case(cid, a.limit_lines)
            user = pr.describe_structure(structure, lines) + f"\n\nWrite the parser spec (schema_version \"1.1.0\", spec_id \"{cid}-model\", regex_dialect \"re2\", bounds max_event_bytes 8192 max_fields 64 max_nesting 4 max_repeat 16) that parses every line above."
            rec = {"machine": a.machine, "model_id": mid, "model_hash": digest, "case": cid, "grammar_compiles": None, "contract_valid": None, "compiles": None, "parsed": None, "lines": len(lines)}
            t0 = time.perf_counter()
            try:
                c = client.chat(WHOLESPEC_SYSTEM, user, projected, max_tokens=3000)
                rec["grammar_compiles"] = True
                rec["wall_s"] = round((time.perf_counter() - t0), 1)
                rec["predicted_tokens"] = c.predicted_tokens
                rec["finish_reason"] = c.finish_reason
                rec["output"] = c.text[:6000]
                try:
                    doc = json.loads(c.text)
                    jsonschema.validate(doc, projected)
                    rec["projected_valid"] = True
                    errs = validate_document("parser-spec", doc)
                    rec["contract_valid"] = errs == []
                    rec["contract_errors"] = errs[:8]
                    try:
                        prog = dslexec.compile_spec(json.dumps(doc).encode())
                        rec["compiles"] = True
                        rec["parsed"] = sum(1 for l in lines if prog.parse(l)["status"] == "ok")
                    except Exception as e:  # noqa: BLE001
                        rec["compiles"] = False
                        rec["compile_error"] = str(e)[:400]
                except (json.JSONDecodeError, jsonschema.ValidationError) as e:
                    rec["projected_valid"] = False
                    rec["error"] = str(e)[:400]
            except Exception as e:  # noqa: BLE001
                rec["grammar_compiles"] = False
                rec["error"] = str(e)[:800]
            print(f"  {mid} {cid}: grammar={rec['grammar_compiles']} contract_valid={rec['contract_valid']} compiles={rec['compiles']} parsed={rec['parsed']}/{len(lines)} wall={rec.get('wall_s')}s", flush=True)
            (RESULTS / a.machine).mkdir(parents=True, exist_ok=True)
            (RESULTS / a.machine / f"wholespec__{mid}__{cid}.json").write_text(json.dumps(rec, indent=1) + "\n", encoding="utf-8")
        if srv:
            srv.stop()


def cases(a) -> None:
    """Dry run without a model: load every case, show the structure the provider would see, and check
    the ground truth — every truth field must be a slot, every truth attribute must exist in the pinned
    class table, every expected-certificate field must be a slot."""
    from ulpf_learn.enumerate_ import load_table
    bad = 0
    for cid in a.cases:
        case, structure, lines = load_case(cid, a.limit_lines)
        leaves = {l["path"] for l in load_table(case["event_class_uid"])["leaf_paths"]}
        names = [s.name or f"pos_{s.index + 1}" for s in structure.slots]
        print(f"== {cid}: {len(lines)} lines, {structure.arity} slots, class {case['event_class_uid']}")
        for s in structure.slots[:80]:
            print(f"   slot {s.index + 1:2d} {(s.name or f'pos_{s.index + 1}'):22s} {s.token_class:8s} distinct={s.distinct:3d} {', '.join(s.samples[:3])[:70]}")
        for f, acc in case["truth"].items():
            for at in acc:
                if at not in (None, "compound") and at not in leaves:
                    print(f"   TRUTH ERROR: {f}: {at} is not in the pinned {case['event_class_uid']} table"); bad += 1
        unscored = [n for n in names if n not in case["truth"]]
        if unscored:
            print(f"   slots without ground truth (unscored): {unscored}")
        for f in case.get("expected_certificates", {}):
            if f not in names:
                print(f"   EXPECTED-CERT ERROR: {f} is not a slot"); bad += 1
    print("ground truth:", "ok" if not bad else f"{bad} problems")


def aggregate(a) -> None:
    """Per (machine, model, backend, mode): means over cases, plus slot-level totals for the anchored
    rule's residual (in-class truth slots vs out-of-class rank-1) and certificate-shape hits."""
    from collections import defaultdict
    acc = defaultdict(lambda: {"n": 0, "agree": [], "wall": [], "iters": [], "shape_hit": 0, "shape_n": 0, "ooc": 0, "inclass": 0, "abandoned": 0, "slots": 0, "class_ok": 0, "labelled": 0, "typeok": 0, "ident": 0, "leak": 0, "over": 0, "scored": 0, "correct": 0})
    for p in sorted(Path(a.results).rglob("*__*.json")):
        if p.name.startswith(("grammar__", "wholespec__")):
            continue
        r = json.loads(p.read_text(encoding="utf-8"))
        if "error" in r:
            continue
        j = r["judgement"]
        k = (r["machine"], r["model_id"], r["backend"].split()[0], r["mode"])
        d = acc[k]
        d["n"] += 1
        d["agree"].append(j["agreement"] or 0.0)
        d["wall"].append(r["wall_s_first"])
        d["iters"].append(r["iterations"])
        for v in j["certificate_shape"].values():
            d["shape_n"] += 1
            d["shape_hit"] += v["got"] == v["expected"]
        d["inclass"] += j["in_class_truth_slots"]
        d["ooc"] += sum(1 for row in j["rows"] if row.get("out_of_class"))
        d["abandoned"] += len(r["abandoned"])
        d["slots"] += j["slots"]
        d["class_ok"] += j["event_class_correct"]
        d["labelled"] += j["labelled"]
        d["typeok"] += sum(1 for row in j["rows"] if row.get("type_compatible"))
        d["ident"] += r["byte_identical"]
        d["leak"] += r["think_leak"]
        d["over"] += j["over_mapped"]
        d["scored"] += j["scored"]
        d["correct"] += sum(1 for row in j["rows"] if row.get("correct"))
    print("| machine | model | backend | mode | cases | class ok | agreement (slot-weighted) | mean agreement | type-compat (labelled) | over-mapped | cert shape hits | out-of-class / in-class-truth | abandoned slots | mean iters | mean wall s | byte-identical | think leaks |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for k in sorted(acc):
        d = acc[k]
        print(f"| {k[0]} | {k[1]} | {k[2]} | {k[3]} | {d['n']} | {d['class_ok']}/{d['n']} | {d['correct']}/{d['scored']} = {d['correct'] / max(1, d['scored']):.2f} | "
              f"{sum(d['agree']) / d['n']:.2f} | {d['typeok']}/{d['labelled']} | {d['over']} | {d['shape_hit']}/{d['shape_n']} | {d['ooc']}/{d['inclass']} = {d['ooc'] / max(1, d['inclass']):.2f} | "
              f"{d['abandoned']} | {sum(d['iters']) / d['n']:.1f} | {sum(d['wall']) / d['n']:.0f} | {d['ident']}/{d['n']} | {d['leak']} |")


def slots_matrix(a) -> None:
    """For one case: per slot, what each model labelled (rank-1 or flag) in one mode — where the models agree and where they all miss."""
    rows = {}
    models = []
    for p in sorted(Path(a.results).rglob(f"*__{a.backend}__{a.case}__{a.mode}.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        if "error" in r:
            continue
        models.append(r["model_id"])
        for row in r["judgement"]["rows"]:
            rows.setdefault(row["field"], {"truth": row["truth"], "class": row["class"]})[r["model_id"]] = ("✓ " if row.get("correct") else ("· " if row.get("correct") is None else "✗ ")) + str(row["label"])
    print("| field | class | truth | " + " | ".join(m.replace("qwen3.5-", "q").replace("granite-4.1-", "gr").replace("gemma-4-", "ge") for m in models) + " |")
    print("|---|---|---|" + "---|" * len(models))
    for f, d in rows.items():
        truth = "|".join("null" if t is None else t for t in (d["truth"] or [])) or "(unscored)"
        print(f"| {f} | {d['class']} | {truth} | " + " | ".join(d.get(m, "-") for m in models) + " |")


def summarize(a) -> None:
    rows = []
    for p in sorted(Path(a.results).rglob("*__*.json")):
        if p.name.startswith(("grammar__", "wholespec__")):
            continue
        r = json.loads(p.read_text(encoding="utf-8"))
        j = r["judgement"]
        off = r.get("offload", {})
        rows.append((r["machine"], r["model_id"], r["backend"], f"{off.get('layers_on_gpu')}/{off.get('layers_total')}" if off.get("layers_total") else "-",
                     r["case"], r["mode"], r["wall_s_first"], r["iterations"], j["event_class_correct"],
                     None if j["type_compatible_rate"] is None else round(j["type_compatible_rate"], 2), None if j["agreement"] is None else round(j["agreement"], 2),
                     j["shape_preserved"], None if j["out_of_class_rate"] is None else round(j["out_of_class_rate"], 2), r["byte_identical"], r["think_leak"]))
    print("| machine | model | backend | offload | case | mode | wall s | iters | class ok | type-compat | agreement | cert shape | out-of-class | byte-identical | think leak |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        print("| " + " | ".join("" if v is None else str(v) for v in r) + " |")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("run", "grammar", "wholespec"):
        p = sub.add_parser(name)
        p.add_argument("--models", nargs="+", required=True)
        p.add_argument("--cases", nargs="+", default=[c.stem for c in sorted(CASES.glob("*.json"))])
        p.add_argument("--modes", nargs="+", default=["whole", "per-slot"], choices=["whole", "per-slot"])
        p.add_argument("--machine", required=True, help="label for the results directory, e.g. desktop-5060ti or laptop-1650")
        p.add_argument("--gpu", dest="gpu", action="store_true", default=True)
        p.add_argument("--cpu", dest="gpu", action="store_false")
        p.add_argument("--ngl", default="auto", help="--n-gpu-layers for llama-server: a number, 'auto' or 'all'")
        p.add_argument("--repeat", type=int, default=1)
        p.add_argument("--max-iterations", type=int, default=3)
        p.add_argument("--limit-lines", type=int, default=12)
        p.add_argument("--server", help="use a running llama-server instead of starting a container")
        p.add_argument("--port", type=int, default=8080)
        p.add_argument("--image", default="ulpf-llama")
        p.add_argument("--cache", default=str(ROOT / "models" / "cache"))
        p.add_argument("--ctx", type=int, default=16384, help="llama-server context size (KV cache grows with it; lower on a 4 GB card if needed)")
        p.add_argument("--cuda-cache", default=None, help="named Docker volume mounted at /root/.nv/ComputeCache so a PTX-only image JITs once per machine")
        p.add_argument("--resume", action="store_true", help="skip configurations whose result file already exists without an error")
    s = sub.add_parser("summarize")
    s.add_argument("--results", default=str(RESULTS))
    c = sub.add_parser("cases")
    c.add_argument("--cases", nargs="+", default=[c.stem for c in sorted(CASES.glob("*.json"))])
    c.add_argument("--limit-lines", type=int, default=12)
    g = sub.add_parser("aggregate")
    g.add_argument("--results", default=str(RESULTS))
    m = sub.add_parser("slots")
    m.add_argument("--results", default=str(RESULTS))
    m.add_argument("--case", required=True)
    m.add_argument("--mode", default="whole")
    m.add_argument("--backend", default="gpu")
    a = ap.parse_args(argv)
    {"run": run, "grammar": grammar, "wholespec": wholespec, "summarize": summarize, "cases": cases, "aggregate": aggregate, "slots": slots_matrix}[a.cmd](a)


if __name__ == "__main__":
    main()
