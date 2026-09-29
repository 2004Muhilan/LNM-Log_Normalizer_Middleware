"""The lake writer (adapters/lake): Parquet whose schema comes from the pinned OCSF tables, never inferred; each event
exactly once through redelivery, partial overlap and a crash between staging and commit; write-then-rename; the
lineage columns that keep traceability; Security Lake's layout convention."""
import json
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "adapters" / "lake"))
import lakewriter  # noqa: E402

PINNED = ROOT / "ocsf" / "pinned"
DAY_MS = 1790467200000   # 2026-09-27T00:00:00Z


def event(i, **extra):
    e = {"class_uid": 4001, "category_uid": 4, "type_uid": 400101, "activity_id": 1, "time": DAY_MS + i * 1000, "action_id": 1 + (i % 2),
         "src_endpoint": {"ip": f"10.4.1.{i % 250}", "port": 40000 + i}, "dst_endpoint": {"ip": "203.0.113.9", "port": 443},
         "_lineage": {"event_id": f"ev_{i:05d}", "raw_hash": f"sha256:{i:064x}", "segment_id": "seg_00003", "offset": 100 * i, "length": 99,
                      "source_id": "flowtap-01", "parser_id": "flowtap-01-json-9", "parser_version": "1.0", "family_id": "json-9", "ingest_time": DAY_MS + i}}
    e.update(extra)
    return e


def body(events):
    return b"".join(json.dumps(e, separators=(",", ":")).encode() + b"\n" for e in events)


def post(lake, events, spool, start):
    b = body(events)
    return lake.ingest(b, spool, start, start + len(b)), start + len(b)


def files(root):
    return sorted(p for p in Path(root).rglob("*.parquet"))


def mk(tmp_path, **kw):
    return lakewriter.Lake(tmp_path / "lake", PINNED, kw.get("rotate_bytes", 1 << 30), kw.get("rotate_seconds", 3600), "local", "000000000000")


def test_two_batches_that_inference_would_type_differently_get_one_identical_schema(tmp_path):
    lake = mk(tmp_path)
    # batch A: no traffic object, `unmapped` holds a number; batch B: traffic counters, `unmapped` holds text
    _, end = post(lake, [event(i, unmapped={"zone": 7}) for i in range(3)], "spoolA", 0)
    assert lake.flush(force=True) == 3
    post(lake, [event(i, traffic={"bytes_in": 123, "bytes_out": 45}, unmapped={"zone": "dmz"}) for i in range(3, 6)], "spoolA", end)
    assert lake.flush(force=True) == 3
    fs = files(tmp_path / "lake")
    assert len(fs) == 2
    con = duckdb.connect()
    schemas = [con.execute(f"DESCRIBE SELECT * FROM read_parquet('{f}')").fetchall() for f in fs]
    assert schemas[0] == schemas[1], "every file of a class has the identical schema"
    cols = dict((r[0], r[1]) for r in schemas[0])
    assert cols["time"] == "BIGINT" and cols["traffic"].startswith("STRUCT(") and cols["unmapped"] == "JSON" and cols["src_endpoint"].startswith("STRUCT(")
    assert [r[0] for r in schemas[0][:6]] == ["event_id", "raw_hash", "segment_id", "offset", "length", "source_id"]
    # inference, for contrast: the two batches as DuckDB would guess them do NOT agree
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    a.write_bytes(body([event(0, unmapped={"zone": 7})])); b.write_bytes(body([event(1, traffic={"bytes_in": 1}, unmapped={"zone": "dmz"})]))
    assert con.execute(f"DESCRIBE SELECT * FROM read_json_auto('{a}')").fetchall() != con.execute(f"DESCRIBE SELECT * FROM read_json_auto('{b}')").fetchall()


def test_layout_lineage_and_values(tmp_path):
    lake = mk(tmp_path)
    post(lake, [event(i) for i in range(4)], "0123456789abcdef", 0)
    lake.flush(force=True)
    (f,) = files(tmp_path / "lake")
    rel = f.relative_to(tmp_path / "lake").parts
    assert rel[:5] == ("ext", "ulpf_network_activity", "region=local", "accountId=000000000000", "eventDay=20260927")
    assert f.name.startswith("part-0123456789ab-") and not list(f.parent.glob(".*.tmp"))
    rows = duckdb.connect().execute(f"SELECT event_id, raw_hash, segment_id, \"offset\", src_endpoint.ip, action_id, json_extract_string(lineage, '$.family_id') FROM read_parquet('{f}') ORDER BY event_id").fetchall()
    assert rows[1] == ("ev_00001", f"sha256:{1:064x}", "seg_00003", 100, "10.4.1.1", 2, "json-9")


def test_each_event_exactly_once_through_redelivery_overlap_and_a_crash(tmp_path):
    lake = mk(tmp_path)
    evs = [event(i) for i in range(10)]
    n, mid = post(lake, evs[:6], "S", 0)
    assert n == 6
    assert post(lake, evs[:6], "S", 0)[0] == 0                        # the same batch again (the ack was lost)
    whole = body(evs)
    assert lake.ingest(whole, "S", 0, len(whole)) == 4                 # a retry cut differently: only the new part
    # crash between staging and the state commit: a staged tail the state does not name is cut on restart
    with open(lake.staging, "ab") as f:
        f.write(b"S 99999 {\"class_uid\":4001}\n")
    lake2 = mk(tmp_path)
    assert lake2.st["staged_rows"] == 10 and lake2.staging.stat().st_size == lake2.st["staging_bytes"]
    assert lake2.flush(force=True) == 10
    # crash after the rename, before staging was emptied: the flush is repeated and replaces the same files
    lake2.ingest(body([event(10)]), "S", len(whole), len(whole) + len(body([event(10)])))
    state = json.loads(lake2.state_path.read_text())
    lake2.flush(force=True)
    lake2.staging.write_bytes(b"S " + str(len(whole)).encode() + b" " + body([event(10)]))
    lake2.state_path.write_text(json.dumps({**state}))
    lake3 = mk(tmp_path)
    lake3.flush(force=True)
    got = duckdb.connect().execute(f"SELECT event_id, count(*) FROM read_parquet('{tmp_path}/lake/ext/*/*/*/*/*.parquet') GROUP BY 1 ORDER BY 1").fetchall()
    assert [r[0] for r in got] == [f"ev_{i:05d}" for i in range(11)] and all(r[1] == 1 for r in got)


def test_a_new_spool_starts_its_own_high_water_mark_and_a_class_without_a_pinned_table_is_kept_whole(tmp_path):
    lake = mk(tmp_path)
    post(lake, [event(0)], "old", 0)
    assert post(lake, [event(1)], "new", 0)[0] == 1
    post(lake, [{"class_uid": 6003, "time": DAY_MS, "api": {"operation": "x"}, "_lineage": {"event_id": "ev_api", "raw_hash": "sha256:0"}}], "new", 10_000)
    assert lake.flush(force=True) == 3, lake.stats["last_error"]
    names = {f.parts[-5] for f in files(tmp_path / "lake")}
    assert names == {"ulpf_network_activity", "ulpf_class_6003"}
    (f,) = [f for f in files(tmp_path / "lake") if "6003" in str(f)]
    assert duckdb.connect().execute(f"SELECT event_id, json_extract_string(event, '$.api.operation') FROM read_parquet('{f}')").fetchall() == [("ev_api", "x")]


def test_the_http_face_refuses_a_batch_without_its_spool_range(tmp_path):
    import http.client
    import threading
    lake = mk(tmp_path)
    srv = lakewriter.http.server.ThreadingHTTPServer(("127.0.0.1", 0), lakewriter.handler(lake))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
        c.request("POST", "/ingest", body=body([event(0)]))
        r = c.getresponse(); r.read()
        assert r.status == 400
        b = body([event(0)])
        c.request("POST", "/ingest", body=b, headers={"X-ULPF-Spool-Id": "S", "X-ULPF-Spool-Start": "0", "X-ULPF-Spool-End": str(len(b))})
        r = c.getresponse(); r.read()
        assert r.status == 204 and lake.status()["staged_rows"] == 1
    finally:
        srv.shutdown()


@pytest.mark.parametrize("uid", [4001, 4002, 3002, 2004])
def test_every_pinned_class_has_a_schema_duckdb_accepts(uid, tmp_path):
    cols = lakewriter.schema.read_columns(str(PINNED), uid)
    (tmp_path / "e.jsonl").write_text("")
    duckdb.connect().execute(f"SELECT * FROM read_json('{tmp_path / "e.jsonl"}', format='newline_delimited', columns={cols}) LIMIT 0")


def test_a_row_whose_time_is_text_is_refused_with_its_reason_and_the_rest_are_written(tmp_path):
    """Found live (2026-09-30): an event whose `time` stayed text crashed the rotation, and with it every later write of
    that writer. Now the row is refused into rejected.jsonl with its reason and everything else is written."""
    lake = mk(tmp_path)
    bad = event(2, time="2026-09-29T17:01:40.291297+0000")
    post(lake, [event(0), event(1), bad, event(3)], "spoolA", 0)
    assert lake.flush(force=True) == 3
    rej = [json.loads(l) for l in (tmp_path / "lake" / "_writer" / "rejected.jsonl").read_text().splitlines()]
    assert len(rej) == 1 and rej[0]["event_id"] == "ev_00002" and "not epoch milliseconds" in rej[0]["reason"]
    assert lake.status()["rows_rejected"] == 1 and lake.status()["staged_rows"] == 0
    con = duckdb.connect()
    assert con.execute(f"SELECT count(*) FROM read_parquet({[str(f) for f in files(tmp_path / 'lake')]!r})").fetchone()[0] == 3
