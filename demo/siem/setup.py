#!/usr/bin/env python3
"""Set up the demo SIEM (idempotent). Standard library only, no network beyond the two local URLs.

  1. index templates: `ulpf-ocsf-*` (one index per OCSF class, written by ULPF's bulk encoding) with IPs as `ip`, times as
     `date` (epoch ms), strings as keyword and the vendor `unmapped` object as `flat_object` (its keys differ per source);
     `ulpf-metrics` (the System console's periodic counts: the quarantine panel).
  2. Security Analytics: the prebuilt OCSF detections cover CloudTrail, Route 53 and VPC Flow only, so a CUSTOM log type
     for our network activity class, two rules (a known-bad address; a deny spike, an aggregation rule) and a detector
     over `ulpf-ocsf-4001` running every minute. Verified against OpenSearch 2.19.2 on 2026-09-27: findings name the
     matching documents by _id, which is ULPF's event_id.
  3. Dashboards (with --osd): index patterns, five panels and one dashboard, "ULPF — normalized events", every panel split
     BY VENDOR (unified visibility, requirement f), and two saved cross-vendor searches (below). The time axis is ULPF's
     RECEIVE time (_lineage.ingest_time): the recorded four-vendor capture keeps its original 2018-2020 event times.

    python3 demo/siem/setup.py --os http://127.0.0.1:9200 [--osd http://127.0.0.1:5601]
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

BAD_IPS = ["203.0.113.66", "203.0.113.99", "198.51.100.23"]
RULES = {
    "ULPF known-bad address": f"""id: 6c3d4e2a-9b1f-4c55-8a2e-2f6d0b7a1c01
title: ULPF known-bad address
description: Network activity to or from an address on the operator's blocklist ({', '.join(BAD_IPS)})
status: experimental
author: ULPF demo
date: 2026/09/27
logsource:
  product: ulpf_ocsf_network
detection:
  sel_src:
    src_endpoint.ip:
{''.join(f'      - {ip}' + chr(10) for ip in BAD_IPS)}  sel_dst:
    dst_endpoint.ip:
{''.join(f'      - {ip}' + chr(10) for ip in BAD_IPS)}  condition: sel_src or sel_dst
level: high
falsepositives:
  - none known
tags:
  - attack.command_and_control
""",
    "ULPF deny spike": """id: 6c3d4e2a-9b1f-4c55-8a2e-2f6d0b7a1c02
title: ULPF deny spike
description: More than 3 denied connections (action_id 2) from one source address within one detector interval (1 minute)
status: experimental
author: ULPF demo
date: 2026/09/27
logsource:
  product: ulpf_ocsf_network
detection:
  sel:
    action_id: 2
  condition: sel | count(*) by src_endpoint.ip > 3
level: medium
falsepositives:
  - a scanner the team runs itself
tags:
  - attack.impact
""",
}
LOGTYPE = "ulpf_ocsf_network"
TEMPLATE = {"index_patterns": ["ulpf-ocsf-*"], "priority": 100, "template": {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {"dynamic_templates": [
        {"ip_fields": {"match": "ip", "mapping": {"type": "ip"}}},
        {"time_fields": {"match_mapping_type": "long", "match_pattern": "regex", "match": "^(time|.*_time)$", "mapping": {"type": "date", "format": "epoch_millis"}}},
        {"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 2048}}}],
        "properties": {
            "time": {"type": "date", "format": "epoch_millis"}, "class_uid": {"type": "integer"}, "action_id": {"type": "integer"},
            "src_endpoint": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}}, "dst_endpoint": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
            "unmapped": {"type": "flat_object"}, "metadata": {"properties": {"product": {"properties": {"vendor_name": {"type": "keyword"}, "name": {"type": "keyword"}}}}},
            "_lineage": {"properties": {"event_id": {"type": "keyword"}, "raw_hash": {"type": "keyword"}, "segment_id": {"type": "keyword"}, "offset": {"type": "long"},
                                         "source_id": {"type": "keyword"}, "parser_id": {"type": "keyword"}, "family_id": {"type": "keyword"},
                                         "event_time": {"type": "date", "format": "epoch_millis"}, "ingest_time": {"type": "date", "format": "epoch_millis"},
                                         "processing_time": {"type": "date", "format": "epoch_millis"}}}}}}}
METRICS = {"index_patterns": ["ulpf-metrics"], "priority": 100, "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
           "mappings": {"properties": {"time": {"type": "date", "format": "epoch_millis"}, "frames": {"type": "long"}, "usable": {"type": "long"}, "quarantined": {"type": "long"}}}}}


def call(base, method, path, body=None, ctype="application/json", headers=None, ok=(200, 201)):
    data = body if isinstance(body, bytes) else body.encode() if isinstance(body, str) else json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": ctype, **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            return e.code, json.loads(b)
        except ValueError:
            return e.code, {"raw": b[:300].decode(errors="replace")}


def must(res, what):
    st, body = res
    if st not in (200, 201):
        sys.exit(f"setup: {what} failed: HTTP {st} {json.dumps(body)[:400]}")
    return body


def opensearch(os_url):
    must(call(os_url, "PUT", "/_index_template/ulpf-ocsf", TEMPLATE), "index template ulpf-ocsf")
    must(call(os_url, "PUT", "/_index_template/ulpf-metrics", METRICS), "index template ulpf-metrics")
    for idx in ("ulpf-ocsf-4001", "ulpf-metrics"):   # the detector's fields must exist before it is created
        st, _ = call(os_url, "HEAD", "/" + idx)
        if st == 404:
            must(call(os_url, "PUT", "/" + idx, {}), "create " + idx)
    st, lt = call(os_url, "POST", "/_plugins/_security_analytics/logtype/_search", {"query": {"match": {"name": LOGTYPE}}})
    if not (st == 200 and lt.get("hits", {}).get("total", {}).get("value")):
        must(call(os_url, "POST", "/_plugins/_security_analytics/logtype", {"name": LOGTYPE, "description": "OCSF 1.3.0 Network Activity (4001) as normalized by ULPF", "source": "Custom", "category": "Network Activity", "tags": {}}), "custom log type")
    st, have = call(os_url, "POST", "/_plugins/_security_analytics/rules/_search?pre_packaged=false", {"query": {"match_all": {}}, "size": 100})
    by_title = {h["_source"]["title"]: h["_id"] for h in (have.get("hits", {}).get("hits", []) if st == 200 else [])}
    ids = []
    for title, body in RULES.items():
        if title not in by_title:
            by_title[title] = must(call(os_url, "POST", f"/_plugins/_security_analytics/rules?category={LOGTYPE}", body), "rule " + title)["_id"]
        ids.append(by_title[title])
    st, dets = call(os_url, "POST", "/_plugins/_security_analytics/detectors/_search", {"query": {"match": {"detector.name": "ulpf-network"}}})
    if not (st == 200 and dets.get("hits", {}).get("total", {}).get("value")):
        must(call(os_url, "POST", "/_plugins/_security_analytics/detectors", {
            "type": "detector", "detector_type": LOGTYPE, "name": "ulpf-network", "enabled": True, "createdBy": "ulpf-demo",
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [{"detector_input": {"description": "ULPF-normalized OCSF network activity", "indices": ["ulpf-ocsf-4001"], "custom_rules": [{"id": i} for i in ids], "pre_packaged_rules": []}}],
            "triggers": [{"name": "ulpf-any", "severity": "1", "types": [LOGTYPE], "ids": [], "sev_levels": ["high", "medium"], "tags": [], "actions": []}]}), "detector")
    print(f"opensearch: templates, custom log type {LOGTYPE}, {len(ids)} rules, detector ulpf-network (every minute)")


def vis(vid, title, vtype, aggs, params, index="ulpf-ocsf", query=""):
    return {"type": "visualization", "id": vid, "attributes": {
        "title": title, "description": "", "version": 1, "uiStateJSON": "{}",
        "visState": json.dumps({"title": title, "type": vtype, "params": params, "aggs": aggs}),
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index}]}


def dashboards(osd_url):
    for _ in range(240):
        st, s = call(osd_url, "GET", "/api/status")
        if st == 200 and s.get("status", {}).get("overall", {}).get("state") == "green":
            break
        time.sleep(1)
    count = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}
    objs = [
        {"type": "index-pattern", "id": "ulpf-ocsf", "attributes": {"title": "ulpf-ocsf-*", "timeFieldName": "_lineage.ingest_time"}},
        {"type": "index-pattern", "id": "ulpf-metrics", "attributes": {"title": "ulpf-metrics", "timeFieldName": "time"}},
        vis("ulpf-by-class", "Events by vendor (inner) and OCSF class (outer) — every source, one schema", "pie", [count,
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "metadata.product.vendor_name", "size": 10, "order": "desc", "orderBy": "1"}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "class_uid", "size": 10, "order": "desc", "orderBy": "1"}}],
            {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}),
        vis("ulpf-denies", "Denied connections by vendor, as received (action_id 2)", "histogram",
            [count, {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {"field": "_lineage.ingest_time", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}},
             {"id": "3", "enabled": True, "type": "terms", "schema": "group", "params": {"field": "metadata.product.vendor_name", "size": 10, "order": "desc", "orderBy": "1"}}],
            {"type": "histogram", "addTooltip": True, "addLegend": False, "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "labels": {"show": True, "truncate": 100}, "title": {}}],
             "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "labels": {"show": True}, "title": {"text": "denied"}}],
             "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "denied", "id": "1"}, "valueAxis": "ValueAxis-1"}], "addLegend": True, "legendPosition": "right"}, query="action_id:2"),
        vis("ulpf-top-src", "Top source addresses, and which device logged them", "table",
            [count, {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "src_endpoint.ip", "size": 10, "order": "desc", "orderBy": "1"}},
             {"id": "3", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "metadata.product.vendor_name", "size": 5, "order": "desc", "orderBy": "1"}}],
            {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False}),
        vis("ulpf-quarantine", "Quarantined by ULPF (bytes kept, not parsed)", "metric",
            [{"id": "1", "enabled": True, "type": "max", "schema": "metric", "params": {"field": "quarantined"}}],
            {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {"colorSchema": "Green to Red", "style": {"fontSize": 48}}}, index="ulpf-metrics"),
    ]
    # requirement (f) made visible: ONE query, ONE set of field names, every device — possible only because every source
    # arrives as the same OCSF class with the same attribute names
    # 10.10.10.10: denied by the FortiGate in the recorded capture AND by the flowtap generator (every 15th line) — one
    # attacker, two devices, one query
    for sid, title, q in (("ulpf-denied-one-source", "Denied connections from 10.10.10.10 — every device that logged it (edit the address)", 'action_id:2 and src_endpoint.ip:"10.10.10.10"'),
                          ("ulpf-denied-internal", "Denied connections from the internal network (10.0.0.0/8) — every device", 'action_id:2 and src_endpoint.ip:"10.0.0.0/8"')):
        objs.append({"type": "search", "id": sid, "attributes": {"title": title, "description": "The same query over every vendor: the field names are OCSF's, not the device's.",
                     "columns": ["metadata.product.vendor_name", "src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port", "action_id", "_lineage.event_id"],
                     "sort": [["_lineage.ingest_time", "desc"]], "version": 1,
                     "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": q, "language": "kuery"}, "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}},
                     "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "ulpf-ocsf"}]})
    panels, refs = [], []
    layout = (("ulpf-by-class", "visualization", 0, 0, 24), ("ulpf-quarantine", "visualization", 24, 0, 24), ("ulpf-denies", "visualization", 0, 15, 24),
              ("ulpf-top-src", "visualization", 24, 15, 24), ("ulpf-denied-internal", "search", 0, 30, 48))
    for i, (vid, typ, x, y, w) in enumerate(layout):
        panels.append({"panelIndex": str(i + 1), "gridData": {"x": x, "y": y, "w": w, "h": 15, "i": str(i + 1)}, "version": "2.19.2", "panelRefName": f"panel_{i}", "embeddableConfig": {}})
        refs.append({"name": f"panel_{i}", "type": typ, "id": vid})
    objs.append({"type": "dashboard", "id": "ulpf-overview", "attributes": {
        "title": "ULPF — normalized events", "description": "OCSF events delivered by ULPF's bulk encoding; quarantine counts from the ULPF console",
        "panelsJSON": json.dumps(panels), "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}), "version": 1,
        "timeRestore": True, "timeFrom": "now-15m", "timeTo": "now", "refreshInterval": {"pause": False, "value": 5000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}}, "references": refs})
    must(call(osd_url, "POST", "/api/saved_objects/_bulk_create?overwrite=true", objs, headers={"osd-xsrf": "true"}), "dashboards saved objects")
    call(osd_url, "POST", "/api/opensearch-dashboards/settings", {"changes": {"defaultIndex": "ulpf-ocsf"}}, headers={"osd-xsrf": "true"})
    # the index pattern needs its field list, or a date histogram on a field that is not the time field cannot be built
    # ("Could not locate that index-pattern-field"): take it from OpenSearch's own mapping of the template's fields
    for pid, pat in (("ulpf-ocsf", "ulpf-ocsf-*"), ("ulpf-metrics", "ulpf-metrics")):
        st, f = call(osd_url, "GET", f"/api/index_patterns/_fields_for_wildcard?pattern={pat}&meta_fields=_source&meta_fields=_id&meta_fields=_index", headers={"osd-xsrf": "true"})
        if st == 200 and f.get("fields"):
            fields = f["fields"]
            if pid == "ulpf-ocsf":   # Dashboards omits every subfield of an underscore-prefixed object (_lineage): add the ones used, typed as the template maps them
                have = {x["name"] for x in fields}
                for name, typ, es in (("_lineage.ingest_time", "date", "date"), ("_lineage.event_time", "date", "date"), ("_lineage.processing_time", "date", "date"),
                                      ("_lineage.event_id", "string", "keyword"), ("_lineage.raw_hash", "string", "keyword"), ("_lineage.segment_id", "string", "keyword"),
                                      ("_lineage.offset", "number", "long"), ("_lineage.source_id", "string", "keyword"), ("_lineage.parser_id", "string", "keyword"),
                                      ("_lineage.family_id", "string", "keyword")):
                    if name not in have:
                        fields.append({"name": name, "type": typ, "esTypes": [es], "searchable": True, "aggregatable": True, "readFromDocValues": True})
            must(call(osd_url, "PUT", f"/api/saved_objects/index-pattern/{pid}", {"attributes": {"fields": json.dumps(fields)}}, headers={"osd-xsrf": "true"}), "index pattern fields " + pid)
    print(f"dashboards: {osd_url}/app/dashboards#/view/ulpf-overview")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--os", required=True)
    ap.add_argument("--osd")
    a = ap.parse_args()
    opensearch(a.os)
    if a.osd:
        dashboards(a.osd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
