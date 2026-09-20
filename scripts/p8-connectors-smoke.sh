#!/usr/bin/env bash
# Connectors, end to end through the BUILT BINARY (the Go suites test the packages; this tests the claim):
#   ingress  file | stdin | syslog UDP | syslog TCP (RFC 6587 octet counting) | HTTP POST | directory drop
#   egress   syslog+tcp (RFC 5424 in octet-counted frames) | HTTP POST (NDJSON) | stdout
#   outage   a sink that is not accepting: ingestion completes, exit 3, an `egress_stalled` gap record is a
#            committed evidence leaf the verifier prints, and `ulpf-runtime forward` later delivers every event.
# The same six golden Squid lines go in through every ingress; every ingress must emit the same six events
# (compared by value, lineage aside). Nothing here needs the corpus, Docker or a model.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
RT=runtime/bin/ulpf-runtime; VF=runtime/bin/ulpf-verify; CM=runtime/bin/ulpf-committer
PACK=contracts/golden/squid-native; IN=$PACK/samples/access.log
W=$(mktemp -d); status=0
ok() { echo "  ok    $*"; }; bad() { echo "  FAIL  $*"; status=1; }
content() { python3 - "$1" <<'EOF'
import json, sys, hashlib
evs = []
for l in open(sys.argv[1]):
    e = json.loads(l); e.pop("_lineage"); evs.append(json.dumps(e, sort_keys=True))
print(len(evs), hashlib.sha256("\n".join(sorted(evs)).encode()).hexdigest()[:16])
EOF
}
run() { # name, extra args...   (input by the caller)
  local name=$1; shift
  "$RT" run --pack $PACK --evidence "$W/ev-$name" --out "$W/out-$name.jsonl" --quarantine "$W/q-$name.jsonl" "$@" 2> "$W/err-$name.txt"
}

echo "=== ingress: six lines in through each connector, the same six events out"
run file --input $IN; REF=$(content "$W/out-file.jsonl"); [ "${REF%% *}" = 6 ] && ok "file            $REF" || bad "file: $REF"
cat $IN | run stdin --input -; c=$(content "$W/out-stdin.jsonl"); [ "$c" = "$REF" ] && ok "stdin           $c" || bad "stdin $c != $REF"
run udp --listen udp:127.0.0.1:35514 --max-frames 6 & pid=$!; sleep 0.6
python3 - $IN <<'EOF'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for l in open(sys.argv[1], "rb"):
    s.sendto(b"<134>Dec 19 00:00:00 proxy01 squid[1]: " + l.rstrip(b"\n"), ("127.0.0.1", 35514)); time.sleep(0.02)
EOF
wait $pid; c=$(content "$W/out-udp.jsonl"); [ "$c" = "$REF" ] && ok "syslog UDP      $c (RFC 3164 envelope unwrapped)" || bad "udp $c != $REF"
run tcp --listen tcp:127.0.0.1:36514 --max-frames 6 & pid=$!; sleep 0.6
python3 - $IN <<'EOF'
import socket, sys
s = socket.create_connection(("127.0.0.1", 36514))
for l in open(sys.argv[1], "rb"):
    m = b"<134>1 2024-12-19T00:00:00Z proxy01 squid 1 - - " + l.rstrip(b"\n")
    s.sendall(str(len(m)).encode() + b" " + m)
s.close()
EOF
wait $pid; c=$(content "$W/out-tcp.jsonl"); [ "$c" = "$REF" ] && ok "syslog TCP      $c (RFC 6587 octet counting, RFC 5424 envelope)" || bad "tcp $c != $REF"
run http --listen http:127.0.0.1:38514 --max-frames 6 & pid=$!; sleep 0.6
python3 - $IN <<'EOF'
import sys, urllib.request
r = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:38514/", data=open(sys.argv[1], "rb").read(), method="POST"), timeout=5)
assert r.status in (200, 202, 204), r.status
EOF
wait $pid; c=$(content "$W/out-http.jsonl"); [ "$c" = "$REF" ] && ok "HTTP receive    $c (one POST, six lines)" || bad "http $c != $REF"
mkdir -p "$W/drop"; cp $IN "$W/drop/access-0001.log"
run pull --pull-dir "$W/drop" --pull-once; c=$(content "$W/out-pull.jsonl"); [ "$c" = "$REF" ] && [ -f "$W/drop/access-0001.log.done" ] && ok "directory drop  $c (file renamed .done)" || bad "pull $c != $REF"
echo "  note  there is NO file-tail (follow) ingress: --input reads a file to EOF; a growing file is covered by dropping rotated files into --pull-dir"

echo "=== egress: the emitted events out through each connector, byte for byte"
cat > "$W/recv.py" <<'EOF'
import json, socket, sys, threading, http.server
kind, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
if kind == "syslog":
    ln = socket.create_server(("127.0.0.1", port)); ln.settimeout(30)
    with open(out, "wb") as f:
        while True:
            try: c, _ = ln.accept()
            except OSError: break
            r = c.makefile("rb")
            while True:
                n = b""
                while (ch := r.read(1)) not in (b" ", b""): n += ch
                if not n: break
                m = r.read(int(n)); assert m.startswith(b"<134>1 ") and b"[ulpf@32473 event_id=" in m, m[:80]
                f.write(m[m.index(b"] {") + 2:] + b"\n"); f.flush()
else:
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.headers["Content-Type"] == "application/x-ndjson"
            open(out, "ab").write(self.rfile.read(int(self.headers["Content-Length"]))); self.send_response(202); self.end_headers()
        def log_message(self, *a): pass
    http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
EOF
python3 "$W/recv.py" syslog 37601 "$W/siem.jsonl" & r1=$!; python3 "$W/recv.py" http 37602 "$W/collector.jsonl" & r2=$!; sleep 0.5
run egress --input $IN --forward syslog+tcp://127.0.0.1:37601 --forward http://127.0.0.1:37602/ingest --forward stdout: > "$W/stdout.jsonl"; rc=$?; sleep 0.3
for sink in siem collector stdout; do
  if [ $rc -eq 0 ] && cmp -s "$W/out-egress.jsonl" "$W/$sink.jsonl"; then ok "$(printf '%-10s' $sink) 6 events, byte-identical to what the runtime emitted"; else bad "$sink differs from the emitted events (rc=$rc)"; fi
done
kill $r1 $r2 2>/dev/null; wait $r1 $r2 2>/dev/null
grep -q '"egress_stalled"' "$W/err-egress.txt" && bad "a healthy run recorded a stall" || ok "healthy sinks left no gap record ($(grep -o '"delivered_events":[0-9]*' "$W/err-egress.txt" | tr '\n' ' '))"

echo "=== outage: a SIEM that is not accepting"
run outage --input $IN --forward syslog+tcp://127.0.0.1:37603 --forward-stall-after 300ms --forward-drain 1200ms; rc=$?
c=$(content "$W/out-outage.jsonl")
[ $rc -eq 3 ] && [ "$c" = "$REF" ] && ok "ingestion completed without the sink (six events normalized and spooled); exit 3 says delivery is owed" || bad "rc=$rc content=$c"
ULPF_COMMIT_SEALED=1 "$CM" commit --evidence "$W/ev-outage" --key keys/dev/ulpf-committer-dev.json >/dev/null 2>&1
"$VF" gaps --evidence "$W/ev-outage" --trust keys/trust > "$W/gaps.txt" 2>&1
grep -q "GAP egress_stalled" "$W/gaps.txt" && grep -q "committed" "$W/gaps.txt" && ok "the interruption is a COMMITTED evidence leaf: $(grep -m1 'GAP egress_stalled' "$W/gaps.txt" | cut -c1-150)" || { cat "$W/gaps.txt"; bad "no committed egress_stalled gap record"; }
python3 "$W/recv.py" syslog 37603 "$W/siem-late.jsonl" & r3=$!; sleep 0.5
"$RT" forward --from "$W/out-outage.jsonl" --to syslog+tcp://127.0.0.1:37603 --cursor "$W/out-outage.jsonl.egress-0.cursor" --wait 10s 2> "$W/forward.txt"; rc=$?; sleep 0.3
kill $r3 2>/dev/null; wait $r3 2>/dev/null
[ $rc -eq 0 ] && cmp -s "$W/out-outage.jsonl" "$W/siem-late.jsonl" && ok "the SIEM came back: \`forward\` delivered all six from the persisted cursor, byte-identical, none dropped" || { cat "$W/forward.txt"; bad "late delivery (rc=$rc)"; }
udp=$("$RT" forward --from "$W/out-outage.jsonl" --to syslog+udp://127.0.0.1:514 2>&1); urc=$?
[ $urc -ne 0 ] && echo "$udp" | grep -q "not offered" && ok "syslog over UDP is refused as an egress, with the reason" || bad "UDP egress not refused"

chmod -R u+w "$W" 2>/dev/null; rm -rf "$W"
echo "p8-connectors-smoke: $([ $status = 0 ] && echo PASS || echo FAIL)"
exit $status
