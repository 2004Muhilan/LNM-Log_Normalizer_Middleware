// ulpf-bench — a MEASUREMENT tool, not part of the runtime: the parse throughput of the per-frame pipeline stages
// WITHOUT the evidence store and without egress (laptop branch, 2026-09-27).
//
// It calls the same functions the pipeline calls per frame, in the same order (runtime/internal/pipeline, RunFrames):
// newline framing -> frame.UnwrapChain -> router.RouteChain -> Program.Parse -> normalize.Normalize -> json.Marshal.
// Left out, and why: step 1, the raw evidence write (hash + two fsyncs) — measured separately with the real binary;
// step 3, the per-peer continuity counters (a map update per frame); the output write (serialized, then discarded).
// So this is the CORE cost of turning bytes into validated OCSF, the upper bound of what the stages can do.
//
//	ulpf-bench --pack DIR [--pack DIR ...] --input FILE [--repeat N] [--workers W]
//
// The input is read once into memory and repeated N times (no disk I/O is measured). With W workers, W independent
// pipelines (each its own router and compiled parsers, as W runtime instances would have) process a copy each, in
// parallel: that is the scaling model — the runtime is one stream per process; more cores means more instances.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/normalize"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/route"
)

type packList []string

func (p *packList) String() string     { return fmt.Sprint(*p) }
func (p *packList) Set(v string) error { *p = append(*p, v); return nil }

type result struct {
	Frames, Emitted, Quarantined, OutBytes int64
}

func worker(packs []*pack.Pack, buf []byte) (result, error) {
	var r result
	router := route.New(packs...)
	if err := router.Err(); err != nil {
		return r, err
	}
	now := time.Now().UnixMilli()
	var off int64
	err := frame.Newline{MaxEventBytes: 65536}.Scan(bytes.NewReader(buf), func(fr frame.Frame) error {
		r.Frames++
		rec := evidence.Record{EventID: fmt.Sprintf("ev_bench_%020d", r.Frames), RawHash: "sha256:not-hashed-in-this-measurement", SegmentID: "seg_bench",
			Offset: off, Length: len(fr.Raw), Framing: fr.Framing, IngestTime: now, SourceID: "bench-01", Collector: "col-bench", Channel: "file:bench"}
		off += int64(len(fr.Raw)) + 1
		if fr.Framing.TruncationStatus != "none" {
			r.Quarantined++
			return nil
		}
		ch := frame.UnwrapChain(fr.Raw)
		payload := fr.Raw[ch.PayloadOffset : ch.PayloadOffset+ch.PayloadLength]
		envPtr := ch.Innermost()
		d := router.RouteChain(payload, ch)
		if d.Family == nil {
			r.Quarantined++
			return nil
		}
		m, perr := d.Family.Program.Parse(payload, dsl.Env{SourceLocation: d.Pack.Location, IngestTime: time.UnixMilli(rec.IngestTime)})
		if perr != nil || m.Status != "ok" {
			r.Quarantined++
			return nil
		}
		m.Event.EventID = rec.EventID
		var chainPtr *frame.Chain
		if ch.Depth() > 1 {
			chainPtr = &ch
		}
		ev, _, nerr := normalize.Normalize(m, normalize.Context{Pack: d.Pack, Family: d.Family, Record: rec, Signature: d.Signature, ProcessingTime: time.Now(), Envelope: envPtr, Chain: chainPtr})
		if nerr != nil {
			r.Quarantined++
			return nil
		}
		b, _ := json.Marshal(ev)
		r.OutBytes += int64(len(b)) + 1
		r.Emitted++
		return nil
	})
	return r, err
}

func main() {
	exe, _ := os.Executable()
	root := filepath.Clean(filepath.Join(filepath.Dir(exe), "..", ".."))
	var dirs packList
	flag.Var(&dirs, "pack", "pack directory (repeat)")
	input := flag.String("input", "", "input file, one event per line")
	repeat := flag.Int("repeat", 1, "repeat the input this many times (in memory)")
	workers := flag.Int("workers", 1, "independent pipelines in parallel (one per core, as separate runtime instances would be)")
	contracts := flag.String("contracts", filepath.Join(root, "contracts"), "contracts directory")
	pinned := flag.String("pinned", filepath.Join(root, "ocsf", "pinned", "index.json"), "pinned OCSF index")
	trust := flag.String("trust", filepath.Join(root, "keys", "trust"), "trust store")
	flag.Parse()
	one, err := os.ReadFile(*input)
	if err != nil || len(dirs) == 0 {
		fmt.Fprintln(os.Stderr, "ulpf-bench: --input FILE and at least one --pack are required:", err)
		os.Exit(2)
	}
	if len(one) > 0 && one[len(one)-1] != '\n' {
		one = append(one, '\n')
	}
	buf := bytes.Repeat(one, *repeat)
	runtime.GC()
	var ru0, ru1 syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru0)
	t0 := time.Now()
	res := make([]result, *workers)
	errs := make([]error, *workers)
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			var packs []*pack.Pack
			for _, d := range dirs { // each worker loads its own packs: its own compiled programs and router
				p, err := pack.Load(d, pack.LoadOptions{ContractsDir: *contracts, PinnedIndex: *pinned, TrustDir: *trust})
				if err != nil {
					errs[w] = err
					return
				}
				packs = append(packs, p)
			}
			res[w], errs[w] = worker(packs, buf)
		}(w)
	}
	wg.Wait()
	wall := time.Since(t0).Seconds()
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru1)
	for _, e := range errs {
		if e != nil {
			fmt.Fprintln(os.Stderr, "ulpf-bench:", e)
			os.Exit(1)
		}
	}
	var tot result
	for _, r := range res {
		tot.Frames += r.Frames
		tot.Emitted += r.Emitted
		tot.Quarantined += r.Quarantined
		tot.OutBytes += r.OutBytes
	}
	cpu := float64(ru1.Utime.Sec-ru0.Utime.Sec+ru1.Stime.Sec-ru0.Stime.Sec) + float64(ru1.Utime.Usec-ru0.Utime.Usec+ru1.Stime.Usec-ru0.Stime.Usec)/1e6
	out := map[string]any{"workers": *workers, "input_lines": bytes.Count(one, []byte{'\n'}), "repeat": *repeat, "frames": tot.Frames, "emitted": tot.Emitted, "quarantined": tot.Quarantined,
		"wall_s": wall, "cpu_s": cpu, "events_per_s": float64(tot.Frames) / wall, "events_per_cpu_s": float64(tot.Frames) / cpu,
		"max_rss_mb": float64(ru1.Maxrss) / 1024, "normalized_bytes_per_event": float64(tot.OutBytes) / float64(max(tot.Emitted, 1)), "gomaxprocs": runtime.GOMAXPROCS(0)}
	json.NewEncoder(os.Stdout).Encode(out)
	_ = io.Discard
}
