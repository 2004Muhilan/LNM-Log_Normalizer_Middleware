// ulpf-runtime: the deterministic runtime engine. No model, no inference, no network egress.
//
//	ulpf-runtime compile  --spec <file>                      print dsl_hash and parser_hash
//	ulpf-runtime verify-pack --pack <dir>                    load a pack (fail closed) and report
//	ulpf-runtime run --pack <dir> --input <file> --evidence <dir> --out <jsonl> [--quarantine <jsonl>]
//	ulpf-runtime run ... --listen udp::5514 | tcp::6514 | http::8514   (P7: syslog UDP/TCP with RFC 6587 octet counting, HTTP receive)
//	ulpf-runtime run ... --pull-dir <dir>                              (P7: directory-drop collector)
//	ulpf-runtime reconstruct --evidence <dir> --out <file>   write the byte-exact original stream
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/pipeline"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "compile":
		fs := flag.NewFlagSet("compile", flag.ExitOnError)
		spec := fs.String("spec", "", "parser spec file")
		fs.Parse(os.Args[2:])
		b, err := os.ReadFile(*spec)
		die(err)
		p, err := dsl.Compile(b)
		die(err)
		json.NewEncoder(os.Stdout).Encode(map[string]any{"spec_id": p.SpecID, "dsl_hash": p.DSLHash, "parser_hash": p.ParserHash(), "compiler": dsl.CompilerVersion, "fields": p.Fields()})
	case "parse":
		// Differential-test surface: span maps (JSONL) for every line of an input under one spec.
		fs := flag.NewFlagSet("parse", flag.ExitOnError)
		specPath := fs.String("spec", "", "parser spec file")
		input := fs.String("input", "", "input file, one event per line")
		fs.Parse(os.Args[2:])
		b, err := os.ReadFile(*specPath)
		die(err)
		p, err := dsl.Compile(b)
		die(err)
		data, err := os.ReadFile(*input)
		die(err)
		enc := json.NewEncoder(os.Stdout)
		for _, line := range splitLines(data) {
			m, err := p.Parse(line, dsl.Env{})
			die(err)
			m.Sort()
			die(enc.Encode(m))
		}
	case "verify-pack":
		fs := flag.NewFlagSet("verify-pack", flag.ExitOnError)
		dir := fs.String("pack", "", "pack directory")
		contractsDir, pinned := commonFlags(fs)
		trust, allowUnsigned := signingFlags(fs)
		fs.Parse(os.Args[2:])
		p, err := pack.Load(*dir, loadOptions(*contractsDir, *pinned, *trust, *allowUnsigned))
		die(err)
		sigState := "signature verified by " + p.Signing.AuthorityID
		if !p.SignatureVerified {
			sigState = "SIGNATURE NOT VERIFIED (--allow-unsigned)"
		}
		fmt.Printf("pack %s v%s: %d families verified (dsl_hash, parser_hash, contract); %s\n", p.PackID, p.PackVersion, len(p.Families), sigState)
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		var dirs packList
		fs.Var(&dirs, "pack", "pack directory (repeat for a mixed stream: every onboarded source)")
		sourceID := fs.String("source-id", "", "evidence-record source id for a mixed stream (defaults to the single pack's source_id)")
		mlPath := fs.String("ml-out", "", "ML feature records JSONL (requirement h): (template_id, parameter_vector, timestamp, entity_ids)")
		input := fs.String("input", "", "input file (use - for stdin)")
		evDir := fs.String("evidence", "", "evidence store directory")
		outPath := fs.String("out", "-", "normalized JSONL output (- for stdout)")
		qPath := fs.String("quarantine", "", "quarantine JSONL output")
		collector := fs.String("collector", "col-01", "collector id")
		channel := fs.String("channel", "", "ingest channel (defaults to file:<input>)")
		failAfter := fs.Int("fail-after-raw-write", 0, "kill-test hook: exit after the Nth raw write")
		listen := fs.String("listen", "", "listener instead of --input: udp::5514, tcp::6514 (RFC 6587 octet counting, newline fallback), http::8514 (POST bodies)")
		maxFrames := fs.Int("max-frames", 0, "with --listen: stop after N frames (0 = until SIGINT)")
		pullDir := fs.String("pull-dir", "", "P7: directory-drop collector; files are ingested in name order and renamed .done")
		pullOnce := fs.Bool("pull-once", false, "with --pull-dir: one pass, then exit")
		maxConns := fs.Int("max-conns", 256, "tcp: connections served at once; more are accepted and closed (invariant 7)")
		idle := fs.Duration("idle-timeout", 30*time.Second, "tcp: close a connection silent for this long; its partial frame is retained")
		maxBody := fs.Int64("max-body-bytes", 8<<20, "http: bytes read per request; the rest is not read, what arrived is framed and flagged")
		maxEvent := fs.Int("max-event-bytes", 65536, "per-frame byte cap; longer frames arrive as truncated/continuation pieces")
		mlStart := fs.String("multiline-start", "", "P7: RE2 pattern that begins an event; other lines join the open event (bounded by --multiline-max-lines)")
		mlLines := fs.Int("multiline-max-lines", 512, "multiline bound (lines)")
		silence := fs.Duration("silence-after", 0, "P7: declare a peer silent after this long without a message and append a gap record (0 = off)")
		noDebatch := fs.Bool("no-debatch", false, "P7: do not explode JSON-array frames into elements")
		fixedClock := fs.Int64("fixed-clock-ms", 0, "deterministic clock for golden outputs (epoch ms)")
		fixedIDs := fs.Bool("deterministic-ids", false, "sequential event ids for golden outputs")
		contractsDir, pinned := commonFlags(fs)
		trust, allowUnsigned := signingFlags(fs)
		fs.Parse(os.Args[2:])
		if len(dirs) == 0 {
			die(fmt.Errorf("at least one --pack is required"))
		}
		var packs []*pack.Pack
		for _, d := range dirs {
			p, err := pack.Load(d, loadOptions(*contractsDir, *pinned, *trust, *allowUnsigned))
			die(err)
			packs = append(packs, p)
		}
		var in io.Reader = os.Stdin
		if *listen == "" && *pullDir == "" && *input != "-" {
			f, err := os.Open(*input)
			die(err)
			defer f.Close()
			in = f
		}
		out := os.Stdout
		if *outPath != "-" {
			f, err := os.Create(*outPath)
			die(err)
			defer f.Close()
			out = f
		}
		var q io.Writer
		if *qPath != "" {
			f, err := os.Create(*qPath)
			die(err)
			defer f.Close()
			q = f
		}
		if *channel == "" {
			*channel = "file:" + *input
		}
		var mlw io.Writer
		if *mlPath != "" {
			f, err := os.Create(*mlPath)
			die(err)
			defer f.Close()
			mlw = f
		}
		o := pipeline.Options{Packs: packs, SourceID: *sourceID, ML: mlw, EvidenceDir: *evDir, Collector: *collector, Channel: *channel, Out: out, Quarantine: q, FailAfterRawWrite: *failAfter,
			MaxEventBytes: *maxEvent, NoDebatch: *noDebatch, SilenceAfter: *silence}
		var multi *frame.Multiline
		if *mlStart != "" {
			re, err := regexp.Compile(*mlStart)
			die(err)
			multi = &frame.Multiline{Start: re, MaxLines: *mlLines}
		}
		if *fixedClock > 0 {
			t := time.UnixMilli(*fixedClock).UTC()
			o.Now = func() time.Time { return t }
		}
		if *fixedIDs {
			n := 0
			o.NewID = func(time.Time) string { n++; return fmt.Sprintf("ev_%026d", n) }
		}
		var st pipeline.Stats
		var err error
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		switch {
		case strings.HasPrefix(*listen, "udp:"):
			// syslog over UDP: one datagram per frame; every received byte is evidence, the envelope is
			// unwrapped after the raw write, the payload is routed and parsed.
			addr := strings.TrimPrefix(*listen, "udp:")
			u := frame.UDP{Addr: addr, MaxEventBytes: *maxEvent, MaxFrames: *maxFrames}
			conn, err := u.Listen()
			die(err)
			if *channel == "file:" {
				o.Channel = "udp:" + addr
			}
			fmt.Fprintf(os.Stderr, "listening for syslog datagrams on %s\n", conn.LocalAddr())
			st, err = pipeline.RunFrames(func(emit func(frame.Frame) error) error { return u.Serve(ctx, conn, emit) }, o)
			die(err)
		case strings.HasPrefix(*listen, "tcp:"):
			// syslog over TCP (P7): RFC 6587 octet counting with non-transparent fallback, bounded per
			// connection; a connection that ends mid-frame leaves a partial frame and a gap record.
			addr := strings.TrimPrefix(*listen, "tcp:")
			t := &frame.TCP{Addr: addr, MaxEventBytes: *maxEvent, MaxConns: *maxConns, IdleTimeout: *idle, MaxFrames: int64(*maxFrames), Multiline: multi}
			ln, err := t.Listen()
			die(err)
			if *channel == "file:" {
				o.Channel = "tcp:" + addr
			}
			fmt.Fprintf(os.Stderr, "listening for syslog over TCP on %s\n", ln.Addr())
			st, err = pipeline.RunFramesWith(func(emit func(frame.Frame) error) error { return t.Serve(ctx, ln, emit) }, o,
				func(p *pipeline.Pipeline) { t.OnClose = p.Lost })
			die(err)
			fmt.Fprintf(os.Stderr, "tcp: accepted=%d refused=%d idle_closed=%d partial_at_close=%d peak_active=%d\n", t.Accepted.Load(), t.Refused.Load(), t.IdleClosed.Load(), t.PartialAtClose.Load(), t.PeakActive.Load())
		case strings.HasPrefix(*listen, "http:"):
			// HTTP receive (P7): POST newline-delimited events or a JSON array; bodies read through a cap.
			addr := strings.TrimPrefix(*listen, "http:")
			h := &frame.HTTP{Addr: addr, MaxBodyBytes: *maxBody, MaxEventBytes: *maxEvent, MaxFrames: int64(*maxFrames)}
			ln, err := h.Listen()
			die(err)
			if *channel == "file:" {
				o.Channel = "http:" + addr
			}
			fmt.Fprintf(os.Stderr, "receiving HTTP POST bodies on %s\n", ln.Addr())
			st, err = pipeline.RunFrames(func(emit func(frame.Frame) error) error { return h.Serve(ctx, ln, emit) }, o)
			die(err)
			fmt.Fprintf(os.Stderr, "http: requests=%d rejected=%d truncated=%d\n", h.Requests.Load(), h.Rejected.Load(), h.Truncated.Load())
		case *listen != "":
			die(fmt.Errorf("--listen must be udp:, tcp: or http:"))
		case *pullDir != "":
			// directory-drop collector (P7): the drop directory is the queue.
			pl := &frame.Pull{Dir: *pullDir, MaxEventBytes: *maxEvent, Once: *pullOnce, Multiline: multi}
			if *channel == "file:" {
				o.Channel = "dir:" + *pullDir
			}
			st, err = pipeline.RunFrames(func(emit func(frame.Frame) error) error { return pl.Serve(ctx, emit) }, o)
			die(err)
			fmt.Fprintf(os.Stderr, "pull: files=%d\n", pl.Files)
		default:
			if multi != nil {
				maxBytes := *maxEvent
				st, err = pipeline.RunFrames(func(emit func(frame.Frame) error) error {
					j := multi.Joiner(emit)
					if err := (frame.Newline{MaxEventBytes: maxBytes}).Scan(in, j.Feed); err != nil {
						return err
					}
					return j.Flush()
				}, o)
				die(err)
				break
			}
			st, err = pipeline.Run(in, o)
			die(err)
		}
		json.NewEncoder(os.Stderr).Encode(st)
	case "export":
		// One-command evidence export: raw bytes + lineage record + inclusion proof + signed checkpoint.
		fs := flag.NewFlagSet("export", flag.ExitOnError)
		evDir := fs.String("evidence", "", "evidence store directory")
		cdir := fs.String("commit", "", "commit directory (default <evidence>/commit)")
		eventID := fs.String("event-id", "", "event id to export")
		outDir := fs.String("out", "", "bundle directory to create")
		fs.Parse(os.Args[2:])
		b, err := checkpoint.Export(*evDir, *cdir, *eventID, *outDir)
		die(err)
		fmt.Fprintf(os.Stderr, "exported %s: leaf %d of %s, root %s, checkpoint %s -> %s\n", b.EventID, b.LeafIndex, b.Record.SegmentID, b.SegmentRoot, b.CheckpointID, *outDir)
	case "reconstruct":
		fs := flag.NewFlagSet("reconstruct", flag.ExitOnError)
		evDir := fs.String("evidence", "", "evidence store directory")
		outPath := fs.String("out", "-", "output file")
		fs.Parse(os.Args[2:])
		stream, recs, err := evidence.Reconstruct(*evDir)
		die(err)
		if *outPath == "-" {
			os.Stdout.Write(stream)
		} else {
			die(os.WriteFile(*outPath, stream, 0o644))
		}
		fmt.Fprintf(os.Stderr, "%d events, %d bytes reconstructed\n", len(recs), len(stream))
	default:
		usage()
	}
}

// packList is a repeatable --pack flag.
type packList []string

func (p *packList) String() string     { return strings.Join(*p, ",") }
func (p *packList) Set(v string) error { *p = append(*p, v); return nil }

// signingFlags: since P5 a pack must carry a valid detached signature by an authority in the trust store.
// --allow-unsigned exists for development only and is loud about it.
func signingFlags(fs *flag.FlagSet) (*string, *bool) {
	trust := fs.String("trust", filepath.Join(repoRoot(), "keys", "trust"), "trust store directory (<authority_id>.pub.json files)")
	allow := fs.Bool("allow-unsigned", false, "DEVELOPMENT ONLY: load packs without verifying their signature")
	return trust, allow
}

func loadOptions(contractsDir, pinned, trust string, allowUnsigned bool) pack.LoadOptions {
	if allowUnsigned {
		fmt.Fprintln(os.Stderr, "WARNING: --allow-unsigned: pack signatures are NOT verified (development only)")
	}
	return pack.LoadOptions{ContractsDir: contractsDir, PinnedIndex: pinned, TrustDir: trust, AllowUnsigned: allowUnsigned}
}

func commonFlags(fs *flag.FlagSet) (*string, *string) {
	root := repoRoot()
	c := fs.String("contracts", filepath.Join(root, "contracts"), "contracts directory")
	p := fs.String("pinned", filepath.Join(root, "ocsf", "pinned", "index.json"), "pinned OCSF index")
	return c, p
}

// repoRoot finds the repository root from the executable's environment: ULPF_ROOT, else cwd walk.
func repoRoot() string {
	if r := os.Getenv("ULPF_ROOT"); r != "" {
		return r
	}
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "contracts", "parser-pack.schema.json")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return "/"
}

// splitLines splits on LF, drops a trailing CR, and skips empty lines.
func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '\n' {
			line := data[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			if len(line) > 0 {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	return out
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ulpf-runtime compile|verify-pack|run|reconstruct [flags]")
	os.Exit(2)
}
