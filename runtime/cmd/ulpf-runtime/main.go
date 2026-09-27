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
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/egress"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/lake"
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
		lakeDir := fs.String("lake", "", "versioned lake directory (invariant 8): normalized events are ALSO sealed there as normalization@v1 (exclusive create, read-only, sha256 manifest); corrections go through `renormalize`")
		var forwards packList
		fs.Var(&forwards, "forward", "P8 egress (repeatable): syslog+tcp://host:port (RFC 5424 over RFC 6587 octet counting) | http(s)://collector/path (NDJSON POST) | stdout: — needs --out FILE (the delivery spool); a sink that stops accepting costs no event: delivery resumes from a persisted cursor and the interruption is a gap record in the evidence log")
		fwdStall := fs.Duration("forward-stall-after", 3*time.Second, "egress: report a sink as stalled (egress_stalled gap record) after this long without an accepted batch")
		spoolDir := fs.String("spool", "", "laptop branch: a BOUNDED, segmented delivery spool directory for --forward (instead of the --out file): every destination has its own cursor there, the slowest governs retention, and the run RESUMES the spool and the cursors; with --spool, --out is optional")
		spoolCap := fs.String("spool-cap", "1GiB", "with --spool: bytes retained for the slowest destination (demo: 256MiB). Past it, that destination skips the oldest segment and each skip is an egress_skipped evidence record. Size it as rate x tolerated outage: 1 h at 11,600 events/s of ~1.3 KB is ~54 GB")
		spoolSeg := fs.String("spool-segment", "16MiB", "with --spool: segment size (the unit of retention and of skipping)")
		spoolFresh := fs.Bool("spool-fresh", false, "with --spool: discard the previous spool and every cursor and start over (the default is to resume)")
		fwdDrain := fs.Duration("forward-drain", 10*time.Second, "egress: at the end of input, wait this long for sinks to catch up; what is left stays spooled (exit 3)")
		mlPath := fs.String("ml-out", "", "ML feature records JSONL (requirement h): (template_id, parameter_vector, timestamp, entity_ids)")
		input := fs.String("input", "", "input file (use - for stdin)")
		evDir := fs.String("evidence", "", "evidence store directory")
		outPath := fs.String("out", "-", "normalized JSONL output (- for stdout)")
		qPath := fs.String("quarantine", "", "quarantine JSONL output")
		collector := fs.String("collector", "col-01", "collector id")
		channel := fs.String("channel", "", "ingest channel (defaults to file:<input>)")
		failAfter := fs.Int("fail-after-raw-write", 0, "kill-test hook: exit once the batch holding the Nth frame is committed, before any of it is parsed")
		commitEvents := fs.Int("commit-events", 256, "group commit (invariant 3): commit the evidence batch at this many frames (1 = an fsync per event)")
		commitWait := fs.Duration("commit-wait", 10*time.Millisecond, "group commit (invariant 3): commit the evidence batch when its oldest frame has waited this long; no frame is parsed or delivered before its batch is durable")
		var listens packList
		fs.Var(&listens, "listen", "listener instead of --input: udp::5514, tcp::6514 (RFC 6587 octet counting, newline fallback), http::8514 (POST bodies); tcp: and http: may be given TOGETHER (repeat the flag): one runtime, two ingress connectors, each frame's evidence record names the connector it arrived on")
		packsFile := fs.String("packs-file", "", "a file listing further pack directories, one per line; re-read on SIGHUP: packs are loaded by the same fail-closed loader and swapped in between two frames without a restart; every change is a pack_activated record in the evidence log")
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
		listenS := ""
		if len(listens) > 0 {
			listenS = listens[0]
		}
		listen := &listenS
		loadAll := func() ([]*pack.Pack, error) {
			all := append([]string{}, dirs...)
			if *packsFile != "" {
				b, err := os.ReadFile(*packsFile)
				if err != nil && !os.IsNotExist(err) {
					return nil, err
				}
				for _, l := range strings.Split(string(b), "\n") {
					if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
						all = append(all, l)
					}
				}
			}
			var out []*pack.Pack
			for _, d := range all {
				p, err := pack.Load(d, loadOptions(*contractsDir, *pinned, *trust, *allowUnsigned))
				if err != nil {
					return nil, fmt.Errorf("%s: %w", d, err)
				}
				out = append(out, p)
			}
			return out, nil
		}
		packs, err := loadAll()
		die(err)
		// SIGHUP: reload. A pack that does not load (schema, invariants, signature) leaves the running set untouched.
		var livePipe *pipeline.Pipeline
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				if livePipe == nil {
					continue
				}
				next, err := loadAll()
				if err == nil {
					err = livePipe.Reload(next, "SIGHUP reload of --pack and --packs-file")
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "reload REFUSED, the running packs stay loaded: %v\n", err)
					continue
				}
				fmt.Fprintf(os.Stderr, "reloaded: %d pack(s)\n", len(next))
			}
		}()
		var in io.Reader = os.Stdin
		if *listen == "" && *pullDir == "" && *input != "-" {
			f, err := os.Open(*input)
			die(err)
			defer f.Close()
			in = f
		}
		out := os.Stdout
		outSet := false
		fs.Visit(func(fl *flag.Flag) { outSet = outSet || fl.Name == "out" })
		if *spoolDir != "" && !outSet { // with a segmented spool the normalized copy on stdout would collide with a stdout: destination
			out = nil
		}
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
		var outW io.Writer = io.Discard
		if out != nil {
			outW = out
		}
		var lakeW *lake.Writer
		if *lakeDir != "" {
			// invariant 8: the live path seals normalization@v1; it can never reopen it (lake.Create is exclusive)
			lw, err := lake.Create(*lakeDir, 1, 0, "ingest", time.Now())
			die(err)
			for _, p := range packs {
				lw.AddPack(p.PackID + "@" + p.PackVersion)
			}
			lakeW, outW = lw, io.MultiWriter(outW, lw)
		}
		o := pipeline.Options{Packs: packs, SourceID: *sourceID, ML: mlw, EvidenceDir: *evDir, Collector: *collector, Channel: *channel, Out: outW, Quarantine: q, FailAfterRawWrite: *failAfter,
			CommitEvents: *commitEvents, CommitWait: *commitWait, MaxEventBytes: *maxEvent, NoDebatch: *noDebatch, SilenceAfter: *silence}
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
		if len(forwards) > 0 && *spoolDir != "" {
			capB, err1 := parseBytes(*spoolCap)
			segB, err2 := parseBytes(*spoolSeg)
			die(errors.Join(err1, err2))
			if capB < 2*segB {
				die(fmt.Errorf("--spool-cap (%d bytes) must be at least two segments (--spool-segment %d bytes)", capB, segB))
			}
			o.SpoolDir, o.SpoolCap, o.SpoolSegment, o.SpoolFresh, o.EgressStallAfter, o.EgressDrain = *spoolDir, capB, segB, *spoolFresh, *fwdStall, *fwdDrain
			for _, u := range forwards {
				o.Egress = append(o.Egress, pipeline.EgressSink{URL: u})
			}
		} else if len(forwards) > 0 {
			if *outPath == "-" {
				die(fmt.Errorf("--forward needs --out FILE (the delivery spool the cursor points into) or --spool DIR"))
			}
			o.SpoolPath, o.EgressStallAfter, o.EgressDrain = *outPath, *fwdStall, *fwdDrain
			for i, u := range forwards {
				o.Egress = append(o.Egress, pipeline.EgressSink{URL: u, CursorPath: fmt.Sprintf("%s.egress-%d.cursor", *outPath, i)})
			}
		}
		var st pipeline.Stats
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		switch {
		case len(listens) > 1:
			// two ingress connectors in one runtime: syslog/TCP and HTTP receive share the evidence log, the router and
			// the egress; every frame carries the connector it arrived on into its evidence record
			var t *frame.TCP
			var h *frame.HTTP
			var tl, hl net.Listener
			for _, l := range listens {
				switch {
				case strings.HasPrefix(l, "tcp:") && t == nil:
					t = &frame.TCP{Addr: strings.TrimPrefix(l, "tcp:"), MaxEventBytes: *maxEvent, MaxConns: *maxConns, IdleTimeout: *idle, MaxFrames: int64(*maxFrames), Multiline: multi}
					tl, err = t.Listen()
					die(err)
				case strings.HasPrefix(l, "http:") && h == nil:
					h = &frame.HTTP{Addr: strings.TrimPrefix(l, "http:"), MaxBodyBytes: *maxBody, MaxEventBytes: *maxEvent, MaxFrames: int64(*maxFrames)}
					hl, err = h.Listen()
					die(err)
				default:
					die(fmt.Errorf("--listen repeated: one tcp: and one http: listener are supported together, got %q", l))
				}
			}
			if t == nil || h == nil {
				die(fmt.Errorf("--listen repeated: one tcp: and one http: listener are supported together"))
			}
			o.Channel = "tcp:" + t.Addr
			fmt.Fprintf(os.Stderr, "listening for syslog over TCP on %s and receiving HTTP POST bodies on %s\n", tl.Addr(), hl.Addr())
			st, err = pipeline.RunFramesWith(func(emit func(frame.Frame) error) error {
				herr := make(chan error, 1)
				go func() {
					herr <- h.Serve(ctx, hl, func(fr frame.Frame) error { fr.Channel = "http:" + h.Addr; return emit(fr) })
				}()
				terr := t.Serve(ctx, tl, func(fr frame.Frame) error { fr.Channel = "tcp:" + t.Addr; return emit(fr) })
				stop()
				if e := <-herr; terr == nil {
					terr = e
				}
				return terr
			}, o, func(p *pipeline.Pipeline) { t.OnClose = p.Lost; h.Commit = p.Commit; livePipe = p })
			die(err)
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
				func(p *pipeline.Pipeline) { t.OnClose = p.Lost; livePipe = p })
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
			st, err = pipeline.RunFramesWith(func(emit func(frame.Frame) error) error { return h.Serve(ctx, ln, emit) }, o, func(p *pipeline.Pipeline) { h.Commit = p.Commit; livePipe = p })
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
		if lakeW != nil {
			m, err := lakeW.Close()
			die(err)
			fmt.Fprintf(os.Stderr, "lake: sealed normalization@v1, %d events, %s\n", m.Events, m.SHA256)
		}
		json.NewEncoder(os.Stderr).Encode(st)
		undelivered := false
		for _, es := range st.Egress {
			if es.Undelivered > 0 {
				fmt.Fprintf(os.Stderr, "egress: %d byte(s) NOT delivered to %s (%s); nothing is lost — resume with: ulpf-runtime forward --from %s --to %s --cursor <the .cursor file beside the spool>\n", es.Undelivered, es.Sink, es.LastError, *outPath, es.Sink)
				undelivered = true
			}
		}
		if undelivered {
			os.Exit(3) // every output file is an unbuffered os.File and the lake is sealed above: nothing is pending
		}
	case "forward":
		// P8: deliver (or finish delivering) a spool of normalized events from a persisted cursor. The standalone form of
		// `run --forward`: same forwarder, same at-least-once semantics; it cannot write gap records (it does not own the
		// evidence store), so it reports stalls on stderr.
		fs := flag.NewFlagSet("forward", flag.ExitOnError)
		from := fs.String("from", "", "spool: a normalized-event JSONL file")
		to := fs.String("to", "", "sink: syslog+tcp://host:port | http(s)://url | stdout:")
		cursor := fs.String("cursor", "", "cursor file (default <from>.forward.cursor)")
		follow := fs.Bool("follow", false, "keep following the spool as it grows (until SIGINT)")
		wait := fs.Duration("wait", 30*time.Second, "without --follow: how long to keep retrying a sink that is not accepting")
		fs.Parse(os.Args[2:])
		if *from == "" || *to == "" {
			die(fmt.Errorf("forward needs --from and --to"))
		}
		if *cursor == "" {
			*cursor = *from + ".forward.cursor"
		}
		sink, err := egress.Open(*to, 5*time.Second)
		die(err)
		f := &egress.Forwarder{Spool: *from, CursorPath: *cursor, Sink: sink,
			OnStall: func(s egress.Stall) {
				fmt.Fprintf(os.Stderr, "egress STALLED %s since %s: %s (last acknowledged %s; nothing dropped)\n", s.Sink, s.Since.Format(time.RFC3339), s.Err, s.LastEventID)
			},
			OnResume: func(s egress.Stall) {
				fmt.Fprintf(os.Stderr, "egress RESUMED %s after %s: %d event(s) delivered late\n", s.Sink, s.Duration.Round(time.Millisecond), s.LagEvents)
			}}
		die(f.Start(false))
		if *follow {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			<-ctx.Done()
			stop()
			*wait = 5 * time.Second
		}
		es := f.Drain(*wait)
		json.NewEncoder(os.Stderr).Encode(es)
		if es.Undelivered > 0 {
			os.Exit(3)
		}
	case "renormalize":
		// Invariant 8: a correction. Re-derives the affected events from the EVIDENCE under the corrected
		// packs and seals them as the next normalization version with derived_from; prior versions are read, never written.
		fs := flag.NewFlagSet("renormalize", flag.ExitOnError)
		var dirs packList
		fs.Var(&dirs, "pack", "corrected pack directory (repeat: every pack of the stream)")
		evDir := fs.String("evidence", "", "evidence store directory (the raw bytes every version derives from)")
		lakeDir := fs.String("lake", "", "versioned lake directory")
		reason := fs.String("reason", "", "why this version exists (the certificate resolved, the pack version applied)")
		contractsDir, pinned := commonFlags(fs)
		trust, allowUnsigned := signingFlags(fs)
		fs.Parse(os.Args[2:])
		if len(dirs) == 0 || *evDir == "" || *lakeDir == "" || *reason == "" {
			die(fmt.Errorf("renormalize needs --pack, --evidence, --lake and --reason"))
		}
		var packs []*pack.Pack
		for _, d := range dirs {
			p, err := pack.Load(d, loadOptions(*contractsDir, *pinned, *trust, *allowUnsigned))
			die(err)
			packs = append(packs, p)
		}
		st, err := pipeline.Renormalize(pipeline.RenormOptions{Packs: packs, EvidenceDir: *evDir, LakeDir: *lakeDir, Reason: *reason})
		die(err)
		json.NewEncoder(os.Stdout).Encode(st)
	case "lake":
		// lake verify --lake DIR | lake get --lake DIR --event-id ID   (every version of one event)
		if len(os.Args) < 3 {
			usage()
		}
		fs := flag.NewFlagSet("lake", flag.ExitOnError)
		lakeDir := fs.String("lake", "", "versioned lake directory")
		eventID := fs.String("event-id", "", "event id (get)")
		fs.Parse(os.Args[3:])
		switch os.Args[2] {
		case "verify":
			ms, findings := lake.Verify(*lakeDir)
			for _, m := range ms {
				from := "ingest"
				if m.DerivedFrom > 0 {
					from = fmt.Sprintf("derived_from v%d", m.DerivedFrom)
				}
				fmt.Printf("normalization@v%d: %d events, %s, %s — %s\n", m.Version, m.Events, from, m.SHA256, m.Reason)
			}
			for _, f := range findings {
				fmt.Printf("FINDING v%d: %s\n", f.Version, f.Problem)
			}
			if len(findings) > 0 || len(ms) == 0 {
				fmt.Printf("LAKE: FAIL — %d finding(s) over %d version(s)\n", len(findings), len(ms))
				os.Exit(1)
			}
			fmt.Printf("LAKE: OK — %d version(s), every version byte-identical to what was sealed\n", len(ms))
		case "get":
			evs, err := lake.Get(*lakeDir, *eventID)
			die(err)
			if len(evs) == 0 {
				die(fmt.Errorf("event %s is in no version", *eventID))
			}
			for _, e := range evs {
				os.Stdout.Write(append(e, '\n'))
			}
		default:
			usage()
		}
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

// parseBytes reads 256MiB, 1GiB, 16MB, 4096.
func parseBytes(s string) (int64, error) {
	units := []struct {
		suf string
		mul int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40}, {"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12}, {"B", 1}}
	for _, u := range units {
		if strings.HasSuffix(s, u.suf) {
			var n float64
			if _, err := fmt.Sscanf(strings.TrimSuffix(s, u.suf), "%g", &n); err != nil || n <= 0 {
				return 0, fmt.Errorf("bad size %q", s)
			}
			return int64(n * float64(u.mul)), nil
		}
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return n, nil
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
	fmt.Fprintln(os.Stderr, "usage: ulpf-runtime compile|parse|verify-pack|run|forward|renormalize|lake verify|lake get|export|reconstruct [flags]")
	os.Exit(2)
}
