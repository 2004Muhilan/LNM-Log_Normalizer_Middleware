// ulpf-runtime: the deterministic runtime engine. No model, no inference, no network egress.
//
//	ulpf-runtime compile  --spec <file>                      print dsl_hash and parser_hash
//	ulpf-runtime verify-pack --pack <dir>                    load a pack (fail closed) and report
//	ulpf-runtime run --pack <dir> --input <file> --evidence <dir> --out <jsonl> [--quarantine <jsonl>]
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
		dir := fs.String("pack", "", "pack directory")
		input := fs.String("input", "", "input file (use - for stdin)")
		evDir := fs.String("evidence", "", "evidence store directory")
		outPath := fs.String("out", "-", "normalized JSONL output (- for stdout)")
		qPath := fs.String("quarantine", "", "quarantine JSONL output")
		collector := fs.String("collector", "col-01", "collector id")
		channel := fs.String("channel", "", "ingest channel (defaults to file:<input>)")
		failAfter := fs.Int("fail-after-raw-write", 0, "kill-test hook: exit after the Nth raw write")
		listen := fs.String("listen", "", "syslog UDP listener instead of --input, e.g. udp::5514 or udp:127.0.0.1:5514")
		maxFrames := fs.Int("max-frames", 0, "with --listen: stop after N datagrams (0 = until SIGINT)")
		fixedClock := fs.Int64("fixed-clock-ms", 0, "deterministic clock for golden outputs (epoch ms)")
		fixedIDs := fs.Bool("deterministic-ids", false, "sequential event ids for golden outputs")
		contractsDir, pinned := commonFlags(fs)
		trust, allowUnsigned := signingFlags(fs)
		fs.Parse(os.Args[2:])
		p, err := pack.Load(*dir, loadOptions(*contractsDir, *pinned, *trust, *allowUnsigned))
		die(err)
		var in io.Reader = os.Stdin
		if *listen == "" && *input != "-" {
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
		o := pipeline.Options{Pack: p, EvidenceDir: *evDir, Collector: *collector, Channel: *channel, Out: out, Quarantine: q, FailAfterRawWrite: *failAfter}
		if *fixedClock > 0 {
			t := time.UnixMilli(*fixedClock).UTC()
			o.Now = func() time.Time { return t }
		}
		if *fixedIDs {
			n := 0
			o.NewID = func(time.Time) string { n++; return fmt.Sprintf("ev_%026d", n) }
		}
		var st pipeline.Stats
		if *listen != "" {
			// syslog over UDP: one datagram per frame; every received byte is evidence, the envelope is
			// unwrapped after the raw write, the payload is routed and parsed.
			addr := strings.TrimPrefix(*listen, "udp:")
			u := frame.UDP{Addr: addr, MaxEventBytes: 65536, MaxFrames: *maxFrames}
			conn, err := u.Listen()
			die(err)
			if *channel == "file:" {
				o.Channel = "udp:" + addr
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			fmt.Fprintf(os.Stderr, "listening for syslog datagrams on %s\n", conn.LocalAddr())
			st, err = pipeline.RunFrames(func(emit func(frame.Frame) error) error { return u.Serve(ctx, conn, emit) }, o)
			die(err)
		} else {
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
