// ulpf-runtime: the deterministic runtime engine. No model, no inference, no network egress.
//
//	ulpf-runtime compile  --spec <file>                      print dsl_hash and parser_hash
//	ulpf-runtime verify-pack --pack <dir>                    load a pack (fail closed) and report
//	ulpf-runtime run --pack <dir> --input <file> --evidence <dir> --out <jsonl> [--quarantine <jsonl>]
//	ulpf-runtime reconstruct --evidence <dir> --out <file>   write the byte-exact original stream
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/evidence"
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
	case "verify-pack":
		fs := flag.NewFlagSet("verify-pack", flag.ExitOnError)
		dir := fs.String("pack", "", "pack directory")
		contractsDir, pinned := commonFlags(fs)
		fs.Parse(os.Args[2:])
		p, err := pack.Load(*dir, pack.LoadOptions{ContractsDir: *contractsDir, PinnedIndex: *pinned})
		die(err)
		fmt.Printf("pack %s v%s: %d families verified (dsl_hash, parser_hash, contract)\n", p.PackID, p.PackVersion, len(p.Families))
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
		fixedClock := fs.Int64("fixed-clock-ms", 0, "deterministic clock for golden outputs (epoch ms)")
		fixedIDs := fs.Bool("deterministic-ids", false, "sequential event ids for golden outputs")
		contractsDir, pinned := commonFlags(fs)
		fs.Parse(os.Args[2:])
		p, err := pack.Load(*dir, pack.LoadOptions{ContractsDir: *contractsDir, PinnedIndex: *pinned})
		die(err)
		var in io.Reader = os.Stdin
		if *input != "-" {
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
		st, err := pipeline.Run(in, o)
		die(err)
		json.NewEncoder(os.Stderr).Encode(st)
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
