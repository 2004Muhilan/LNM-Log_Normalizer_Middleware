// ulpf-verify — the standalone verifier. Needs a trust store (public keys) and either an evidence
// directory with its commit/ tree or an exported bundle. No pack, no contracts, no ULPF state: it is
// what a machine that has never run ULPF uses to check what a ULPF instance claims.
//
//	ulpf-verify evidence --evidence <dir> --trust <dir>     recompute every root, check every signature and the chain
//	ulpf-verify bundle   --bundle <dir>   --trust <dir>     verify one exported event against its checkpoint
//	ulpf-verify locate   --evidence <dir> --segment <id>    name the first record whose bytes changed
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/keys"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "evidence":
		fs := flag.NewFlagSet("evidence", flag.ExitOnError)
		ev := fs.String("evidence", "", "evidence directory")
		cdir := fs.String("commit", "", "commit directory (default <evidence>/commit)")
		trust := fs.String("trust", "", "trust store directory")
		fs.Parse(os.Args[2:])
		findings, n, err := checkpoint.VerifyAll(*ev, *cdir, keys.TrustStore{Dir: *trust})
		die(err)
		for _, f := range findings {
			fmt.Printf("FINDING %s: %s\n", f.Where, f.Detail)
			if loc, _ := checkpoint.LocateTamper(*ev, f.Where); loc != "" {
				fmt.Printf("        tampered %s\n", loc)
			}
		}
		if len(findings) > 0 {
			fmt.Printf("VERIFY: FAIL — %d finding(s) over %d checkpoint(s)\n", len(findings), n)
			os.Exit(1)
		}
		fmt.Printf("VERIFY: OK — %d checkpoint(s), every segment root recomputed from the raw bytes, every signature and the chain verified\n", n)
	case "bundle":
		fs := flag.NewFlagSet("bundle", flag.ExitOnError)
		b := fs.String("bundle", "", "bundle directory")
		trust := fs.String("trust", "", "trust store directory")
		fs.Parse(os.Args[2:])
		findings, err := checkpoint.VerifyBundle(*b, keys.TrustStore{Dir: *trust})
		for _, f := range findings {
			fmt.Printf("FINDING %s: %s\n", f.Where, f.Detail)
		}
		if err != nil {
			fmt.Println("VERIFY: FAIL —", err)
			os.Exit(1)
		}
		bb, _ := os.ReadFile(*b + "/bundle.json")
		var doc map[string]any
		json.Unmarshal(bb, &doc)
		fmt.Printf("VERIFY: OK — event %v: raw bytes match the record, leaf proof reaches segment root %v, checkpoint %v signed by a trusted authority\n", doc["event_id"], doc["segment_root"], doc["checkpoint_id"])
	case "locate":
		fs := flag.NewFlagSet("locate", flag.ExitOnError)
		ev := fs.String("evidence", "", "evidence directory")
		seg := fs.String("segment", "", "segment id")
		fs.Parse(os.Args[2:])
		loc, err := checkpoint.LocateTamper(*ev, *seg)
		die(err)
		if loc == "" {
			fmt.Println("intact")
		} else {
			fmt.Println("tampered:", loc)
		}
	default:
		usage()
	}
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ulpf-verify evidence|bundle|locate [flags]")
	os.Exit(2)
}
