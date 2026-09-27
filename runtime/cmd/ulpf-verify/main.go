// ulpf-verify — the standalone verifier. Needs a trust store (public keys) and either an evidence
// directory with its commit/ tree or an exported bundle. No pack, no contracts, no ULPF state: it is
// what a machine that has never run ULPF uses to check what a ULPF instance claims.
//
//	ulpf-verify evidence --evidence <dir> --trust <dir>     recompute every root, check every signature and the chain
//	ulpf-verify bundle   --bundle <dir>   --trust <dir>     verify one exported event against its checkpoint
//	ulpf-verify locate   --evidence <dir> --segment <id>    name the first record whose bytes changed
//	ulpf-verify gaps     --evidence <dir> --trust <dir>     P7: list every gap record (silence, sequence gap, connection lost) with its commitment status
//	ulpf-verify derivation --bundle <file> --trust <dir> [--json]   Proof of Derivation: the raw bytes, the logged pack re-run
//	                     on them, the SIEM's event — offline; says which part fails (raw bytes | pack | SIEM document).
//	                     It re-runs the pack with the engine compiled into this binary, and loads it against the contract
//	                     schemas and the pinned OCSF index (--contracts, --pinned), whose hashes the bundle records.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/derivation"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/keys"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "derivation":
		fs := flag.NewFlagSet("derivation", flag.ExitOnError)
		bundle := fs.String("bundle", "", "derivation bundle (ulpf-runtime derive)")
		trust := fs.String("trust", "keys/trust", "trust store")
		root := os.Getenv("ULPF_ROOT")
		if root == "" {
			root = "."
		}
		contracts := fs.String("contracts", filepath.Join(root, "contracts"), "contract schemas")
		pinned := fs.String("pinned", filepath.Join(root, "ocsf", "pinned", "index.json"), "pinned OCSF index")
		minW := fs.Int("min-witnesses", 0, "witness cosignatures the pack's log checkpoint must carry")
		asJSON := fs.Bool("json", false, "the report as JSON")
		fs.Parse(os.Args[2:])
		data, err := os.ReadFile(*bundle)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		var b derivation.Bundle
		if err := json.Unmarshal(data, &b); err != nil {
			fmt.Fprintln(os.Stderr, "not a derivation bundle:", err)
			os.Exit(2)
		}
		r := derivation.Verify(&b, derivation.VerifyOptions{TrustDir: *trust, ContractsDir: *contracts, PinnedIndex: *pinned, MinWitnesses: *minW})
		if *asJSON {
			json.NewEncoder(os.Stdout).Encode(r)
		} else {
			for _, s := range r.Steps {
				mark := "ok  "
				if !s.OK {
					mark = "FAIL"
				}
				fmt.Printf("%s [%s] %s: %s\n", mark, s.Part, s.Name, s.Detail)
			}
			for _, d := range r.Differing {
				fmt.Printf("     %s: derived %v, the SIEM holds %v\n", d.Field, d.Derived, d.SIEM)
			}
			if r.OK {
				fmt.Printf("DERIVATION: OK — event %s: the logged pack, re-run on the committed raw bytes, reproduces the SIEM's event (excluded: _lineage.processing_time)\n", b.EventID)
			} else {
				fmt.Printf("DERIVATION: FAIL — %s\n", map[string]string{"raw bytes": "the RAW BYTES were altered", "pack": "the PACK is not the logged pack", "SIEM document": "the SIEM DOCUMENT differs from the derivation"}[r.Culprit])
			}
		}
		if !r.OK {
			os.Exit(1)
		}
	case "evidence":
		fs := flag.NewFlagSet("evidence", flag.ExitOnError)
		ev := fs.String("evidence", "", "evidence directory")
		evArchive := fs.String("evidence-archive", "", "the evidence archive: a segment deleted locally is verified from its archived copy")
		cdir := fs.String("commit", "", "commit directory (default <evidence>/commit)")
		trust := fs.String("trust", "", "trust store directory")
		strict := fs.Bool("strict", false, "fail unless every checkpoint attests to kernel-locked evidence (commit_mode kernel_immutable)")
		fs.Parse(os.Args[2:])
		loc := evidence.NewLocator(*ev, *evArchive)
		findings, n, err := checkpoint.VerifyAllFrom(loc, *cdir, keys.TrustStore{Dir: *trust})
		die(err)
		for _, f := range findings {
			fmt.Printf("FINDING %s: %s\n", f.Where, f.Detail)
			if loc, _ := checkpoint.LocateTamperFrom(loc, f.Where); loc != "" {
				fmt.Printf("        tampered %s\n", loc)
			}
		}
		weak := reportModes(checkpoint.Modes(*ev, *cdir))
		if len(findings) > 0 {
			fmt.Printf("VERIFY: FAIL — %d finding(s) over %d checkpoint(s)\n", len(findings), n)
			os.Exit(1)
		}
		if weak && *strict {
			fmt.Println("VERIFY: FAIL — --strict: a checkpoint does not attest to kernel-locked evidence")
			os.Exit(1)
		}
		fmt.Printf("VERIFY: OK — %d checkpoint(s), every segment root recomputed from the raw bytes, every signature and the chain verified\n", n)
	case "bundle":
		fs := flag.NewFlagSet("bundle", flag.ExitOnError)
		b := fs.String("bundle", "", "bundle directory")
		trust := fs.String("trust", "", "trust store directory")
		strict := fs.Bool("strict", false, "fail unless the checkpoint attests to kernel-locked evidence (commit_mode kernel_immutable)")
		fs.Parse(os.Args[2:])
		findings, err := checkpoint.VerifyBundle(*b, keys.TrustStore{Dir: *trust})
		for _, f := range findings {
			fmt.Printf("FINDING %s: %s\n", f.Where, f.Detail)
		}
		if err != nil || len(findings) > 0 { // a finding is a failure even if the library returned no error (it once did: a missing .sig printed VERIFY: OK)
			if err == nil {
				err = fmt.Errorf("%d finding(s)", len(findings))
			}
			fmt.Println("VERIFY: FAIL —", err)
			os.Exit(1)
		}
		bb, _ := os.ReadFile(*b + "/bundle.json")
		var doc map[string]any
		json.Unmarshal(bb, &doc)
		var ck checkpoint.Checkpoint
		cb, _ := os.ReadFile(*b + "/checkpoint.json")
		json.Unmarshal(cb, &ck)
		weak := reportModes(map[string]string{ck.CheckpointID: ck.Mode()})
		if weak && *strict {
			fmt.Println("VERIFY: FAIL — --strict: the checkpoint does not attest to kernel-locked evidence")
			os.Exit(1)
		}
		fmt.Printf("VERIFY: OK — event %v: raw bytes match the record, leaf proof reaches segment root %v, checkpoint %v signed by a trusted authority\n", doc["event_id"], doc["segment_root"], doc["checkpoint_id"])
	case "gaps":
		// P7: absence made tamper-evident. Every gap record is a leaf like any event: listed here with the
		// checkpoint that committed it, the recomputed segment root and the signature verdict — or
		// UNCOMMITTED, never hidden.
		fs := flag.NewFlagSet("gaps", flag.ExitOnError)
		ev := fs.String("evidence", "", "evidence directory")
		gapArchive := fs.String("evidence-archive", "", "the evidence archive: a segment deleted locally is verified from its archived copy")
		cdir := fs.String("commit", "", "commit directory (default <evidence>/commit)")
		trust := fs.String("trust", "", "trust store directory")
		asJSON := fs.Bool("json", false, "one JSON object per line")
		fs.Parse(os.Args[2:])
		entries, err := checkpoint.GapsFrom(evidence.NewLocator(*ev, *gapArchive), *cdir, keys.TrustStore{Dir: *trust})
		die(err)
		bad := 0
		for _, e := range entries {
			if *asJSON {
				json.NewEncoder(os.Stdout).Encode(e)
				continue
			}
			state := "UNCOMMITTED"
			if e.Committed {
				state = fmt.Sprintf("committed in %s", e.CheckpointID)
				if e.RootVerified && e.SignatureOK {
					state += fmt.Sprintf(", root recomputed, signed by %s (%s)", e.AuthorityID, e.CommitMode)
				} else {
					state += " BUT root or signature does not verify"
					bad++
				}
			}
			if e.Problem != "" {
				state += " PROBLEM: " + e.Problem
				bad++
			}
			r := e.Record
			detail := ""
			switch r.Kind {
			case "silence":
				detail = fmt.Sprintf("silent for %d ms since %d (last event %s)", r.SilenceMS, r.LastSeenAt, r.LastEventID)
			case "silence_end":
				detail = fmt.Sprintf("resumed after %d ms", r.SilenceMS)
			case "sequence_gap":
				detail = fmt.Sprintf("expected sequence %d, observed %d: %d message(s) missing", r.Expected, r.Observed, r.Missing)
			case "sequence_reset":
				detail = fmt.Sprintf("expected sequence %d, observed %d: %s", r.Expected, r.Observed, r.Detail)
			case "egress_stalled":
				detail = fmt.Sprintf("DELIVERY to %s interrupted (last acknowledged event %s): %s", r.Peer, r.LastEventID, r.Detail)
			case "egress_resumed":
				detail = fmt.Sprintf("delivery to %s resumed after %d ms: %s", r.Peer, r.SilenceMS, r.Detail)
			default:
				detail = r.Detail
			}
			fmt.Printf("GAP %-15s peer=%s source=%s channel=%s at=%d — %s\n     leaf %d of %s (%s), %s\n", r.Kind, r.Peer, r.SourceID, r.Channel, r.DetectedAt, detail, e.LeafIndex, e.SegmentID, e.EventID, state)
		}
		summary := os.Stdout
		if *asJSON {
			summary = os.Stderr // keep stdout one JSON object per line
		}
		fmt.Fprintf(summary, "GAPS: %d record(s)", len(entries))
		if bad > 0 {
			fmt.Fprintf(summary, ", %d with problems\n", bad)
			os.Exit(1)
		}
		fmt.Fprintln(summary)
	case "locate":
		fs := flag.NewFlagSet("locate", flag.ExitOnError)
		ev := fs.String("evidence", "", "evidence directory")
		locArchive := fs.String("evidence-archive", "", "the evidence archive: a segment deleted locally is verified from its archived copy")
		seg := fs.String("segment", "", "segment id")
		fs.Parse(os.Args[2:])
		loc, err := checkpoint.LocateTamperFrom(evidence.NewLocator(*ev, *locArchive), *seg)
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

// reportModes prints what each checkpoint attests to and returns true when any is weaker than
// kernel_immutable. A development checkpoint (sealed_only_dev) verifies cryptographically like any other;
// what it attests to is file hashes at commit time, NOT kernel-locked evidence — and it says so here.
func reportModes(modes map[string]string) bool {
	weak := false
	ids := make([]string, 0, len(modes))
	for id := range modes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		m := modes[id]
		switch m {
		case checkpoint.ModeKernelImmutable:
			fmt.Printf("MODE %s: kernel_immutable — every committed segment carried the kernel immutable flag\n", id)
		case checkpoint.ModeSealedOnlyDev:
			weak = true
			fmt.Printf("MODE %s: *** sealed_only_dev *** — DEVELOPMENT checkpoint: attests to file hashes at commit time, NOT to kernel-locked evidence\n", id)
		default:
			weak = true
			fmt.Printf("MODE %s: %s — cannot say what this checkpoint attests to\n", id, m)
		}
	}
	return weak
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ulpf-verify evidence|bundle|locate|gaps [flags]")
	os.Exit(2)
}
