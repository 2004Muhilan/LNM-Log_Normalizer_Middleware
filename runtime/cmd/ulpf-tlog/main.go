// ulpf-tlog — the Parser Transparency Log (laptop branch, 2026-09-27). Every parser pack is appended here before any
// runtime may load it; the runtime refuses a pack without a valid inclusion proof (c2sp.org/tlog-proof, beside the pack
// as pack.json.tlog-proof). Formats: C2SP signed-note checkpoints, RFC 6962 Merkle tree, witness cosignatures.
//
//	ulpf-tlog keygen  --name ORIGIN --kind log|witness --key OUT.json --vkey OUT.vkey
//	ulpf-tlog append  --pack DIR --produced-by hand-written|onboarded|auto-healed|vendor-onboarded   (idempotent)
//	ulpf-tlog prove   --pack DIR          rewrite the pack's proof against the latest checkpoint
//	ulpf-tlog verify  --pack DIR [--min-witnesses N]   offline: the proof, the checkpoint signature, the cosignatures
//	ulpf-tlog list    [--json]            every entry: index, pack, version, how it was produced, when it was logged
//	ulpf-tlog cosign                      ask the witness to cosign the latest checkpoint
//
// Common: --log DIR (default <repo>/tlog, ULPF_TLOG_DIR), --key FILE (default keys/dev/ulpf-tlog-dev.json,
// ULPF_TLOG_KEY), --origin NAME (default: the key's authority id), --witness URL (ULPF_TLOG_WITNESS),
// --trust DIR (default keys/trust).
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"ulpf/runtime/internal/keys"
	"ulpf/runtime/internal/tlog"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	root := repoRoot()
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	logDir := fs.String("log", env("ULPF_TLOG_DIR", filepath.Join(root, "tlog")), "log directory")
	keyPath := fs.String("key", env("ULPF_TLOG_KEY", filepath.Join(root, "keys", "dev", "ulpf-tlog-dev.json")), "the log's signing key")
	origin := fs.String("origin", "", "the log's origin and key name (default: the key's authority id, e.g. ulpf-tlog-dev)")
	witness := fs.String("witness", os.Getenv("ULPF_TLOG_WITNESS"), "witness submission prefix (http://host:port)")
	trust := fs.String("trust", filepath.Join(root, "keys", "trust"), "trust store (*.vkey)")
	pack := fs.String("pack", "", "pack directory")
	produced := fs.String("produced-by", "", "how the pack was produced")
	minW := fs.Int("min-witnesses", 0, "verify: witness cosignatures required")
	asJSON := fs.Bool("json", false, "list: JSON")
	name := fs.String("name", "", "keygen: key name (a log's origin, or a witness's name)")
	kind := fs.String("kind", "log", "keygen: log | witness")
	out := fs.String("vkey", "", "keygen: verifier-key file to write")
	fs.Parse(os.Args[2:])

	if os.Args[1] == "keygen" {
		k, err := keys.Generate(*name) // the key name is the log's origin / the witness's name: a slug
		die(err)
		seed, _ := hex.DecodeString(k.PrivateKey)
		kb := byte(0x01)
		if *kind == "witness" {
			kb = 0x04
		}
		s, err := tlog.NewSigner(*name, seed, kb)
		die(err)
		die(k.Save(*keyPath))
		die(os.WriteFile(*out, []byte(s.VerifierKey()+"\n"), 0o644))
		fmt.Println(s.VerifierKey())
		return
	}
	if os.Args[1] == "verify" {
		pol, err := tlog.LoadPolicy(*trust, *minW)
		die(err)
		v, err := tlog.VerifyPack(*pack, pol)
		die(err)
		fmt.Printf("TLOG: OK — %s v%s is entry %d of %s (checkpoint size %d), produced by %s, logged %s; witnesses: %v\n",
			v.Entry.PackID, v.Entry.PackVersion, v.Index, v.Log, v.Checkpoint.Size, v.Entry.ProducedBy, v.Entry.LoggedAt, v.Witnesses)
		return
	}
	lg := &tlog.Log{Dir: *logDir, Witness: *witness}
	if os.Args[1] != "list" {
		k, err := keys.Load(*keyPath)
		die(err)
		seed, _ := hex.DecodeString(k.PrivateKey)
		o := *origin
		if o == "" {
			o = k.AuthorityID
		}
		lg.Signer, err = tlog.NewSigner(o, seed, 0x01)
		die(err)
	}
	switch os.Args[1] {
	case "append":
		idx, fresh, err := lg.Append(*pack, *produced)
		die(err)
		what := "already logged"
		if fresh {
			what = "appended"
		}
		fmt.Printf("tlog: %s as entry %d; proof written to %s\n", what, idx, filepath.Join(*pack, tlog.ProofFile))
	case "prove":
		_, _, _, sha, err := tlog.PackFacts(*pack)
		die(err)
		idx := lg.Find(sha)
		if idx < 0 {
			die(fmt.Errorf("%s is not in the log", *pack))
		}
		p, err := lg.Prove(idx)
		die(err)
		die(os.WriteFile(filepath.Join(*pack, tlog.ProofFile), []byte(p), 0o644))
	case "cosign":
		die(lg.Cosign())
		n, _ := lg.Latest()
		fmt.Print(n.Text)
	case "list":
		lv, err := lg.Leaves()
		die(err)
		type row struct {
			Index int `json:"index"`
			tlog.Entry
		}
		var rows []row
		for i := range lv {
			e, _, err := lg.Entry(i)
			if err == nil {
				rows = append(rows, row{i, e})
			}
		}
		cp := map[string]any{}
		if n, err := lg.Latest(); err == nil {
			c, _ := tlog.ParseCheckpoint(n.Text)
			names := []string{}
			for _, s := range n.Sigs {
				names = append(names, s.Name)
			}
			cp = map[string]any{"origin": c.Origin, "size": c.Size, "signatures": names}
		}
		if *asJSON {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"checkpoint": cp, "entries": rows})
			return
		}
		for _, r := range rows {
			fmt.Printf("%4d  %-40s %-8s %-18s %s  %s\n", r.Index, r.PackID, r.PackVersion, r.ProducedBy, r.LoggedAt, r.PackSHA256[:23])
		}
		fmt.Printf("checkpoint: %v\n", cp)
	default:
		usage()
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

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
		fmt.Fprintln(os.Stderr, "ulpf-tlog:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ulpf-tlog keygen|append|prove|verify|list|cosign [flags]")
	os.Exit(2)
}
