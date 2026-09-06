// ulpf-committer — the privilege-separated committer. Reads sealed, immutable evidence segments and
// writes signed Merkle checkpoints. It holds the checkpoint signing key and NO capability: it cannot
// alter the evidence it commits (the store, which holds CAP_LINUX_IMMUTABLE, cannot sign). Run as a
// separate unprivileged process/container over the same evidence volume.
//
//	ulpf-committer commit --evidence <dir> --key <key.json> [--every 60s]   one pass, or a loop
//	ulpf-committer daily  --evidence <dir> --key <key.json> [--day YYYY-MM-DD]
//	ulpf-committer keygen --authority <id> --out <key.json> [--pub <pub.json>]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/keys"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "commit":
		fs := flag.NewFlagSet("commit", flag.ExitOnError)
		ev := fs.String("evidence", "", "evidence directory (read)")
		cdir := fs.String("commit", "", "commit directory (written; default <evidence>/commit — in production a directory the committer owns and the store cannot write)")
		keyPath := fs.String("key", "", "committer signing key (json)")
		every := fs.Duration("every", 0, "loop interval (0 = one pass)")
		fs.Parse(os.Args[2:])
		key, err := keys.Load(*keyPath)
		die(err)
		imm := checkpoint.KernelImmutability
		if os.Getenv("ULPF_COMMIT_SEALED") == "1" {
			// Test seam for unprivileged development shells where the kernel flag cannot be set: treat
			// SEALED as committable. Loud, because it removes the ordering guarantee the kernel provides.
			fmt.Fprintln(os.Stderr, "WARNING: ULPF_COMMIT_SEALED=1 — committing SEALED segments without the kernel immutable flag (development only)")
			imm = func(dir, seg string) string {
				st := checkpoint.KernelImmutability(dir, seg)
				if st == "sealed" {
					return "immutable"
				}
				return st
			}
		}
		for {
			rep, err := checkpoint.Commit(*ev, *cdir, key, imm, time.Now())
			die(err)
			json.NewEncoder(os.Stdout).Encode(rep)
			if *every == 0 {
				return
			}
			time.Sleep(*every)
		}
	case "daily":
		fs := flag.NewFlagSet("daily", flag.ExitOnError)
		ev := fs.String("evidence", "", "evidence directory")
		cdir := fs.String("commit", "", "commit directory (default <evidence>/commit)")
		keyPath := fs.String("key", "", "committer signing key (json)")
		day := fs.String("day", "", "UTC day YYYY-MM-DD (default today)")
		fs.Parse(os.Args[2:])
		key, err := keys.Load(*keyPath)
		die(err)
		d := time.Now().UTC()
		if *day != "" {
			d, err = time.Parse("2006-01-02", *day)
			die(err)
		}
		ck, path, err := checkpoint.Daily(*ev, *cdir, key, d)
		die(err)
		fmt.Printf("daily root %s over %d checkpoints: %s (%s)\n", ck.CheckpointID, len(ck.Checkpoints), ck.Root, path)
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		auth := fs.String("authority", "", "authority id (slug)")
		out := fs.String("out", "", "private key file")
		pub := fs.String("pub", "", "public key file for the trust store (default <authority>.pub.json beside --out)")
		fs.Parse(os.Args[2:])
		k, err := keys.Generate(*auth)
		die(err)
		die(k.Save(*out))
		if *pub == "" {
			*pub = *auth + ".pub.json"
		}
		die(k.PublicOnly().Save(*pub))
		fmt.Printf("generated %s: private %s, public %s\n", *auth, *out, *pub)
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
	fmt.Fprintln(os.Stderr, "usage: ulpf-committer commit|daily|keygen [flags]")
	os.Exit(2)
}
