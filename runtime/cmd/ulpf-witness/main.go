// ulpf-witness — a transparency-log witness (c2sp.org/tlog-witness): it cosigns a parser-log checkpoint only after
// verifying that it is a consistent extension of the last checkpoint it cosigned, so a log that rewrote its history
// cannot obtain a cosignature. In the demo it runs on the same machine as the log and STANDS IN for an independent
// site; real deployments put witnesses on separate machines, under separate operators.
//
//	ulpf-witness --key keys/dev/ulpf-witness-dev.json --name ulpf-witness-dev --trust keys/trust --state DIR --listen 127.0.0.1:8796
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"

	"ulpf/runtime/internal/keys"
	"ulpf/runtime/internal/tlog"
)

func main() {
	keyPath := flag.String("key", "keys/dev/ulpf-witness-dev.json", "the witness's cosigning key")
	name := flag.String("name", "ulpf-witness-dev", "the witness's key name")
	trust := flag.String("trust", "keys/trust", "trust store: the logs it witnesses (*.vkey of type log)")
	state := flag.String("state", "", "state directory (the latest cosigned checkpoint per log)")
	listen := flag.String("listen", "127.0.0.1:8796", "address")
	flag.Parse()
	k, err := keys.Load(*keyPath)
	die(err)
	seed, _ := hex.DecodeString(k.PrivateKey)
	s, err := tlog.NewSigner(*name, seed, 0x04)
	die(err)
	pol, err := tlog.LoadPolicy(*trust, 0)
	die(err)
	if len(pol.Logs) == 0 {
		die(fmt.Errorf("the trust store names no log to witness"))
	}
	if *state == "" {
		die(fmt.Errorf("--state is required"))
	}
	w := &tlog.Witness{Signer: s, Logs: pol.Logs, Dir: *state}
	fmt.Fprintf(os.Stderr, "witness %s: cosigning %d log(s) on http://%s/add-checkpoint (state %s)\n", *name, len(pol.Logs), *listen, *state)
	die(http.ListenAndServe(*listen, w.Handler()))
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ulpf-witness:", err)
		os.Exit(1)
	}
}
