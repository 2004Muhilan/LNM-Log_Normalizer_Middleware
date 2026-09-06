// Package merkle is the commitment structure over sealed evidence (architecture §3.7, plan P5).
//
// Leaf (canonical, architecture):  H(0x00 || "ulpf-leaf-v1" || segment_id || offset(8 BE) || length(4 BE) || raw_event_hash)
// Node:                            H(0x01 || left || right)
// Trees are RFC 6962-style: for n > 1 leaves the split is at the largest power of two below n, so
// an unbalanced tree needs no padding leaves and a proof is a list of siblings with sides. Domain
// separation (0x00 leaf / 0x01 node, the leaf label) closes the second-preimage attack in which an
// inner node is presented as a leaf. Everything is sha256; hashes are 32 raw bytes internally and
// "sha256:<hex>" at the file boundary.
package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

const LeafDomain = "ulpf-leaf-v1"

type Hash [32]byte

func (h Hash) String() string { return "sha256:" + hex.EncodeToString(h[:]) }

// Parse accepts "sha256:<64 hex>".
func Parse(s string) (Hash, error) {
	var h Hash
	s = strings.TrimPrefix(s, "sha256:")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, errors.New("not a sha256 hash string")
	}
	copy(h[:], b)
	return h, nil
}

// Leaf is the canonical leaf hash for one evidence record.
func Leaf(segmentID string, offset int64, length int, rawHash Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write([]byte(LeafDomain))
	h.Write([]byte(segmentID))
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], uint64(offset))
	h.Write(b8[:])
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(length))
	h.Write(b4[:])
	h.Write(rawHash[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func node(l, r Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l[:])
	h.Write(r[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// Root of a list of hashes. Empty list -> the hash of the empty string under the node domain, so an
// empty commitment is distinguishable from any real one.
func Root(hs []Hash) Hash {
	switch len(hs) {
	case 0:
		var out Hash
		copy(out[:], sha256.New().Sum(nil))
		return out
	case 1:
		return hs[0]
	}
	k := split(len(hs))
	return node(Root(hs[:k]), Root(hs[k:]))
}

// split returns the largest power of two strictly less than n (n >= 2).
func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// Step is one proof element: the sibling hash and whether it sits to the left of the running hash.
type Step struct {
	Sibling Hash
	Left    bool
}

// Proof returns the inclusion proof for leaf index i in hs.
func Proof(hs []Hash, i int) ([]Step, error) {
	if i < 0 || i >= len(hs) {
		return nil, errors.New("leaf index out of range")
	}
	var steps []Step
	var walk func(hs []Hash, i int)
	walk = func(hs []Hash, i int) {
		if len(hs) == 1 {
			return
		}
		k := split(len(hs))
		if i < k {
			walk(hs[:k], i)
			steps = append(steps, Step{Sibling: Root(hs[k:]), Left: false})
		} else {
			walk(hs[k:], i-k)
			steps = append(steps, Step{Sibling: Root(hs[:k]), Left: true})
		}
	}
	walk(hs, i)
	return steps, nil
}

// Verify recomputes the root from a leaf and its proof.
func Verify(leaf Hash, proof []Step, root Hash) bool {
	h := leaf
	for _, s := range proof {
		if s.Left {
			h = node(s.Sibling, h)
		} else {
			h = node(h, s.Sibling)
		}
	}
	return h == root
}
