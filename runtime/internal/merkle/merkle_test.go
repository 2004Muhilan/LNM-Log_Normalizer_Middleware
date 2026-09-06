package merkle

import (
	"crypto/sha256"
	"testing"
)

func h(s string) Hash { return Hash(sha256.Sum256([]byte(s))) }

func TestRootAndProofsForEverySizeUpTo33(t *testing.T) {
	for n := 1; n <= 33; n++ {
		var leaves []Hash
		for i := 0; i < n; i++ {
			leaves = append(leaves, Leaf("seg_00001", int64(i*100), 100, h(string(rune('a'+i%26)))))
		}
		root := Root(leaves)
		for i := range leaves {
			p, err := Proof(leaves, i)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(leaves[i], p, root) {
				t.Fatalf("n=%d i=%d proof does not verify", n, i)
			}
			// a proof for one leaf must not verify another leaf
			other := leaves[(i+1)%n]
			if n > 1 && Verify(other, p, root) {
				t.Fatalf("n=%d i=%d proof verifies a different leaf", n, i)
			}
		}
	}
}

func TestLeafIsDomainSeparatedAndPositional(t *testing.T) {
	a := Leaf("seg_00001", 0, 10, h("x"))
	if a == Leaf("seg_00002", 0, 10, h("x")) || a == Leaf("seg_00001", 1, 10, h("x")) || a == Leaf("seg_00001", 0, 11, h("x")) || a == Leaf("seg_00001", 0, 10, h("y")) {
		t.Fatal("leaf must depend on segment, offset, length and raw hash")
	}
	// an inner node presented as a leaf hashes differently (0x00 vs 0x01 prefix)
	inner := node(a, a)
	if inner == Root([]Hash{a, a}) != true {
		t.Fatal("sanity")
	}
	if inner == a {
		t.Fatal("node collides with leaf")
	}
}

func TestEmptyRootIsDistinct(t *testing.T) {
	if Root(nil) == Root([]Hash{h("a")}) {
		t.Fatal("empty root must differ from any single-leaf root")
	}
}

func TestParseRoundTrip(t *testing.T) {
	x := h("abc")
	y, err := Parse(x.String())
	if err != nil || y != x {
		t.Fatal("round trip")
	}
	if _, err := Parse("sha256:zz"); err == nil {
		t.Fatal("bad hex accepted")
	}
}
