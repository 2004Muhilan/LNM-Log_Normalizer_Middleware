// Package keys is the file-based ed25519 key material for pack signing and checkpoint signing —
// demo-grade by decision (plan §1 "Signatures"): a key is a JSON file, a trust store is a directory
// of public-key files keyed by authority id. No key ceremony, no HSM. The same file format is read by
// the learning plane (Python `cryptography`) to sign packs and by the runtime to verify them.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// Key is a signing key file. private_key is the 32-byte ed25519 seed (hex); public_key 32 bytes (hex).
type Key struct {
	AuthorityID string `json:"authority_id"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key,omitempty"`
}

// Generate a new key for an authority.
func Generate(authorityID string) (Key, error) {
	if !slug.MatchString(authorityID) {
		return Key{}, errors.New("authority_id must be a slug")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	return Key{AuthorityID: authorityID, Algorithm: "ed25519", PublicKey: hex.EncodeToString(pub), PrivateKey: hex.EncodeToString(priv.Seed())}, nil
}

func Load(path string) (Key, error) {
	var k Key
	b, err := os.ReadFile(path)
	if err != nil {
		return k, err
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return k, fmt.Errorf("%s: %w", path, err)
	}
	if k.Algorithm != "ed25519" || !slug.MatchString(k.AuthorityID) {
		return k, fmt.Errorf("%s: not an ed25519 key file", path)
	}
	if _, err := k.Public(); err != nil {
		return k, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

func (k Key) Public() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(k.PublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("bad public key")
	}
	return ed25519.PublicKey(b), nil
}

func (k Key) private() (ed25519.PrivateKey, error) {
	if k.PrivateKey == "" {
		return nil, errors.New("key file has no private key")
	}
	seed, err := hex.DecodeString(k.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("bad private key seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := k.Public()
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		return nil, errors.New("public key does not match private key")
	}
	return priv, nil
}

// Sign returns the ed25519 signature over msg as hex.
func (k Key) Sign(msg []byte) (string, error) {
	priv, err := k.private()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(priv, msg)), nil
}

// PublicOnly strips the private half for a trust-store file.
func (k Key) PublicOnly() Key {
	return Key{AuthorityID: k.AuthorityID, Algorithm: k.Algorithm, PublicKey: k.PublicKey}
}

// Save writes the key file (0600 when it holds a private key).
func (k Key) Save(path string) error {
	b, _ := json.MarshalIndent(k, "", "  ")
	mode := os.FileMode(0o644)
	if k.PrivateKey != "" {
		mode = 0o600
	}
	return os.WriteFile(path, append(b, '\n'), mode)
}

// TrustStore is a directory of <authority_id>.pub.json files.
type TrustStore struct{ Dir string }

func (t TrustStore) Lookup(authorityID string) (ed25519.PublicKey, error) {
	if !slug.MatchString(authorityID) {
		return nil, errors.New("authority_id must be a slug")
	}
	k, err := Load(filepath.Join(t.Dir, authorityID+".pub.json"))
	if err != nil {
		return nil, fmt.Errorf("authority %q is not in the trust store %s: %w", authorityID, t.Dir, err)
	}
	if k.AuthorityID != authorityID {
		return nil, fmt.Errorf("trust store file for %q names authority %q", authorityID, k.AuthorityID)
	}
	return k.Public()
}

// Verify checks a hex signature over msg by the named authority.
func (t TrustStore) Verify(authorityID string, msg []byte, sigHex string) error {
	pub, err := t.Lookup(authorityID)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("signature is not 64 bytes of hex")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("signature by %q does not verify over these bytes", authorityID)
	}
	return nil
}
