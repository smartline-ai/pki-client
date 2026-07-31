package pkiclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadOrCreateKey returns the existing key or creates a new one.
//
// Reusing the existing one is not an optimisation, it is what makes the retry
// path correct: if the node died between the moment the CP burned the token
// and the moment it wrote the certificate, the second attempt has to present
// the same public key. Otherwise the CP sees a foreign key against a burned
// token and refuses.
//
// The same holds within a single run: if two first callers start at once (a
// cold-start race), both pass the "no file" check and both generate THEIR OWN
// keys. Only one of them lands on disk — but without the guard below the loser
// would hand the caller a key that is no longer on disk, diverging from what
// was actually stored. CreateFileExclusive guarantees that publishing to path
// happens exactly once; the loser does not invent an error out of that, it
// reads whatever actually won.
func LoadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return parseECKey(path, raw)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("pkiclient: reading %s: %w", path, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: generating key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: serialising key: %w", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	if err := CreateFileExclusive(path, body, 0o600); err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("pkiclient: storing key %s: %w", path, err)
		}
		// We lost the race: between our ReadFile and the publish attempt
		// someone else created path. Our key is thrown away entirely — it
		// never touched the disk — and we read what actually ended up there.
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("pkiclient: reading %s after losing the race to create the key: %w", path, err)
		}
		return parseECKey(path, raw)
	}
	return key, nil
}

func parseECKey(path string, raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("pkiclient: %s contains no PEM key", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: parsing key %s: %w", path, err)
	}
	return key, nil
}
