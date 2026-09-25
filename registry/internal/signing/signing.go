// Package signing holds the registry's Ed25519 signing key and the envelope
// format clients verify. Signatures cover "rivet-attestation-v1\n" followed by
// the exact payload bytes, so verifiers never need to re-canonicalize JSON.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	Algorithm     = "ed25519"
	payloadDomain = "rivet-attestation-v1\n"
)

type Signer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	keyID   string
}

type PublicKey struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// Envelope is the wire format for anything the registry signs.
type Envelope struct {
	PayloadType string `json:"payload_type"`
	Payload     string `json:"payload"`
	KeyID       string `json:"keyid"`
	Signature   string `json:"signature"`
}

func NewSigner(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key seed must be %d bytes", ed25519.SeedSize)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	return &Signer{private: private, public: public, keyID: KeyID(public)}, nil
}

// LoadSigner reads a base64 seed from value, or from path, or (when
// allowGenerate) creates a new seed at path with 0600 permissions.
func LoadSigner(value, path string, allowGenerate bool) (*Signer, bool, error) {
	if value != "" {
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return nil, false, fmt.Errorf("decode signing key: %w", err)
		}
		signer, err := NewSigner(seed)
		return signer, false, err
	}
	if path == "" {
		return nil, false, errors.New("no signing key configured")
	}
	data, err := os.ReadFile(path)
	if err == nil {
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, false, fmt.Errorf("decode signing key file: %w", err)
		}
		signer, err := NewSigner(seed)
		return signer, false, err
	}
	if !errors.Is(err, os.ErrNotExist) || !allowGenerate {
		return nil, false, fmt.Errorf("read signing key file: %w", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, false, err
	}
	signer, err := NewSigner(seed)
	return signer, true, err
}

func KeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return "ed25519:" + hex.EncodeToString(sum[:])[:32]
}

func (s *Signer) KeyID() string { return s.keyID }

func (s *Signer) Public() PublicKey {
	return PublicKey{
		KeyID:     s.keyID,
		Algorithm: Algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(s.public),
	}
}

func (s *Signer) SignBytes(payload []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, append([]byte(payloadDomain), payload...)))
}

func (s *Signer) Seal(payloadType string, payload []byte) Envelope {
	return Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		KeyID:       s.keyID,
		Signature:   s.SignBytes(payload),
	}
}

func (s *Signer) VerifyBytes(payload []byte, signature string) bool {
	return Verify(s.public, payload, signature)
}

// Open verifies an envelope against this signer's public key and returns the payload.
func (s *Signer) Open(envelope Envelope) ([]byte, error) {
	if envelope.KeyID != s.keyID {
		return nil, errors.New("envelope signed by unknown key")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, err
	}
	if !s.VerifyBytes(payload, envelope.Signature) {
		return nil, errors.New("envelope signature is invalid")
	}
	return payload, nil
}

func Verify(public ed25519.PublicKey, payload []byte, signature string) bool {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(public, append([]byte(payloadDomain), payload...), raw)
}
