package artifacts

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaxArtifactBytes bounds a single uploaded artifact.
const MaxArtifactBytes = 256 << 20

var (
	ErrInvalidHash  = errors.New("invalid artifact hash")
	ErrHashMismatch = errors.New("artifact content does not match its hash")
	ErrTooLarge     = errors.New("artifact exceeds size limit")
)

// FileStore is content-addressed: an artifact is only stored under the
// sha512 of its bytes, which the store computes itself.
type FileStore struct {
	root string
}

func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, errors.New("artifact root is required")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &FileStore{root: root}, nil
}

// Hash returns the canonical Rivet artifact hash for data.
func Hash(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512-" + hex.EncodeToString(sum[:])
}

// Put stores body under hash after verifying that sha512(body) == hash.
func (s *FileStore) Put(hash string, body io.Reader) (string, error) {
	path, err := s.path(hash)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	hasher := sha512.New()
	written, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(body, MaxArtifactBytes+1))
	closeErr := tmp.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if written > MaxArtifactBytes {
		return "", ErrTooLarge
	}
	if "sha512-"+hex.EncodeToString(hasher.Sum(nil)) != hash {
		return "", ErrHashMismatch
	}
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if err := os.Chmod(tmp.Name(), 0o444); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

// PutBytes stores data under its computed hash.
func (s *FileStore) PutBytes(data []byte) (string, string, error) {
	hash := Hash(data)
	path, err := s.Put(hash, bytes.NewReader(data))
	return hash, path, err
}

func (s *FileStore) Get(hash string) (*os.File, error) {
	path, err := s.path(hash)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (s *FileStore) Read(hash string) ([]byte, error) {
	path, err := s.path(hash)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if Hash(data) != hash {
		return nil, fmt.Errorf("%w: stored artifact %s is corrupt", ErrHashMismatch, hash)
	}
	return data, nil
}

func (s *FileStore) Path(hash string) (string, error) {
	return s.path(hash)
}

func (s *FileStore) path(hash string) (string, error) {
	hexPart, ok := strings.CutPrefix(hash, "sha512-")
	if !ok || len(hexPart) != 128 {
		return "", ErrInvalidHash
	}
	if _, err := hex.DecodeString(hexPart); err != nil || strings.ToLower(hexPart) != hexPart {
		return "", ErrInvalidHash
	}
	return filepath.Join(s.root, hexPart[:2], hexPart[2:4], hash+".tgz"), nil
}
