package artifacts

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

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

func (s *FileStore) Put(hash string, body io.Reader) (string, error) {
	path, err := s.path(hash)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(file, body); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}

func (s *FileStore) Get(hash string) (*os.File, error) {
	path, err := s.path(hash)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (s *FileStore) Path(hash string) (string, error) {
	return s.path(hash)
}

func (s *FileStore) path(hash string) (string, error) {
	if hash == "" || strings.Contains(hash, "..") || strings.ContainsAny(hash, `/\`) {
		return "", errors.New("invalid artifact hash")
	}
	prefix := hash
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	return filepath.Join(s.root, prefix, hash+".tgz"), nil
}
