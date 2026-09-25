// Package canon implements Rivet's canonical view of an npm-style package
// tarball. The registry and the CLI must agree byte-for-byte on which files a
// tarball contains and on the resulting tree digest, so the rules here are
// mirrored in cli/src/core/tree.rs and pinned by a shared fixture vector.
//
// Rules (tree digest v1):
//   - the archive is gzip-compressed tar;
//   - the first path component is stripped (npm convention: "package/");
//   - only regular files are kept; directories, links, special files and
//     entries whose name ends in "/" are skipped, matching npm's pacote;
//   - paths containing "..", NUL, backslashes or absolute prefixes are rejected;
//   - a later entry with the same path replaces an earlier one;
//   - each file contributes "<path>\x00<x|->\x00<sha256 hex>\n", sorted by path,
//     where "x" marks any executable bit;
//   - the digest is "rivet-tree-v1:sha256:" + sha256 over those lines.
package canon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	MaxUnpackedBytes = 512 << 20
	MaxFileBytes     = 256 << 20
	MaxEntries       = 100_000
	TreeDigestPrefix = "rivet-tree-v1:sha256:"
)

var ErrUnsafeArchive = errors.New("unsafe package archive")

type File struct {
	Path       string
	Executable bool
	Data       []byte
}

type Package struct {
	Files      map[string]File
	TreeDigest string
}

func (p *Package) Paths() []string {
	paths := make([]string, 0, len(p.Files))
	for path := range p.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// ReadTarball parses a gzip tarball using the canonical rules above.
func ReadTarball(tgz []byte) (*Package, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, fmt.Errorf("%w: gzip: %v", ErrUnsafeArchive, err)
	}
	defer gz.Close()
	reader := tar.NewReader(io.LimitReader(gz, MaxUnpackedBytes+1))
	files := map[string]File{}
	var total int64
	entries := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar: %v", ErrUnsafeArchive, err)
		}
		entries++
		if entries > MaxEntries {
			return nil, fmt.Errorf("%w: too many entries", ErrUnsafeArchive)
		}
		if header.Typeflag != tar.TypeReg || strings.HasSuffix(header.Name, "/") {
			continue
		}
		path, ok, err := NormalizePath(header.Name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if header.Size > MaxFileBytes {
			return nil, fmt.Errorf("%w: %s exceeds file size limit", ErrUnsafeArchive, path)
		}
		total += header.Size
		if total > MaxUnpackedBytes {
			return nil, fmt.Errorf("%w: unpacked size limit exceeded", ErrUnsafeArchive)
		}
		data, err := io.ReadAll(io.LimitReader(reader, MaxFileBytes+1))
		if err != nil {
			return nil, fmt.Errorf("%w: read %s: %v", ErrUnsafeArchive, path, err)
		}
		files[path] = File{Path: path, Executable: header.Mode&0o111 != 0, Data: data}
	}
	pkg := &Package{Files: files}
	pkg.TreeDigest = TreeDigest(files)
	return pkg, nil
}

// NormalizePath strips the leading component and validates the remainder.
// ok is false for entries that have nothing left after stripping.
func NormalizePath(name string) (string, bool, error) {
	if strings.ContainsAny(name, "\x00\\") || strings.HasPrefix(name, "/") {
		return "", false, fmt.Errorf("%w: invalid path %q", ErrUnsafeArchive, name)
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 {
		return "", false, nil
	}
	out := make([]string, 0, len(parts)-1)
	for _, part := range parts[1:] {
		switch part {
		case "", ".":
			continue
		case "..":
			return "", false, fmt.Errorf("%w: path traversal in %q", ErrUnsafeArchive, name)
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return "", false, nil
	}
	return strings.Join(out, "/"), true, nil
}

func TreeDigest(files map[string]File) string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	hasher := sha256.New()
	for _, path := range paths {
		file := files[path]
		sum := sha256.Sum256(file.Data)
		mode := "-"
		if file.Executable {
			mode = "x"
		}
		hasher.Write([]byte(path))
		hasher.Write([]byte{0})
		hasher.Write([]byte(mode))
		hasher.Write([]byte{0})
		hasher.Write([]byte(hex.EncodeToString(sum[:])))
		hasher.Write([]byte{'\n'})
	}
	return TreeDigestPrefix + hex.EncodeToString(hasher.Sum(nil))
}
