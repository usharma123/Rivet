package canon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"strings"
	"testing"
)

// The expected digest is shared with cli/src/core/tree.rs; if this changes,
// the CLI and registry disagree about package contents.
func TestTreeVectorMatchesSharedFixture(t *testing.T) {
	data, err := os.ReadFile("../../../fixtures/tarballs/tree-vector.tgz")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("../../../fixtures/tarballs/tree-vector.digest")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := ReadTarball(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(pkg.Paths(), ","); got != "README.md,bin/tv.js,lib/a.js,lib/b.js,package.json" {
		t.Fatalf("unexpected paths: %s", got)
	}
	if string(pkg.Files["lib/a.js"].Data) != "module.exports = 2\n" {
		t.Fatal("later duplicate entry should win")
	}
	if !pkg.Files["bin/tv.js"].Executable || pkg.Files["lib/a.js"].Executable {
		t.Fatal("executable bits not preserved")
	}
	if pkg.TreeDigest != strings.TrimSpace(string(expected)) {
		t.Fatalf("tree digest %s does not match fixture %s", pkg.TreeDigest, strings.TrimSpace(string(expected)))
	}
}

func tgz(t *testing.T, entries ...tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, header := range entries {
		body := []byte("x")
		header.Size = int64(len(body))
		if header.Typeflag == 0 {
			header.Typeflag = tar.TypeReg
		}
		if header.Typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			_, _ = tw.Write(body)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestRejectsTraversalAndAbsolutePaths(t *testing.T) {
	for _, name := range []string{"package/../../etc/passwd", "/package/x.js", `package\x.js`} {
		_, err := ReadTarball(tgz(t, tar.Header{Name: name, Mode: 0o644}))
		if !errors.Is(err, ErrUnsafeArchive) {
			t.Fatalf("%s: expected unsafe archive, got %v", name, err)
		}
	}
}

func TestSkipsLinksAndStripsFirstComponent(t *testing.T) {
	pkg, err := ReadTarball(tgz(t,
		tar.Header{Name: "node-v1/index.js", Mode: 0o644},
		tar.Header{Name: "node-v1/evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		tar.Header{Name: "node-v1/hard", Typeflag: tar.TypeLink, Linkname: "node-v1/index.js"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pkg.Paths(), ",") != "index.js" {
		t.Fatalf("unexpected files %v", pkg.Paths())
	}
}

func TestRejectsNonGzip(t *testing.T) {
	if _, err := ReadTarball([]byte("not a tarball")); !errors.Is(err, ErrUnsafeArchive) {
		t.Fatalf("expected unsafe archive, got %v", err)
	}
}
