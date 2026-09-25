package npm

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	in_toto "github.com/in-toto/attestation/go/v1"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func packument() *Packument {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	versions := map[string]VersionMeta{}
	times := map[string]string{}
	for version, age := range map[string]time.Duration{
		"1.0.0":        400 * 24 * time.Hour,
		"1.1.0":        200 * 24 * time.Hour,
		"1.2.0":        30 * 24 * time.Hour,
		"1.3.0":        2 * time.Hour,
		"2.0.0-beta.1": 10 * 24 * time.Hour,
		"2.0.0":        5 * 24 * time.Hour,
	} {
		versions[version] = VersionMeta{Name: "demo", Version: version}
		times[version] = now.Add(-age).Format(time.RFC3339)
	}
	return &Packument{
		Name:     "demo",
		DistTags: map[string]string{"latest": "1.3.0", "next": "2.0.0-beta.1"},
		Versions: versions,
		Time:     times,
	}
}

var testNow = time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)

func TestSelectRanges(t *testing.T) {
	p := packument()
	cases := map[string]string{
		"^1.0.0":           "1.3.0",
		"~1.1.0":           "1.1.0",
		"1.x":              "1.3.0",
		">=1.0.0 <1.2.0":   "1.1.0",
		"1.0.0 - 1.2.0":    "1.2.0",
		"*":                "2.0.0",
		"":                 "2.0.0",
		"^1.0.0 || ^2.0.0": "2.0.0",
		"1.1.0":            "1.1.0",
		"latest":           "1.3.0",
		"next":             "2.0.0-beta.1",
	}
	for spec, want := range cases {
		got, err := Select(p, spec, SelectOptions{Now: testNow})
		if err != nil || got.Version != want {
			t.Errorf("Select(%q) = %q, %v; want %q", spec, got.Version, err, want)
		}
	}
}

func TestSelectCooldownSkipsFreshReleases(t *testing.T) {
	p := packument()
	got, err := Select(p, "^1.0.0", SelectOptions{Now: testNow, MinAge: 72 * time.Hour})
	if err != nil || got.Version != "1.2.0" {
		t.Fatalf("expected cooldown to fall back to 1.2.0, got %q %v", got.Version, err)
	}
	if len(got.Skipped) == 0 || !strings.Contains(got.Skipped[0], "1.3.0") {
		t.Fatalf("expected 1.3.0 to be reported as skipped: %v", got.Skipped)
	}
	// A dist-tag inside the cooldown falls back to the newest older release.
	got, err = Select(p, "latest", SelectOptions{Now: testNow, MinAge: 72 * time.Hour})
	if err != nil || got.Version != "1.2.0" {
		t.Fatalf("expected latest to fall back to 1.2.0, got %q %v", got.Version, err)
	}
	if _, err := Select(p, "1.3.0", SelectOptions{Now: testNow, MinAge: 72 * time.Hour}); err == nil {
		t.Fatal("expected exact pin inside cooldown to fail")
	}
}

func TestSelectPreferAndExclude(t *testing.T) {
	p := packument()
	got, err := Select(p, "^1.0.0", SelectOptions{Now: testNow, Prefer: []string{"1.1.0"}})
	if err != nil || got.Version != "1.1.0" {
		t.Fatalf("expected preferred 1.1.0, got %q %v", got.Version, err)
	}
	got, err = Select(p, "^1.0.0", SelectOptions{Now: testNow, Exclude: func(v string) (bool, string) {
		return v == "1.3.0", "release is blocked"
	}})
	if err != nil || got.Version != "1.2.0" {
		t.Fatalf("expected blocked 1.3.0 to be skipped, got %q %v", got.Version, err)
	}
}

func TestCheckSpecRejectsNonRegistrySources(t *testing.T) {
	for _, spec := range []string{"git+https://github.com/a/b.git", "github:a/b", "a/b", "file:../x", "https://evil.example/x.tgz", "npm:other@1"} {
		if err := CheckSpec(spec); !errors.Is(err, ErrUnsupportedSpec) {
			t.Errorf("CheckSpec(%q) = %v, want unsupported", spec, err)
		}
	}
	for _, spec := range []string{"^1.2.3", ">=1 <2", "latest", "1.x || 2.x"} {
		if err := CheckSpec(spec); err != nil {
			t.Errorf("CheckSpec(%q) = %v", spec, err)
		}
	}
}

func TestPreviousVersion(t *testing.T) {
	if got := PreviousVersion(packument(), "2.0.0"); got != "1.3.0" {
		t.Fatalf("expected 1.3.0, got %s", got)
	}
	if got := PreviousVersion(packument(), "1.0.0"); got != "" {
		t.Fatalf("expected no previous version, got %s", got)
	}
}

func TestVerifyIntegrity(t *testing.T) {
	data := []byte("tarball")
	sum512 := sha512.Sum512(data)
	sum1 := sha1.Sum(data)
	good := Dist{Integrity: "sha512-" + base64.StdEncoding.EncodeToString(sum512[:])}
	if algo, err := VerifyIntegrity(data, good); err != nil || algo != "sha512" {
		t.Fatalf("sha512: %s %v", algo, err)
	}
	if _, err := VerifyIntegrity([]byte("tampered"), good); !errors.Is(err, ErrIntegrity) {
		t.Fatal("tampered sha512 accepted")
	}
	legacy := Dist{Integrity: "sha1-abc", Shasum: hex.EncodeToString(sum1[:])}
	if algo, err := VerifyIntegrity(data, legacy); err != nil || algo != "sha1" {
		t.Fatalf("sha1 fallback: %s %v", algo, err)
	}
	if _, err := VerifyIntegrity([]byte("tampered"), legacy); !errors.Is(err, ErrIntegrity) {
		t.Fatal("tampered sha1 accepted")
	}
	if _, err := VerifyIntegrity(data, Dist{Integrity: "md5-xyz"}); !errors.Is(err, ErrIntegrity) {
		t.Fatal("tarball with no usable digest must be rejected, not skipped")
	}
}

func TestValidName(t *testing.T) {
	for _, name := range []string{"react", "@babel/core", "lodash.merge", "a-b_c"} {
		if !ValidName(name) {
			t.Errorf("%s should be valid", name)
		}
	}
	for _, name := range []string{"", "../etc", "a/b", "@scope", "@scope/a/b", "@scope/..", "@../pkg", ".hidden", " spaced", "a%2f"} {
		if ValidName(name) {
			t.Errorf("%q should be invalid", name)
		}
	}
}

func TestBinNamesRejectShellSyntax(t *testing.T) {
	for _, command := range []string{"ok\ntouch PWN\n#", "bad\rname", "-option", "a/b", "x;touch"} {
		if ValidCommand(command) {
			t.Fatalf("accepted unsafe command %q", command)
		}
	}
	if got := BinEntries("demo", []byte(`{"ok\ntouch PWN\n#":"bin/x.js","safe":"bin/s.js"}`)); len(got) != 1 || got["safe"] != "bin/s.js" {
		t.Fatalf("unsafe bin survived normalization: %v", got)
	}
}

func TestRestrictedFetchesDoNotFollowCrossHostRedirects(t *testing.T) {
	contacted := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contacted = true; w.WriteHeader(http.StatusOK) }))
	defer other.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer upstream.Close()
	client, err := NewClient(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Tarball(context.Background(), VersionMeta{Dist: Dist{Tarball: upstream.URL + "/pkg.tgz"}}); err == nil {
		t.Fatal("tarball redirect accepted")
	}
	var out any
	if err := client.FetchJSON(context.Background(), upstream.URL+"/attestations", 1024, &out); err == nil {
		t.Fatal("attestation redirect accepted")
	}
	if contacted {
		t.Fatal("redirect target received a request")
	}
}

func TestProvenanceRequiresNameAndDigestOnSameSubject(t *testing.T) {
	subjects := []*in_toto.ResourceDescriptor{
		{Name: "pkg:npm/demo@1.0.0", Digest: map[string]string{"sha512": "other"}},
		{Name: "pkg:npm/unrelated@9.0.0", Digest: map[string]string{"sha512": "actual"}},
	}
	if subjectBindsArtifact(subjects, "pkg:npm/demo@1.0.0", "actual") {
		t.Fatal("pooled subjects accepted")
	}
	subjects[0].Digest["sha512"] = "actual"
	if !subjectBindsArtifact(subjects, "pkg:npm/demo@1.0.0", "actual") {
		t.Fatal("matching subject rejected")
	}
	if supportedSLSA("https://example.com/not-slsa") {
		t.Fatal("unsupported predicate accepted")
	}
}

func TestSameRepository(t *testing.T) {
	if !SameRepository("git+https://github.com/npm/node-semver.git", "https://github.com/npm/node-semver") {
		t.Fatal("expected equivalent repos to match")
	}
	if !SameRepository("github:npm/node-semver", "git@github.com:npm/node-semver.git") {
		t.Fatal("expected shorthand and ssh to match")
	}
	if SameRepository("https://github.com/npm/node-semver", "https://github.com/evil/node-semver") {
		t.Fatal("different owners must not match")
	}
}

// TestLiveProvenance verifies a real npm package with Sigstore provenance.
// It needs network access, so it only runs with RIVET_NETWORK_TESTS=1.
func TestLiveProvenance(t *testing.T) {
	if os.Getenv("RIVET_NETWORK_TESTS") != "1" {
		t.Skip("set RIVET_NETWORK_TESTS=1 to run")
	}
	client, err := NewClient(DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p, err := client.Packument(ctx, "semver")
	if err != nil {
		t.Fatal(err)
	}
	meta := p.Versions["7.7.2"]
	tarball, algo, err := client.Tarball(ctx, meta)
	if err != nil || algo != "sha512" {
		t.Fatalf("tarball: %v %s", err, algo)
	}
	verifier := NewProvenanceVerifier(client)
	result := verifier.Verify(ctx, meta, tarball)
	if result.Status != ProvenanceVerified {
		t.Fatalf("expected verified provenance, got %s: %s", result.Status, result.Detail)
	}
	if !SameRepository(result.SourceRepo, "https://github.com/npm/node-semver") || result.RepoMatches == nil || !*result.RepoMatches {
		t.Fatalf("unexpected source repo %s (matches=%v)", result.SourceRepo, result.RepoMatches)
	}
	// The same bundle must not verify for different bytes.
	tampered := append([]byte{}, tarball...)
	tampered[len(tampered)-1] ^= 0xff
	if bad := verifier.Verify(ctx, meta, tampered); bad.Status != ProvenanceInvalid {
		t.Fatalf("tampered tarball should fail provenance, got %s", bad.Status)
	}
}
