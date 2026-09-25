package audit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usharma123/rivet/registry/internal/canon"
	"github.com/usharma123/rivet/registry/internal/registry"
)

const fixturesDir = "../../../fixtures/packages"

func packDir(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		info, _ := entry.Info()
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + filepath.ToSlash(rel), Mode: int64(info.Mode().Perm()), Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestFixtureVerdicts(t *testing.T) {
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatal(err)
	}
	pipeline := &Pipeline{Signer: testSigner(t, 3)}
	for _, entry := range entries {
		dir := filepath.Join(fixturesDir, entry.Name())
		var manifest struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Fixture struct {
				ExpectedVerdict string `json:"expectedVerdict"`
				ExpectedState   string `json:"expectedState"`
			} `json:"rivetFixture"`
		}
		data, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil {
			continue
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		t.Run(entry.Name(), func(t *testing.T) {
			pkg, err := canon.ReadTarball(packDir(t, dir))
			if err != nil {
				t.Fatal(err)
			}
			record, err := pipeline.Audit(context.Background(), Input{
				Version: registry.VersionRecord{Name: manifest.Name, Version: manifest.Version},
				Package: pkg,
			})
			if err != nil {
				t.Fatal(err)
			}
			if string(record.Verdict) != manifest.Fixture.ExpectedVerdict {
				t.Fatalf("verdict %s (score %d, reasons %s), want %s", record.Verdict, record.RiskScore, record.Reasons, manifest.Fixture.ExpectedVerdict)
			}
			if got := registry.StateForVerdict(record.Verdict); string(got) != manifest.Fixture.ExpectedState {
				t.Fatalf("state %s, want %s", got, manifest.Fixture.ExpectedState)
			}
			if !VerifyAuditSignature(record, pipeline.Signer) {
				t.Fatal("pipeline produced an unverifiable audit")
			}
		})
	}
}

func TestCredentialStealerCapabilities(t *testing.T) {
	pkg, err := canon.ReadTarball(packDir(t, filepath.Join(fixturesDir, "credential-stealer")))
	if err != nil {
		t.Fatal(err)
	}
	static := AnalyzeStatic(pkg)
	for _, capability := range []string{CapNetwork, CapSensitivePaths, CapEnvHarvest, CapExfilEndpoint, CapExfilPattern} {
		if len(static.Capabilities[capability]) == 0 {
			t.Errorf("expected capability %s, got %v", capability, static.CapabilityNames())
		}
	}
}

func TestDiffFlagsCompromisedRelease(t *testing.T) {
	previous := StaticEvidence{Capabilities: map[string][]string{CapFSWrite: {"index.js"}}}
	current := StaticEvidence{
		Capabilities:      map[string][]string{CapFSWrite: {"index.js"}, CapNetwork: {"index.js"}, CapChildProcess: {"setup.js"}},
		HasInstallScripts: true,
		InstallScripts:    []string{"postinstall"},
		SourceRepo:        "https://github.com/example/pkg",
	}
	diff := Diff("1.0.0", previous, current, map[string]string{"a": "^1"}, map[string]string{"a": "^1", "b": "^2"})
	diff.ProvenanceRegressed = true
	diff.PublisherChanged = true
	diff.PreviousPublisher = "maintainer"
	score := ScoreEvidence(Evidence{Static: current, Diff: diff, Upstream: &UpstreamEvidence{Publisher: "attacker"}})
	if score.Verdict != registry.VerdictCritical {
		t.Fatalf("expected critical, got %s (%d): %v", score.Verdict, score.RiskScore, score.Reasons)
	}
	joined := strings.Join(score.Reasons, "\n")
	for _, want := range []string{"had provenance", "install script added", "new capabilities", "published by"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing reason %q in %s", want, joined)
		}
	}
	// The same capabilities without any change stay low: most packages use
	// the network or child processes legitimately.
	steady := ScoreEvidence(Evidence{Static: StaticEvidence{Capabilities: current.Capabilities, SourceRepo: "x"}})
	if steady.Verdict != registry.VerdictLow {
		t.Fatalf("unchanged capabilities should be low, got %s %v", steady.Verdict, steady.Reasons)
	}
}

func TestProvenanceMismatchAndInvalid(t *testing.T) {
	no := false
	score := ScoreEvidence(Evidence{Static: StaticEvidence{SourceRepo: "x"}, Provenance: &ProvenanceEvidence{Status: "invalid", Detail: "bad signature"}})
	if score.Verdict != registry.VerdictHigh {
		t.Fatalf("invalid provenance should be high, got %s", score.Verdict)
	}
	score = ScoreEvidence(Evidence{Static: StaticEvidence{SourceRepo: "x"}, Provenance: &ProvenanceEvidence{Status: "verified", RepoMatches: &no}})
	if score.Verdict != registry.VerdictMedium {
		t.Fatalf("repo mismatch should be medium, got %s", score.Verdict)
	}
}

func TestNamesquat(t *testing.T) {
	for name, want := range map[string]bool{"lodash": false, "l0dash": true, "lodahs": true, "expres": true, "react": false, "preact": false, "my-internal-tool": false, "is-0dd": true} {
		if got := NamesquatWarning(name) != ""; got != want {
			t.Errorf("NamesquatWarning(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestNodeAgentDetectsHoneytokenTheft runs the dynamic agent outside the
// sandbox against the credential-stealer fixture. The fixture only targets a
// .invalid host, so no traffic can leave the machine.
func TestNodeAgentDetectsHoneytokenTheft(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	work := t.TempDir()
	artifact := filepath.Join(work, "package.tgz")
	if err := os.WriteFile(artifact, packDir(t, filepath.Join(fixturesDir, "credential-stealer")), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", "../../../audit-agent/agent.js")
	cmd.Env = append(os.Environ(),
		"RIVET_ARTIFACT_PATH="+artifact,
		"RIVET_EVIDENCE_DIR="+filepath.Join(work, "evidence"),
		"RIVET_WORK_DIR="+filepath.Join(work, "run"),
		"RIVET_SAFE_TIMEOUT_MS=10000",
		"RIVET_ADVERSARIAL_TIMEOUT_MS=10000",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("agent failed: %v\n%s", err, out)
	}
	evidence, err := readEvidence(filepath.Join(work, "evidence", "evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Honeytokens) == 0 {
		t.Fatalf("expected honeytoken access, got %+v", evidence)
	}
	sawEgress := false
	for _, egress := range evidence.Egress {
		if strings.Contains(egress.Host, "webhook.site.invalid") {
			sawEgress = true
		}
	}
	if !sawEgress {
		t.Fatalf("expected egress to webhook.site.invalid, got %+v", evidence.Egress)
	}
	score := ScoreEvidence(Evidence{Static: StaticEvidence{SourceRepo: "x"}, Egress: evidence.Egress, Honeytokens: evidence.Honeytokens})
	if score.Verdict != registry.VerdictCritical {
		t.Fatalf("dynamic evidence alone should be critical, got %s %v", score.Verdict, score.Reasons)
	}
}

func TestDockerArgsDenyNetwork(t *testing.T) {
	args := strings.Join(NewDockerRunner("").Args(registry.VersionRecord{Name: "a", Version: "1.0.0"}, "/a.tgz", "/out"), " ")
	for _, want := range []string{"--runtime=runsc", "--network=none", "--read-only", "--cap-drop=ALL", "a.tgz:/artifact/package:ro", "manifest.json:/audit/manifest.json:ro"} {
		if !strings.Contains(args, want) {
			t.Errorf("docker args missing %s: %s", want, args)
		}
	}
	for _, forbidden := range []string{"host-gateway", "PROXY", "TOKEN"} {
		if strings.Contains(args, forbidden) {
			t.Errorf("docker args must not contain %s: %s", forbidden, args)
		}
	}
}

func TestNativeManifestWithoutPackageJSONIsAuditedAndProbed(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	work := t.TempDir()
	canonical := filepath.Join(work, "canonical")
	if err := os.MkdirAll(filepath.Join(canonical, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(canonical, "bin", "tool.js"), []byte("console.log('native bin')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := registry.PackageManifest{Name: "native-demo", Version: "1.0.0", Bin: map[string]string{"native-tool": "bin/tool.js"}, InstallScripts: map[string]string{"postinstall": "echo curl https://example.invalid/install"}}
	manifestJSON, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(work, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := &canon.Package{Files: map[string]canon.File{"bin/tool.js": {Path: "bin/tool.js", Data: []byte("console.log('native bin')\n")}}}
	static := AnalyzeStaticWithManifest(pkg, &manifest)
	if !static.HasInstallScripts || len(static.SuspiciousScripts) == 0 {
		t.Fatalf("native script was not scored: %+v", static)
	}
	cmd := exec.Command("node", "../../../audit-agent/agent.js")
	cmd.Env = append(os.Environ(), "RIVET_CANONICAL_PACKAGE_DIR="+canonical, "RIVET_MANIFEST_PATH="+manifestPath, "RIVET_EVIDENCE_DIR="+filepath.Join(work, "evidence"), "RIVET_WORK_DIR="+filepath.Join(work, "run"), "RIVET_SAFE_TIMEOUT_MS=5000", "RIVET_ADVERSARIAL_TIMEOUT_MS=5000")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("agent failed: %v\n%s", err, out)
	}
	evidence, err := readEvidence(filepath.Join(work, "evidence", "evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Agent["complete"] != "true" {
		t.Fatalf("agent did not complete: %+v", evidence.Agent)
	}
	foundScript, foundBin := false, false
	for _, probe := range evidence.Adversarial {
		if probe.Name == "script:postinstall" {
			foundScript = true
		}
	}
	for _, probe := range evidence.SafeProbes {
		if probe.Name == "help:native-tool" {
			foundBin = true
		}
	}
	if !foundScript || !foundBin {
		t.Fatalf("native metadata omitted from probes: %+v", evidence)
	}
}

type forgedSandbox struct{}

func (forgedSandbox) Runtime() string { return registry.SandboxGVisor }
func (forgedSandbox) Image() string   { return "forged-test" }
func (forgedSandbox) Run(context.Context, registry.VersionRecord, string) (Evidence, error) {
	return Evidence{Egress: []EgressEvidence{{Host: "forged.example", Decision: "blocked"}}, Honeytokens: []HoneytokenAccess{{Token: "fake"}}, Agent: map[string]string{"complete": "true"}}, nil
}

func TestPackageWritableDynamicEvidenceCannotCertifyGVisorPass(t *testing.T) {
	pkg, err := canon.ReadTarball(tgzFiles(t, map[string]string{"package.json": `{"name":"demo","version":"1.0.0"}`, "index.js": "module.exports = 1"}))
	if err != nil {
		t.Fatal(err)
	}
	pipeline := &Pipeline{Signer: testSigner(t, 7), Sandbox: forgedSandbox{}}
	record, err := pipeline.Audit(context.Background(), Input{Version: registry.VersionRecord{Name: "demo", Version: "1.0.0"}, Package: pkg})
	if err != nil {
		t.Fatal(err)
	}
	if record.SandboxRuntime != registry.SandboxStatic {
		t.Fatalf("untrusted probe certified as %s", record.SandboxRuntime)
	}
	var evidence Evidence
	if err := json.Unmarshal(record.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Sandbox["observations"] != "package-tamperable" {
		t.Fatalf("missing trust limit: %+v", evidence.Sandbox)
	}
}

func TestEmbeddedBlobIsNotObfuscation(t *testing.T) {
	wasm := "const wasm = \"" + strings.Repeat("AGFzbQEAAAAB", 400) + "\";\n"
	pkg, err := canon.ReadTarball(tgzFiles(t, map[string]string{"package.json": `{"name":"parser","repository":"x"}`, "index.js": wasm}))
	if err != nil {
		t.Fatal(err)
	}
	static := AnalyzeStatic(pkg)
	if len(static.Capabilities[CapEmbeddedBlob]) == 0 || len(static.Capabilities[CapObfuscation]) != 0 {
		t.Fatalf("expected embedded blob without obfuscation: %v", static.CapabilityNames())
	}
	if score := ScoreEvidence(Evidence{Static: static}); score.RiskScore != 0 {
		t.Fatalf("a steady embedded blob should not add risk: %v", score.Reasons)
	}
}

func tgzFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}
