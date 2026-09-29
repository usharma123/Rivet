package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usharma123/rivet/registry/internal/canon"
	"github.com/usharma123/rivet/registry/internal/registry"
)

func TestTraceValidationRejectsInvalidReports(t *testing.T) {
	id := strings.Repeat("a", 64)
	good := traceReport{ContainerID: id, Nonce: "fresh", Started: true, Completed: true, Complete: true, PackageEvents: 4, Execs: 1, Packets: 5, Bytes: 100}
	if err := validateTraceReport(good, id, "fresh"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*traceReport){
		"container":           func(r *traceReport) { r.ContainerID = strings.Repeat("b", 64) },
		"nonce":               func(r *traceReport) { r.Nonce = "stale" },
		"start":               func(r *traceReport) { r.Started = false },
		"marker":              func(r *traceReport) { r.Completed = false },
		"complete":            func(r *traceReport) { r.Complete = false },
		"negative execs":      func(r *traceReport) { r.Execs = -1 },
		"large execs":         func(r *traceReport) { r.Execs = 5 },
		"large package count": func(r *traceReport) { r.PackageEvents = 6 },
		"unresolved path":     func(r *traceReport) { r.UnresolvedOpens = 1 },
		"foreign honey path":  func(r *traceReport) { r.HoneyPaths = []string{"/evidence/release"} },
		"large honey list":    func(r *traceReport) { r.HoneyPaths = make([]string, 33) },
		"negative network":    func(r *traceReport) { r.NetworkAttempts = -1 },
		"large bytes":         func(r *traceReport) { r.Bytes = 8*1024*1024 + 1 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := good
			change(&r)
			if validateTraceReport(r, id, "fresh") == nil {
				t.Fatal("accepted invalid report")
			}
		})
	}
	for name, listing := range map[string]string{
		"dropped":   "SESSIONS (1)\n\"Default\"\nSink: \"remote\", dropped: 1\n",
		"missing":   "SESSIONS (0)\n",
		"duplicate": "SESSIONS (1)\n\"Default\"\nSink: \"remote\", dropped: 0\nSink: \"remote\", dropped: 0\n",
	} {
		t.Run(name, func(t *testing.T) {
			if validateTraceList(listing) == nil {
				t.Fatal("accepted invalid trace status")
			}
		})
	}
}

// Run inside the disposable DinD daemon with built audit images and runsc.
func TestDockerRunnerLive(t *testing.T) {
	if os.Getenv("RIVET_AUDIT_LIVE") != "1" {
		t.Skip("requires isolated gVisor Docker daemon")
	}
	manifest := registry.PackageManifest{Name: "trusted-audit-probe", Version: "1.0.0", InstallScripts: map[string]string{"postinstall": "cat \"$HOME/.npmrc\" >/dev/null; busybox wget -q -T 1 -O /dev/null http://127.0.0.1:9 || true"}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	artifact := tgzFiles(t, map[string]string{"package.json": `{"name":"trusted-audit-probe","version":"1.0.0"}`, "index.js": "module.exports = 1;\n"})
	path := filepath.Join(t.TempDir(), "package.tgz")
	if err := os.WriteFile(path, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	pkg, err := canon.ReadTarball(artifact)
	if err != nil {
		t.Fatal(err)
	}
	version := registry.VersionRecord{Name: manifest.Name, Version: manifest.Version, ArtifactHash: "sha512-" + sha512Hex(artifact), TreeDigest: pkg.TreeDigest, Manifest: manifestBytes}
	runner := NewDockerRunner("rivet-audit-agent:local")
	runner.RunscBin = "/runsc/runsc"
	if helper := os.Getenv("RIVET_AUDIT_TEST_RUNSC_BIN"); helper != "" {
		runner.RunscBin = helper
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pipeline := &Pipeline{Signer: testSigner(t, 31), Sandbox: runner}
	record, err := pipeline.Audit(ctx, Input{Version: version, Package: pkg, ArtifactPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if record.SandboxRuntime != registry.SandboxGVisor {
		t.Fatalf("sandbox: %s", record.SandboxRuntime)
	}
	if !VerifyAuditSignature(record, pipeline.Signer) {
		t.Fatal("audit signature invalid")
	}
	var evidence Evidence
	if err := json.Unmarshal(record.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Sandbox["artifact_hash"] != version.ArtifactHash || evidence.Sandbox["tree_digest"] != version.TreeDigest || evidence.Sandbox["manifest_sha512"] != sha512Hex(manifestBytes) {
		t.Fatalf("input bindings missing: %+v", evidence.Sandbox)
	}
	if len(evidence.Honeytokens) == 0 || len(evidence.Egress) == 0 {
		t.Fatalf("kernel observations missing: %+v", evidence)
	}
}

func TestTrustedTraceBindsCurrentInput(t *testing.T) {
	artifact := tgzFiles(t, map[string]string{"package.json": `{"name":"bound","version":"1.0.0"}`, "index.js": "module.exports = 1;\n"})
	pkg, err := canon.ReadTarball(artifact)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "package.tgz")
	if err := os.WriteFile(path, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"name":"bound","version":"1.0.0"}`)
	in := Input{Version: registry.VersionRecord{Name: "bound", Version: "1.0.0", ArtifactHash: "sha512-" + sha512Hex(artifact), TreeDigest: pkg.TreeDigest, Manifest: manifest}, Package: pkg, ArtifactPath: path}
	trace := &validatedTrace{containerID: strings.Repeat("a", 64), nonce: "fresh", packageName: "bound", version: "1.0.0", artifactHash: in.Version.ArtifactHash, treeDigest: pkg.TreeDigest, manifestHash: sha512Hex(manifest)}
	if err := validateTrustedInput(trace, in); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Input){
		"name":         func(i *Input) { i.Version.Name = "other" },
		"version":      func(i *Input) { i.Version.Version = "2.0.0" },
		"manifest":     func(i *Input) { i.Version.Manifest = []byte(`{"name":"bound","version":"1.0.0","scripts":{}}`) },
		"tree":         func(i *Input) { copy := *i.Package; copy.TreeDigest = "other"; i.Package = &copy },
		"version tree": func(i *Input) { i.Version.TreeDigest = "other" },
		"version hash": func(i *Input) { i.Version.ArtifactHash = "sha512-other" },
		"artifact": func(i *Input) {
			other := filepath.Join(t.TempDir(), "other.tgz")
			if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
				t.Fatal(err)
			}
			i.ArtifactPath = other
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			changed := in
			change(&changed)
			if validateTrustedInput(trace, changed) == nil {
				t.Fatal("accepted mismatched trace")
			}
		})
	}
}

func TestTraceConfigCoversNativeAndAliasSyscalls(t *testing.T) {
	for arch, numbers := range map[string][]string{
		"arm64": {"206", "211", "269", "36", "37", "38", "276", "97", "268", "40", "41", "51", "39", "425", "426", "427", "428", "429", "430", "431", "432", "433", "437"},
		"amd64": {"44", "46", "307", "88", "266", "86", "265", "82", "264", "316", "272", "308", "165", "155", "161", "166", "425", "426", "427", "428", "429", "430", "431", "432", "433", "437"},
	} {
		t.Run(arch, func(t *testing.T) {
			config, err := traceConfig("/trace/events.sock", arch)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(config), "syscall/sysno/425/exit") {
				t.Error("missing io_uring setup result")
			}
			for _, number := range numbers {
				if !strings.Contains(string(config), `syscall/sysno/`+number+`/enter`) {
					t.Errorf("missing syscall %s", number)
				}
			}
		})
	}
	if _, err := traceConfig("/trace/events.sock", "unsupported"); err == nil {
		t.Fatal("accepted unsupported architecture")
	}
}

func TestWaitCompletionReportsEarlyExit(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ncase \"$1\" in inspect) echo false ;; logs) echo 'probe failed' ;; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := NewDockerRunner("")
	runner.DockerBin = fake
	started := time.Now()
	err := runner.waitCompletion(context.Background(), filepath.Join(t.TempDir(), "ready"), "nonce", "workload", "observer", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "probe failed") {
		t.Fatalf("expected named early failure, got %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("early failure waited too long")
	}
}

func TestRunscProcessListRequiresSupervisorAlone(t *testing.T) {
	if err := validateRunscPS("[1]"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"[]", "[1,2]", "[2]", "[1,1]", "not-json", "{\"pid\":1}"} {
		if validateRunscPS(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// The DinD harness builds an actual ELF and sets RIVET_AUDIT_NATIVE_BINARY.
// These cases test gVisor observations beyond the Node hook.
func TestDockerRunnerNativeGuardsLive(t *testing.T) {
	if os.Getenv("RIVET_AUDIT_LIVE") != "1" {
		t.Skip("requires isolated gVisor Docker daemon")
	}
	nativePath := os.Getenv("RIVET_AUDIT_NATIVE_BINARY")
	if nativePath == "" {
		t.Skip("native fixture binary not built")
	}
	native, err := os.ReadFile(nativePath)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		mode, refusal, output string
		allow, honey, egress  bool
	}{
		{"symlink_mmap", "unsupported", "", false, false, false},
		{"proc_mmap", "unsupported proc or fd path alias", "", false, false, false},
		{"openat2_mmap", "", "openat2 errno=38", true, true, false},
		{"unshare", "unsupported unshare", "", false, false, false},
		{"double_slash_mmap", "", "", true, true, false},
		{"udp_send", "", "", true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "audit-native"), native, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"native-guard","version":"1.0.0"}`), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("module.exports = 1;\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			artifact := packDir(t, dir)
			artifactPath := filepath.Join(t.TempDir(), "package.tgz")
			if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
				t.Fatal(err)
			}
			pkg, err := canon.ReadTarball(artifact)
			if err != nil {
				t.Fatal(err)
			}
			manifest := registry.PackageManifest{Name: "native-guard", Version: "1.0.0", InstallScripts: map[string]string{"postinstall": "./audit-native " + tc.mode}}
			manifestBytes, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			version := registry.VersionRecord{Name: manifest.Name, Version: manifest.Version, ArtifactHash: "sha512-" + sha512Hex(artifact), TreeDigest: pkg.TreeDigest, Manifest: manifestBytes}
			runner := NewDockerRunner("rivet-audit-agent:local")
			runner.RunscBin = os.Getenv("RIVET_AUDIT_TEST_RUNSC_BIN")
			if runner.RunscBin == "" {
				runner.RunscBin = "/runsc/runsc"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			pipeline := &Pipeline{Signer: testSigner(t, 32), Sandbox: runner}
			record, err := pipeline.Audit(ctx, Input{Version: version, Package: pkg, ArtifactPath: artifactPath})
			if !tc.allow {
				if err == nil || !strings.Contains(err.Error(), tc.refusal) {
					t.Fatalf("want %q refusal, got runtime=%s err=%v", tc.refusal, record.SandboxRuntime, err)
				}
				t.Logf("%s refused: %s", tc.mode, truncate(err.Error(), 300))
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if record.SandboxRuntime != registry.SandboxGVisor {
				t.Fatalf("uncertified result: %s", record.SandboxRuntime)
			}
			var evidence Evidence
			if err := json.Unmarshal(record.Evidence, &evidence); err != nil {
				t.Fatal(err)
			}
			if tc.honey && len(evidence.Honeytokens) == 0 {
				t.Fatalf("native honey read missed in %s", tc.mode)
			}
			if tc.egress && len(evidence.Egress) == 0 {
				t.Fatalf("native UDP send missed in %s", tc.mode)
			}
			t.Logf("%s certified: honey_paths=%d network_attempts=%d", tc.mode, len(evidence.Honeytokens), len(evidence.Egress))
			if tc.output != "" {
				found := false
				for _, probe := range evidence.Adversarial {
					if strings.Contains(probe.Output, tc.output) {
						found = true
						t.Logf("%s probe: %s", tc.mode, truncate(strings.TrimSpace(probe.Output), 160))
					}
				}
				if !found {
					t.Fatalf("expected probe output %q", tc.output)
				}
			}
		})
	}
}

func TestTrustedAuditPinsRunscVersion(t *testing.T) {
	if err := validateRunscVersion("runsc version release-20260601.0\nspec: 1.2.1"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"runsc version release-20260422.0", "runsc version release-20260601.0-modified", "", "spec: 1.2.1"} {
		if validateRunscVersion(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestDockerRunnerPackageTamperLive(t *testing.T) {
	if os.Getenv("RIVET_AUDIT_LIVE") != "1" {
		t.Skip("requires isolated gVisor Docker daemon")
	}
	for _, tc := range []struct {
		name, detached string
	}{{"hook_forgery", ""}, {"detached_child", "const child=spawn('/bin/sleep',['120'],{detached:true,stdio:'ignore'});child.unref();"}} {
		t.Run(tc.name, func(t *testing.T) {
			attack := `const fs=require('fs');
const {spawn}=require('child_process');
function denied(fn,label){try{fn();throw Error(label+' unexpectedly available')}catch(e){if(e.message===label+' unexpectedly available')throw e}}
if(process.getuid()!==2000)throw Error('probe did not run as UID2000');
if(process.env.RIVET_AUDIT_NONCE)throw Error('nonce leaked into probe');
denied(()=>fs.readdirSync('/evidence'),'evidence directory');
if(fs.existsSync('/trace'))throw Error('private trace mounted into package');
denied(()=>fs.readFileSync('/proc/1/environ'),'supervisor environment');
denied(()=>fs.readFileSync('/opt/rivet/agent.js'),'supervisor source');
denied(()=>process.kill(1,0),'supervisor signal permission');
const honey=fs.readFileSync(process.env.HOME+'/.npmrc','utf8');
if(!honey.includes('RIVETHONEYTOKEN'))throw Error('honey file missing');
fs.writeFileSync(process.env.RIVET_EGRESS_LOG,'');
fs.appendFileSync(process.env.RIVET_EGRESS_LOG,JSON.stringify({kind:'egress',host:'forged.invalid',port:443,protocol:'tcp',probe:'forged'})+'\n');
fs.appendFileSync(process.env.RIVET_EGRESS_LOG,JSON.stringify({kind:'honeytoken',token:'forged-token',probe:'forged'})+'\n');
// DETACHED_CHILD
console.log('tamper fixture complete');
`
			attack = strings.Replace(attack, "// DETACHED_CHILD", tc.detached, 1)
			artifact := tgzFiles(t, map[string]string{"package.json": `{"name":"tamper-guard","version":"1.0.0"}`, "index.js": "module.exports=1;\n", "attack.js": attack})
			path := filepath.Join(t.TempDir(), "package.tgz")
			if err := os.WriteFile(path, artifact, 0o600); err != nil {
				t.Fatal(err)
			}
			pkg, err := canon.ReadTarball(artifact)
			if err != nil {
				t.Fatal(err)
			}
			manifest := registry.PackageManifest{Name: "tamper-guard", Version: "1.0.0", InstallScripts: map[string]string{"postinstall": "node attack.js"}}
			manifestBytes, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			version := registry.VersionRecord{Name: manifest.Name, Version: manifest.Version, ArtifactHash: "sha512-" + sha512Hex(artifact), TreeDigest: pkg.TreeDigest, Manifest: manifestBytes}
			runner := NewDockerRunner("rivet-audit-agent:local")
			if dockerBin := os.Getenv("RIVET_AUDIT_TEST_DOCKER_BIN"); dockerBin != "" {
				runner.DockerBin = dockerBin
			}
			if helper := os.Getenv("RIVET_AUDIT_TEST_RUNSC_BIN"); helper != "" {
				runner.RunscBin = helper
			} else {
				runner.RunscBin = "/runsc/runsc"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			pipeline := &Pipeline{Signer: testSigner(t, 33), Sandbox: runner}
			record, err := pipeline.Audit(ctx, Input{Version: version, Package: pkg, ArtifactPath: path})
			if tc.detached != "" {
				if err == nil || !strings.Contains(err.Error(), "tasks after completion marker") {
					t.Fatalf("detached child should refuse certification, got runtime=%s err=%v", record.SandboxRuntime, err)
				}
				t.Logf("detached child refused: %s", truncate(err.Error(), 260))
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if record.SandboxRuntime != registry.SandboxGVisor || !VerifyAuditSignature(record, pipeline.Signer) {
				t.Fatalf("tamper run not signed gVisor: %s", record.SandboxRuntime)
			}
			var evidence Evidence
			if err := json.Unmarshal(record.Evidence, &evidence); err != nil {
				t.Fatal(err)
			}
			sawHoney := false
			for _, h := range evidence.Honeytokens {
				if strings.Contains(h.Token, ".npmrc") {
					sawHoney = true
				}
				if h.Token == "forged-token" {
					t.Fatal("forged hook token entered signed evidence")
				}
			}
			if !sawHoney {
				t.Fatal("kernel honey observation missing")
			}
			for _, egress := range evidence.Egress {
				if egress.Host == "forged.invalid" {
					t.Fatal("forged hook egress entered signed evidence")
				}
			}
			t.Logf("tamper fixture certified: kernel_honey=%d kernel_egress=%d, runsc process list supervisor-only", len(evidence.Honeytokens), len(evidence.Egress))
		})
	}
}

func TestDockerRunnerUIDCollisionLive(t *testing.T) {
	if os.Geteuid() != 2000 {
		t.Skip("run this test as UID2000")
	}
	_, err := NewDockerRunner("").Run(context.Background(), registry.VersionRecord{}, "")
	if err == nil || !strings.Contains(err.Error(), "registry UID 2000 collides") {
		t.Fatalf("expected collision refusal before Docker resources, got %v", err)
	}
	t.Logf("UID2000 registry refused before Docker resources: %s", err)
}
