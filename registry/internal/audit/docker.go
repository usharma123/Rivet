package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/usharma123/rivet/registry/internal/canon"
	"github.com/usharma123/rivet/registry/internal/registry"
)

// DockerRunner uses a separate collector and a private Docker volume for
// gVisor's kernel trace. The audited workload never mounts the trace volume.
type DockerRunner struct {
	AgentImage    string
	ObserverImage string
	DockerBin     string
	RunscBin      string
	RunscRoot     string
}

func NewDockerRunner(image string) *DockerRunner {
	if image == "" {
		image = "rivet-audit-agent:local"
	}
	return &DockerRunner{AgentImage: image, ObserverImage: "rivet-audit-observer:local", DockerBin: "docker", RunscBin: "runsc", RunscRoot: "/var/run/docker/runtime-runc/moby"}
}

func (r *DockerRunner) Runtime() string { return registry.SandboxGVisor }
func (r *DockerRunner) Image() string   { return r.AgentImage }

// Args exposes the security-critical workload defaults for inspection and tests.
func (r *DockerRunner) Args(version registry.VersionRecord, artifactPath, outDir string) []string {
	return r.workloadArgs(version, artifactPath, outDir, "", "")
}

func (r *DockerRunner) workloadArgs(version registry.VersionRecord, artifactPath, outDir, volumePath, nonce string) []string {
	args := []string{"create", "--runtime=runsc", "--network=none", "--read-only", "--tmpfs=/tmp:rw,exec,size=64m", "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=DAC_OVERRIDE", "--cap-add=KILL", "--security-opt=no-new-privileges", "--pids-limit=256", "--memory=512m", "--cpus=1"}
	if volumePath != "" {
		args = append(args, "--annotation=dev.gvisor.flag.pod-init-config="+filepath.Join(volumePath, "config.json"))
	}
	args = append(args,
		"-v", artifactPath+":/artifact/package:ro",
		"-v", filepath.Join(outDir, "manifest.json")+":/audit/manifest.json:ro",
		"-v", outDir+":/evidence:rw",
		"-e", "RIVET_PACKAGE_NAME="+version.Name,
		"-e", "RIVET_PACKAGE_VERSION="+version.Version,
		"-e", "RIVET_SAFE_TIMEOUT_MS=30000",
		"-e", "RIVET_ADVERSARIAL_TIMEOUT_MS=120000",
	)
	if nonce != "" {
		args = append(args, "-e", "RIVET_AUDIT_NONCE="+nonce)
	}
	return append(args, r.AgentImage)
}

func (r *DockerRunner) Run(ctx context.Context, version registry.VersionRecord, artifactPath string) (Evidence, error) {
	if os.Geteuid() == 2000 {
		return Evidence{}, fmt.Errorf("registry UID 2000 collides with audit probe UID; use a different registry account for gVisor audit")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := r.ensureRunsc(ctx); err != nil {
		return Evidence{}, err
	}
	if _, err := exec.LookPath(r.RunscBin); err != nil {
		return Evidence{}, fmt.Errorf("host runsc trace helper unavailable: %w", err)
	}
	versionOutput, err := runBounded(ctx, r.RunscBin, "--version")
	if err != nil {
		return Evidence{}, fmt.Errorf("host runsc version query failed: %w", err)
	}
	if err := validateRunscVersion(versionOutput); err != nil {
		return Evidence{}, err
	}
	outDir, err := os.MkdirTemp("", "rivet-audit-evidence-*")
	if err != nil {
		return Evidence{}, err
	}
	defer os.RemoveAll(outDir)
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return Evidence{}, err
	}
	artifactHash := "sha512-" + sha512Hex(artifact)
	if version.ArtifactHash != "" && version.ArtifactHash != artifactHash {
		return Evidence{}, fmt.Errorf("audit artifact hash mismatch")
	}
	canonical, err := canon.ReadTarball(artifact)
	if err != nil {
		return Evidence{}, err
	}
	if version.TreeDigest != "" && canonical.TreeDigest != version.TreeDigest {
		return Evidence{}, fmt.Errorf("audit tree differs from signed tree digest")
	}
	packageDir := filepath.Join(outDir, "canonical-package")
	for _, name := range canonical.Paths() {
		file := canonical.Files[name]
		path := filepath.Join(packageDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return Evidence{}, err
		}
		mode := os.FileMode(0o644)
		if file.Executable {
			mode = 0o755
		}
		if err := os.WriteFile(path, file.Data, mode); err != nil {
			return Evidence{}, err
		}
	}
	manifestPath := filepath.Join(outDir, "manifest.json")
	if err := os.WriteFile(manifestPath, version.Manifest, 0o600); err != nil {
		return Evidence{}, err
	}
	// Package children see only the bind-mounted package tree, not this parent.
	if err := os.Chmod(outDir, 0o700); err != nil {
		return Evidence{}, err
	}
	nonce, err := freshNonce()
	if err != nil {
		return Evidence{}, err
	}
	// AF_UNIX paths are limited to 108 bytes on Linux. Docker's volume root
	// contributes most of that path, so keep the random volume name short.
	volume := "ra-" + nonce[:32]
	var workloadID, observerID string
	workloadName, observerName := "ra-work-"+nonce[:32], "ra-observer-"+nonce[:32]
	workloadCreateAttempted, observerCreateAttempted := false, false
	volumeCreateAttempted := false
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cleanupCancel()
		if workloadCreateAttempted {
			_, _ = r.docker(cleanupCtx, "rm", "-f", "-v", workloadName)
		}
		if observerCreateAttempted {
			_, _ = r.docker(cleanupCtx, "rm", "-f", "-v", observerName)
		}
		if volumeCreateAttempted {
			_, _ = r.docker(cleanupCtx, "volume", "rm", "-f", volume)
		}
	}()
	volumeCreateAttempted = true
	if _, err := r.docker(ctx, "volume", "create", "--name", volume); err != nil {
		return Evidence{}, err
	}
	mountpoint, err := r.docker(ctx, "volume", "inspect", "--format", "{{.Mountpoint}}", volume)
	if err != nil {
		return Evidence{}, err
	}
	mountpoint = strings.TrimSpace(mountpoint)
	if !filepath.IsAbs(mountpoint) || !strings.HasSuffix(mountpoint, "/_data") {
		return Evidence{}, fmt.Errorf("invalid Docker trace volume mountpoint")
	}
	if len(filepath.Join(mountpoint, "events.sock")) >= 108 {
		return Evidence{}, fmt.Errorf("Docker trace socket path exceeds AF_UNIX limit")
	}
	architecture, err := r.auditArchitecture(ctx)
	if err != nil {
		return Evidence{}, err
	}
	config, err := traceConfig(filepath.Join(mountpoint, "events.sock"), architecture)
	if err != nil {
		return Evidence{}, err
	}
	configPath := filepath.Join(outDir, "config.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		return Evidence{}, err
	}
	workloadArgs := r.workloadArgs(version, packageDir, outDir, mountpoint, nonce)
	workloadArgs = append(workloadArgs[:1], append([]string{"--name=" + workloadName}, workloadArgs[1:]...)...)
	workloadCreateAttempted = true
	workloadID, err = r.docker(ctx, workloadArgs...)
	if err != nil {
		return Evidence{}, err
	}
	workloadID = strings.TrimSpace(workloadID)
	if !fullContainerID.MatchString(workloadID) {
		return Evidence{}, fmt.Errorf("Docker returned invalid workload ID")
	}
	if err := r.verifyWorkload(ctx, workloadID, packageDir, manifestPath, outDir, mountpoint, nonce); err != nil {
		return Evidence{}, err
	}
	observerCreateAttempted = true
	observerID, err = r.docker(ctx, "create", "--name="+observerName, "--runtime=runc", "--network=none", "--read-only", "--tmpfs=/tmp:rw,size=16m", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=32", "--memory=128m", "-v", volume+":/trace:rw", "-e", "RIVET_CONTAINER_ID="+workloadID, "-e", "RIVET_AUDIT_NONCE="+nonce, r.ObserverImage)
	if err != nil {
		return Evidence{}, err
	}
	observerID = strings.TrimSpace(observerID)
	if !fullContainerID.MatchString(observerID) {
		return Evidence{}, fmt.Errorf("Docker returned invalid observer ID")
	}
	if _, err := r.docker(ctx, "cp", configPath, observerID+":/trace/config.json"); err != nil {
		return Evidence{}, fmt.Errorf("initialize trace config: %w", err)
	}
	readback := filepath.Join(outDir, "config-readback.json")
	if _, err := r.docker(ctx, "cp", observerID+":/trace/config.json", readback); err != nil {
		return Evidence{}, fmt.Errorf("read trace config: %w", err)
	}
	readbackBytes, err := os.ReadFile(readback)
	if err != nil || sha512Hex(readbackBytes) != sha512Hex(config) {
		return Evidence{}, fmt.Errorf("trace config volume readback mismatch: %w", err)
	}
	if _, err := r.docker(ctx, "start", observerID); err != nil {
		return Evidence{}, err
	}
	if err := r.waitObserverFile(ctx, observerID, "/trace/ready", 15*time.Second); err != nil {
		return Evidence{}, err
	}
	if _, err := r.docker(ctx, "start", workloadID); err != nil {
		return Evidence{}, err
	}
	if err := r.waitCompletion(ctx, filepath.Join(outDir, "ready"), nonce, workloadID, observerID, 4*time.Minute); err != nil {
		return Evidence{}, fmt.Errorf("workload completion barrier: %w", err)
	}
	if err := r.waitObserverFile(ctx, observerID, "/trace/marker", 10*time.Second); err != nil {
		return Evidence{}, err
	}
	marker, err := r.docker(ctx, "exec", observerID, "cat", "/trace/marker")
	if err != nil || marker != nonce {
		return Evidence{}, fmt.Errorf("observer completion marker mismatch: %w", err)
	}
	psOutput, err := runBounded(ctx, r.RunscBin, "--root="+r.RunscRoot, "ps", "-format=json", workloadID)
	if err != nil {
		return Evidence{}, fmt.Errorf("host gVisor process query failed: %w", err)
	}
	if err := validateRunscPS(psOutput); err != nil {
		return Evidence{}, err
	}
	traceOutput, err := runBounded(ctx, r.RunscBin, "--root="+r.RunscRoot, "trace", "list", workloadID)
	if err != nil {
		return Evidence{}, fmt.Errorf("host gVisor trace query failed: %w", err)
	}
	if err := validateTraceList(traceOutput); err != nil {
		return Evidence{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "release"), []byte(nonce), 0o600); err != nil {
		return Evidence{}, err
	}
	if err := r.waitExit(ctx, workloadID); err != nil {
		return Evidence{}, fmt.Errorf("workload: %w", err)
	}
	if err := r.waitExit(ctx, observerID); err != nil {
		return Evidence{}, fmt.Errorf("observer: %w", err)
	}
	resultPath := filepath.Join(outDir, "trace-result.json")
	if _, err := r.docker(ctx, "cp", observerID+":/trace/result.json", resultPath); err != nil {
		return Evidence{}, err
	}
	resultBytes, err := os.ReadFile(resultPath)
	if err != nil {
		return Evidence{}, err
	}
	if len(resultBytes) > 256*1024 {
		return Evidence{}, fmt.Errorf("trace result exceeds limit")
	}
	var report traceReport
	if err := json.Unmarshal(resultBytes, &report); err != nil {
		return Evidence{}, err
	}
	if err := validateTraceReport(report, workloadID, nonce); err != nil {
		return Evidence{}, err
	}
	evidence, err := readEvidence(filepath.Join(outDir, "evidence.json"))
	if err != nil {
		return Evidence{}, err
	}
	if evidence.Agent == nil || evidence.Agent["complete"] != "true" {
		return Evidence{}, fmt.Errorf("audit agent did not complete a runnable probe")
	}
	// Package-writable hook reports remain advisory. Only kernel-observed events
	// from the isolated collector can affect the signed risk score.
	evidence.Egress = nil
	if report.NetworkAttempts > 0 {
		evidence.Egress = []EgressEvidence{{Host: "unknown", Protocol: "kernel-trace", Decision: "blocked", Probe: "package", Bytes: 0}}
	}
	evidence.Honeytokens = nil
	for _, path := range report.HoneyPaths {
		evidence.Honeytokens = append(evidence.Honeytokens, HoneytokenAccess{Token: path, Probe: "package", How: "kernel-trace"})
	}
	evidence.Agent["image"] = r.AgentImage
	evidence.Agent["trace_container_id"] = workloadID
	evidence.Agent["trace_nonce"] = nonce
	evidence.Agent["artifact_hash"] = artifactHash
	evidence.Agent["tree_digest"] = canonical.TreeDigest
	evidence.Agent["manifest_sha512"] = sha512Hex(version.Manifest)
	evidence.Agent["trace_packets"] = fmt.Sprint(report.Packets)
	evidence.validatedTrace = &validatedTrace{containerID: workloadID, nonce: nonce, packageName: version.Name, version: version.Version, artifactHash: artifactHash, treeDigest: canonical.TreeDigest, manifestHash: sha512Hex(version.Manifest)}
	return evidence, nil
}

var fullContainerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (r *DockerRunner) verifyWorkload(ctx context.Context, id, packageDir, manifestPath, evidenceDir, mountpoint, nonce string) error {
	out, err := r.docker(ctx, "inspect", "--format", "{{json .}}", id)
	if err != nil {
		return err
	}
	var inspect struct {
		HostConfig struct {
			Runtime        string
			NetworkMode    string
			ReadonlyRootfs bool
			Binds          []string
			Annotations    map[string]string
		} `json:"HostConfig"`
		Config struct {
			Image string
			Env   []string
		} `json:"Config"`
	}
	if err := json.Unmarshal([]byte(out), &inspect); err != nil {
		return err
	}
	if inspect.HostConfig.Runtime != "runsc" || inspect.HostConfig.NetworkMode != "none" || !inspect.HostConfig.ReadonlyRootfs || inspect.Config.Image != r.AgentImage || len(inspect.HostConfig.Binds) != 3 {
		return fmt.Errorf("Docker workload configuration changed")
	}
	wantBinds := []string{packageDir + ":/artifact/package:ro", manifestPath + ":/audit/manifest.json:ro", evidenceDir + ":/evidence:rw"}
	for _, bind := range wantBinds {
		if !contains(inspect.HostConfig.Binds, bind) {
			return fmt.Errorf("Docker workload mount missing: %s", bind)
		}
	}
	if inspect.HostConfig.Annotations["dev.gvisor.flag.pod-init-config"] != filepath.Join(mountpoint, "config.json") {
		return fmt.Errorf("gVisor trace config annotation missing")
	}
	if !contains(inspect.Config.Env, "RIVET_AUDIT_NONCE="+nonce) {
		return fmt.Errorf("workload audit nonce missing")
	}
	return nil
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
func sha512Hex(data []byte) string { sum := sha512.Sum512(data); return hex.EncodeToString(sum[:]) }
func freshNonce() (string, error) {
	var data [24]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func (r *DockerRunner) ensureRunsc(ctx context.Context) error {
	output, err := r.docker(ctx, "info", "--format", "{{json .Runtimes}}")
	if err != nil {
		return fmt.Errorf("docker runtime detection failed: %w", err)
	}
	if !strings.Contains(output, `"runsc"`) {
		return errors.New("gVisor runsc runtime is not registered with Docker")
	}
	return nil
}

func (r *DockerRunner) auditArchitecture(ctx context.Context) (string, error) {
	daemon, err := r.docker(ctx, "info", "--format", "{{.Architecture}}")
	if err != nil {
		return "", err
	}
	architecture := normalizeArchitecture(daemon)
	if architecture == "" {
		return "", fmt.Errorf("unsupported Docker daemon architecture %q", daemon)
	}
	for _, image := range []string{r.AgentImage, r.ObserverImage} {
		imageArch, err := r.docker(ctx, "image", "inspect", "--format", "{{.Architecture}}", image)
		if err != nil {
			return "", err
		}
		if normalizeArchitecture(imageArch) != architecture {
			return "", fmt.Errorf("audit image %s architecture differs from Docker daemon", image)
		}
	}
	return architecture, nil
}

func normalizeArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "arm64", "aarch64":
		return "arm64"
	case "amd64", "x86_64":
		return "amd64"
	default:
		return ""
	}
}

func (r *DockerRunner) docker(ctx context.Context, args ...string) (string, error) {
	return runBounded(ctx, r.DockerBin, args...)
}

// runBounded caps each command's output and duration, including Docker waits.
func runBounded(parent context.Context, binary string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.WaitDelay = time.Second
	output := &limitedOutput{max: 256 * 1024}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	if output.exceeded {
		return "", fmt.Errorf("%s output exceeds limit", filepath.Base(binary))
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", filepath.Base(binary), strings.Join(args[:min(len(args), 2)], " "), err, truncate(output.String(), 1200))
	}
	return strings.TrimSpace(output.String()), nil
}

type limitedOutput struct {
	data     []byte
	max      int
	exceeded bool
}

func (l *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(l.data)+n > l.max {
		l.exceeded = true
		p = p[:max(0, l.max-len(l.data))]
	}
	l.data = append(l.data, p...)
	return n, nil
}
func (l *limitedOutput) String() string { return string(l.data) }

func (r *DockerRunner) waitObserverFile(parent context.Context, id, path string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	for {
		if _, err := r.docker(ctx, "exec", id, "test", "-f", path); err == nil {
			return nil
		}
		if running, err := r.containerRunning(ctx, id); err != nil {
			return err
		} else if !running {
			return r.containerFailure(ctx, id, "observer")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("observer did not create %s: %w", path, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (r *DockerRunner) waitCompletion(parent context.Context, path, expected, workloadID, observerID string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			if string(data) != expected {
				return fmt.Errorf("completion nonce mismatch")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, container := range []struct{ id, role string }{{observerID, "observer"}, {workloadID, "workload"}} {
			running, err := r.containerRunning(ctx, container.id)
			if err != nil {
				return err
			}
			if !running {
				if container.role == "workload" {
					// An unsupported syscall may make the workload fail while the
					// observer is still draining its trace. Prefer its named error.
					for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
						observerRunning, err := r.containerRunning(ctx, observerID)
						if err == nil && !observerRunning {
							return r.containerFailure(ctx, observerID, "observer")
						}
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-time.After(100 * time.Millisecond):
						}
					}
				}
				return r.containerFailure(ctx, container.id, container.role)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (r *DockerRunner) containerRunning(ctx context.Context, id string) (bool, error) {
	status, err := r.docker(ctx, "inspect", "--format", "{{.State.Running}}", id)
	if err != nil {
		return false, err
	}
	switch status {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid Docker container state %q", status)
	}
}

func (r *DockerRunner) containerFailure(ctx context.Context, id, role string) error {
	logs, err := r.docker(ctx, "logs", "--tail", "5", id)
	if err != nil {
		return fmt.Errorf("%s exited before audit completion: %w", role, err)
	}
	return fmt.Errorf("%s exited before audit completion: %s", role, truncate(logs, 1200))
}
func (r *DockerRunner) waitExit(ctx context.Context, id string) error {
	out, err := r.docker(ctx, "wait", id)
	if err != nil {
		return err
	}
	if out != "0" {
		return fmt.Errorf("container exited %s", out)
	}
	return nil
}
func readEvidence(path string) (Evidence, error) {
	file, err := os.Open(path)
	if err != nil {
		return Evidence{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 512*1024+1))
	if err != nil {
		return Evidence{}, err
	}
	if len(data) > 512*1024 {
		return Evidence{}, fmt.Errorf("audit evidence exceeds limit")
	}
	var evidence Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}
func mustJSON(value any) json.RawMessage { data, _ := json.Marshal(value); return data }
