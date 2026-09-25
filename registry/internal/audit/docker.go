package audit

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/usharma123/rivet/registry/internal/canon"
	"github.com/usharma123/rivet/registry/internal/registry"
)

// DockerRunner executes the audit agent image under gVisor with no network.
// Egress attempts are recorded by the agent's in-process hooks and by the
// absence of any network namespace; nothing can leave the sandbox.
type DockerRunner struct {
	AgentImage string
	DockerBin  string
}

func NewDockerRunner(image string) *DockerRunner {
	if image == "" {
		image = "rivet-audit-agent:local"
	}
	return &DockerRunner{AgentImage: image, DockerBin: "docker"}
}

func (r *DockerRunner) Runtime() string { return registry.SandboxGVisor }

func (r *DockerRunner) Image() string { return r.AgentImage }

// Args returns the docker arguments used for an audit run.
func (r *DockerRunner) Args(version registry.VersionRecord, artifactPath, outDir string) []string {
	return []string{
		"run", "--rm",
		"--runtime=runsc",
		"--network=none",
		"--read-only",
		"--tmpfs=/tmp:rw,size=64m",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pids-limit=256",
		"--memory=512m",
		"--cpus=1",
		"-v", artifactPath + ":/artifact/package:ro",
		"-v", filepath.Join(outDir, "manifest.json") + ":/audit/manifest.json:ro",
		"-v", outDir + ":/evidence:rw",
		"-e", "RIVET_PACKAGE_NAME=" + version.Name,
		"-e", "RIVET_PACKAGE_VERSION=" + version.Version,
		"-e", "RIVET_SAFE_TIMEOUT_MS=30000",
		"-e", "RIVET_ADVERSARIAL_TIMEOUT_MS=120000",
		r.AgentImage,
	}
}

func (r *DockerRunner) Run(ctx context.Context, version registry.VersionRecord, artifactPath string) (Evidence, error) {
	if err := r.ensureRunsc(ctx); err != nil {
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
	if version.ArtifactHash != "" {
		sum := sha512.Sum512(artifact)
		if version.ArtifactHash != "sha512-"+hex.EncodeToString(sum[:]) {
			return Evidence{}, fmt.Errorf("audit artifact hash mismatch")
		}
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
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), version.Manifest, 0o644); err != nil {
		return Evidence{}, err
	}
	// The agent runs as an unprivileged uid inside the container.
	if err := os.Chmod(outDir, 0o777); err != nil {
		return Evidence{}, err
	}
	cmd := exec.CommandContext(ctx, r.DockerBin, r.Args(version, packageDir, outDir)...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return Evidence{}, fmt.Errorf("gVisor audit container failed: %w: %s", err, truncate(output.String(), 2000))
	}
	evidence, err := readEvidence(filepath.Join(outDir, "evidence.json"))
	if err != nil {
		return Evidence{}, err
	}
	if evidence.Agent == nil {
		return Evidence{}, fmt.Errorf("audit agent omitted completion evidence")
	}
	if evidence.Agent["complete"] != "true" {
		return Evidence{}, fmt.Errorf("audit agent did not complete a runnable probe")
	}
	evidence.Agent["image"] = r.AgentImage
	return evidence, nil
}

func (r *DockerRunner) ensureRunsc(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, r.DockerBin, "info", "--format", "{{json .Runtimes}}")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("docker runtime detection failed: %w", err)
	}
	if !strings.Contains(string(output), `"runsc"`) {
		return errors.New("gVisor runsc runtime is not registered with Docker")
	}
	return nil
}

func readEvidence(path string) (Evidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Evidence{}, err
	}
	var evidence Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

func mustJSON(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}
