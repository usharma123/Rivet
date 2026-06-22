package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/usharma123/rivet/registry/internal/registry"
)

type DockerRunner struct {
	Image      string
	ProxyURL   string
	SignSecret string
	DockerBin  string
	Now        func() time.Time
}

func NewDockerRunner(image, proxyURL, signSecret string) *DockerRunner {
	if image == "" {
		image = "rivet-audit-agent:local"
	}
	if signSecret == "" {
		signSecret = "dev-audit-signing-key"
	}
	return &DockerRunner{
		Image:      image,
		ProxyURL:   proxyURL,
		SignSecret: signSecret,
		DockerBin:  "docker",
		Now:        time.Now,
	}
}

func (r *DockerRunner) Audit(ctx context.Context, version registry.VersionRecord, artifactPath string) (registry.AuditRecord, error) {
	if err := r.ensureRunsc(ctx); err != nil {
		return registry.AuditRecord{}, err
	}
	outDir, err := os.MkdirTemp("", "rivet-audit-evidence-*")
	if err != nil {
		return registry.AuditRecord{}, err
	}
	defer os.RemoveAll(outDir)

	token := auditToken(version)
	proxyURL := r.ProxyURL
	if proxyURL == "" {
		proxyURL = "http://host.docker.internal:8080/v1/audit-proxy/model"
	}
	args := []string{
		"run", "--rm",
		"--runtime=runsc",
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pids-limit=256",
		"--memory=512m",
		"--cpus=1",
		"--network=rivet-audit-net",
		"--add-host=host.docker.internal:host-gateway",
		"-v", artifactPath + ":/artifact/package.tgz:ro",
		"-v", outDir + ":/evidence:rw",
		"-e", "RIVET_AUDIT_TOKEN=" + token,
		"-e", "RIVET_AUDIT_PROXY_URL=" + proxyURL,
		"-e", "RIVET_PACKAGE_NAME=" + version.Name,
		"-e", "RIVET_PACKAGE_VERSION=" + version.Version,
		"-e", "RIVET_SAFE_TIMEOUT_MS=30000",
		"-e", "RIVET_ADVERSARIAL_TIMEOUT_MS=120000",
		r.Image,
	}
	cmd := exec.CommandContext(ctx, r.DockerBin, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return registry.AuditRecord{}, fmt.Errorf("gVisor audit container failed: %w: %s", err, output.String())
	}

	evidence, err := readEvidence(filepath.Join(outDir, "evidence.json"))
	if err != nil {
		return registry.AuditRecord{}, err
	}
	if evidence.Static.ArtifactSize == 0 {
		evidence.Static.ArtifactSize = version.ArtifactSize
	}
	evidence.Sandbox = map[string]string{"runtime": "gvisor/runsc", "network": "rivet-audit-net"}
	evidence.Agent = map[string]string{"image": r.Image}
	score := ScoreEvidence(evidence)
	now := r.Now()
	audit := registry.AuditRecord{
		PackageName:    version.Name,
		Version:        version.Version,
		Status:         registry.AuditPassed,
		SandboxRuntime: "gvisor/runsc",
		AgentImage:     r.Image,
		Evidence:       EvidenceJSON(evidence),
		Verdict:        score.Verdict,
		RiskScore:      score.RiskScore,
		Reasons:        mustJSON(score.Reasons),
		Suggested:      mustJSON(score.SuggestedActions),
		CostCents:      50,
		StartedAt:      now,
		CompletedAt:    &now,
	}
	signature, err := SignAudit(audit, r.SignSecret)
	if err != nil {
		return registry.AuditRecord{}, err
	}
	audit.Signature = signature
	return audit, nil
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
	network := exec.CommandContext(ctx, r.DockerBin, "network", "inspect", "rivet-audit-net")
	if err := network.Run(); err != nil {
		create := exec.CommandContext(ctx, r.DockerBin, "network", "create", "rivet-audit-net")
		if out, err := create.CombinedOutput(); err != nil {
			return fmt.Errorf("create rivet-audit-net: %w: %s", err, string(out))
		}
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

func auditToken(version registry.VersionRecord) string {
	return strings.ReplaceAll(version.Name+"-"+version.Version+"-"+time.Now().Format("20060102150405"), "/", "-")
}

func mustJSON(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}
