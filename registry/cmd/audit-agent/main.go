package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/usharma123/rivet/registry/internal/audit"
)

func main() {
	if err := run(); err != nil {
		_ = writeEvidence(audit.Evidence{
			Static: audit.StaticEvidence{
				ArtifactSize:     fileSize("/artifact/package.tgz"),
				SourceVisibility: "unknown",
			},
			SafeProbes: []audit.ProbeEvidence{{
				Name:     "agent",
				ExitCode: 1,
				Output:   redact(err.Error()),
			}},
		})
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	workDir := "/evidence/work"
	if err := os.RemoveAll(workDir); err != nil {
		return err
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return err
	}
	artifact := "/artifact/package.tgz"
	if err := extractTGZ(artifact, workDir); err != nil {
		return err
	}
	packageDir := filepath.Join(workDir, "package")
	manifest := map[string]any{}
	if data, err := os.ReadFile(filepath.Join(packageDir, "package.json")); err == nil {
		_ = json.Unmarshal(data, &manifest)
	}
	evidence := audit.Evidence{
		Static: audit.StaticEvidence{
			ArtifactSize:     fileSize(artifact),
			SourceVisibility: "unknown",
			SourceRepo:       sourceRepo(manifest),
		},
		Privacy: map[string][]string{
			"will_send": {
				"package manifest",
				"dependency summary",
				"executable metadata",
				"install scripts",
				"release diff",
				"selected suspicious snippets",
			},
			"will_not_send": {
				".env files",
				"registry tokens",
				"git credentials",
				"private project files",
				"shell history",
			},
		},
		Sandbox: map[string]string{"runtime": "gvisor/runsc", "network": "rivet-audit-net"},
		Agent:   map[string]string{"name": "rivet-static-audit-agent", "version": "0.1.0"},
	}
	if evidence.Static.SourceRepo != "" {
		evidence.Static.SourceVisibility = "open"
	}
	scanManifest(manifest, &evidence)
	if err := scanFiles(packageDir, &evidence); err != nil {
		return err
	}
	callProxy(&evidence)
	return writeEvidence(evidence)
}

func scanManifest(manifest map[string]any, evidence *audit.Evidence) {
	if scripts, ok := manifest["scripts"].(map[string]any); ok {
		for _, name := range []string{"preinstall", "install", "postinstall"} {
			if _, ok := scripts[name]; ok {
				evidence.Static.InstallScripts = append(evidence.Static.InstallScripts, name)
			}
		}
	}
	evidence.Static.HasInstallScripts = len(evidence.Static.InstallScripts) > 0
	evidence.SafeProbes = append(evidence.SafeProbes, audit.ProbeEvidence{
		Name:     "metadata",
		Command:  "read package.json",
		ExitCode: 0,
		Output:   "package metadata parsed inside gVisor sandbox",
	})
	evidence.Adversarial = append(evidence.Adversarial, audit.ProbeEvidence{
		Name:     "runtime-probes",
		Command:  "static-agent",
		ExitCode: 0,
		Output:   "runtime execution deferred to Node-based audit image",
	})
}

func scanFiles(root string, evidence *audit.Evidence) error {
	minified := regexp.MustCompile(`(?m)^.{500,}$`)
	obfuscated := regexp.MustCompile(`eval\s*\(|Function\s*\(|atob\s*\(|\\x[0-9a-fA-F]{2}`)
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		lower := strings.ToLower(rel)
		if strings.HasSuffix(lower, ".node") || strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".dylib") || strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".exe") {
			evidence.Static.NativeBinaries = append(evidence.Static.NativeBinaries, rel)
			evidence.Static.HasNativeBinaries = true
		}
		if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".cjs") || strings.HasSuffix(lower, ".mjs") {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			sample := string(data)
			if len(sample) > 256000 {
				sample = sample[:256000]
			}
			if minified.MatchString(sample) {
				evidence.Static.MinifiedFiles = append(evidence.Static.MinifiedFiles, rel)
			}
			if obfuscated.MatchString(sample) {
				evidence.Static.ObfuscatedFiles = append(evidence.Static.ObfuscatedFiles, rel)
			}
		}
		return nil
	})
}

func callProxy(evidence *audit.Evidence) {
	proxyURL := os.Getenv("RIVET_AUDIT_PROXY_URL")
	token := os.Getenv("RIVET_AUDIT_TOKEN")
	if proxyURL == "" || token == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"package":  os.Getenv("RIVET_PACKAGE_NAME"),
		"version":  os.Getenv("RIVET_PACKAGE_VERSION"),
		"evidence": evidence,
	})
	request, err := http.NewRequest(http.MethodPost, proxyURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Rivet-Audit-Token", token)
	client := &http.Client{Timeout: 60 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		evidence.Egress = append(evidence.Egress, audit.EgressEvidence{Host: "audit-proxy", Protocol: "http", Decision: "blocked"})
		return
	}
	defer response.Body.Close()
	evidence.Agent["proxy_status"] = response.Status
}

func extractTGZ(path, destination string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(destination, filepath.Clean(header.Name))
		if !strings.HasPrefix(target, destination) {
			return fmt.Errorf("unsafe tar path: %s", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, reader)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
}

func sourceRepo(manifest map[string]any) string {
	switch repo := manifest["repository"].(type) {
	case string:
		return repo
	case map[string]any:
		if url, ok := repo["url"].(string); ok {
			return url
		}
	}
	return ""
}

func writeEvidence(evidence audit.Evidence) error {
	if err := os.MkdirAll("/evidence", 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("/evidence/evidence.json", data, 0o644)
}

func fileSize(path string) int64 {
	stat, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return stat.Size()
}

func redact(value string) string {
	value = regexp.MustCompile(`(?i)(RIVET_REGISTRY_TOKEN|RIVET_AUDIT_TOKEN|API_KEY)=\S+`).ReplaceAllString(value, "$1=[REDACTED]")
	return regexp.MustCompile(`sk-[A-Za-z0-9_-]{10,}`).ReplaceAllString(value, "sk-[REDACTED]")
}
