package audit

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/usharma123/rivet/registry/internal/canon"
	"github.com/usharma123/rivet/registry/internal/registry"
)

// Capability names are part of the signed evidence contract; the CLI shows
// them and diffs compare them across versions.
const (
	CapNetwork        = "network"
	CapChildProcess   = "child_process"
	CapDynamicCode    = "dynamic_code"
	CapEnvHarvest     = "env_harvest"
	CapSensitivePaths = "sensitive_paths"
	CapFSWrite        = "fs_write"
	CapObfuscation    = "obfuscation"
	CapNative         = "native_code"
	CapExfilEndpoint  = "exfil_endpoint"
	CapExfilPattern   = "exfil_pattern"
	// CapEmbeddedBlob marks large encoded payloads (often WebAssembly). Common
	// in bundlers and parsers, so only a newly added blob is scored.
	CapEmbeddedBlob = "embedded_blob"
)

const maxScanBytes = 4 << 20
const maxFilesPerCapability = 10

var (
	reNetwork      = regexp.MustCompile(`require\(\s*['"](?:node:)?(?:http|https|http2|net|tls|dgram|dns)['"]\s*\)|from\s*['"](?:node:)?(?:http|https|http2|net|tls|dgram|dns)['"]|\bfetch\s*\(|new\s+WebSocket\s*\(|XMLHttpRequest|require\(\s*['"](?:axios|node-fetch|got|undici|request)['"]\s*\)`)
	reChildProcess = regexp.MustCompile(`['"](?:node:)?child_process['"]`)
	reDynamicCode  = regexp.MustCompile(`\beval\s*\(|new\s+Function\s*\(|['"](?:node:)?vm['"]`)
	reEnvHarvest   = regexp.MustCompile(`JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|process\.env\.(?:NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|CI_JOB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)\b`)
	reSensitive    = regexp.MustCompile(`\.ssh[/\\'"]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.gnupg|\.config[/\\]gh[/\\'"]|\.docker[/\\]config\.json|\.kube[/\\]config|Library[/\\]Keychains|Login Data|\.bash_history|\.zsh_history|wallet\.dat|\.git-credentials|\.netrc['"]|\.npmrc['"]`)
	reFSWrite      = regexp.MustCompile(`writeFileSync|\bwriteFile\s*\(|appendFileSync|createWriteStream|\brmSync\s*\(|unlinkSync|chmodSync`)
	reExfilHost    = regexp.MustCompile(`(?i)discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services|webhook\.site|ngrok(?:-free)?\.(?:io|app)|requestbin|burpcollaborator|\.oast\.|interact\.sh|transfer\.sh|pipedream\.net|api\.telegram\.org/bot`)
	reHexIdent     = regexp.MustCompile(`_0x[0-9a-fA-F]{4,}`)
	reHexEscape    = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	reFromCharCode = regexp.MustCompile(`String\.fromCharCode\(`)
	reLongLine     = regexp.MustCompile(`(?m)^.{1000,}$`)
	reScriptRisk   = regexp.MustCompile(`(?i)\bcurl\b|\bwget\b|node\s+-e|bash\s+-c|sh\s+-c|powershell|\|\s*(?:ba)?sh\b|base64\s+(?:-d|--decode)|\beval\b|nc\s+-`)
)

var lifecycleScripts = []string{"preinstall", "install", "postinstall", "prepare"}

type Manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Scripts              map[string]any    `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Repository           json.RawMessage   `json:"repository"`
	Gypfile              bool              `json:"gypfile"`
}

func ParseManifest(files map[string]canon.File) Manifest {
	var manifest Manifest
	if file, ok := files["package.json"]; ok {
		_ = json.Unmarshal(file.Data, &manifest)
	}
	return manifest
}

// InstallScripts returns lifecycle scripts npm would run on install. A
// binding.gyp without an install script implies "node-gyp rebuild".
func InstallScripts(manifest Manifest, files map[string]canon.File) map[string]string {
	out := map[string]string{}
	for _, name := range lifecycleScripts {
		if name == "prepare" {
			continue // prepare only runs for git/local installs
		}
		if value, ok := manifest.Scripts[name].(string); ok && value != "" {
			out[name] = value
		}
	}
	if _, hasGyp := files["binding.gyp"]; hasGyp {
		if _, ok := out["install"]; !ok {
			if _, ok := out["preinstall"]; !ok {
				out["install"] = "node-gyp rebuild"
			}
		}
	}
	return out
}

// AnalyzeStatic scans a canonical package for capabilities and red flags.
func AnalyzeStatic(pkg *canon.Package) StaticEvidence {
	return AnalyzeStaticWithManifest(pkg, nil)
}

// AnalyzeStaticWithManifest scans the authoritative metadata that will be
// signed, including native lifecycle commands absent from package.json.
func AnalyzeStaticWithManifest(pkg *canon.Package, normalized *registry.PackageManifest) StaticEvidence {
	manifest := ParseManifest(pkg.Files)
	evidence := StaticEvidence{
		SourceVisibility: "unknown",
		Capabilities:     map[string][]string{},
		FileCount:        len(pkg.Files),
		TreeDigest:       pkg.TreeDigest,
	}
	for _, file := range pkg.Files {
		evidence.ArtifactSize += int64(len(file.Data))
	}
	if repo := repositoryURL(manifest.Repository); repo != "" {
		evidence.SourceRepo = repo
		evidence.SourceVisibility = "declared"
	}
	evidence.InstallScriptCommands = InstallScripts(manifest, pkg.Files)
	if normalized != nil {
		evidence.InstallScriptCommands = normalized.InstallScripts
		if normalized.Repository != "" {
			evidence.SourceRepo = normalized.Repository
			evidence.SourceVisibility = "declared"
		}
	}
	for name, command := range evidence.InstallScriptCommands {
		evidence.InstallScripts = append(evidence.InstallScripts, name)
		if reScriptRisk.MatchString(command) {
			evidence.SuspiciousScripts = append(evidence.SuspiciousScripts, name+": "+truncate(command, 200))
		}
	}
	sort.Strings(evidence.InstallScripts)
	sort.Strings(evidence.SuspiciousScripts)
	evidence.HasInstallScripts = len(evidence.InstallScripts) > 0

	for _, path := range pkg.Paths() {
		file := pkg.Files[path]
		lower := strings.ToLower(path)
		if isNativeBinary(lower, file.Data) {
			evidence.NativeBinaries = append(evidence.NativeBinaries, path)
			evidence.add(CapNative, path)
			continue
		}
		if !isScript(lower) {
			continue
		}
		data := file.Data
		if len(data) > maxScanBytes {
			data = data[:maxScanBytes]
		}
		text := string(data)
		found := map[string]bool{}
		check := func(capability string, re *regexp.Regexp) {
			if re.MatchString(text) {
				found[capability] = true
				evidence.add(capability, path)
			}
		}
		check(CapNetwork, reNetwork)
		check(CapChildProcess, reChildProcess)
		check(CapDynamicCode, reDynamicCode)
		check(CapEnvHarvest, reEnvHarvest)
		check(CapSensitivePaths, reSensitive)
		check(CapFSWrite, reFSWrite)
		check(CapExfilEndpoint, reExfilHost)
		if hasLongBase64Run(text, 3000) {
			evidence.add(CapEmbeddedBlob, path)
		}
		if looksObfuscated(text) {
			found[CapObfuscation] = true
			evidence.add(CapObfuscation, path)
			evidence.ObfuscatedFiles = append(evidence.ObfuscatedFiles, path)
		} else if reLongLine.MatchString(text) {
			evidence.MinifiedFiles = append(evidence.MinifiedFiles, path)
		}
		if found[CapNetwork] && (found[CapSensitivePaths] || found[CapEnvHarvest]) {
			evidence.add(CapExfilPattern, path)
		}
	}
	evidence.HasNativeBinaries = len(evidence.NativeBinaries) > 0
	if warning := NamesquatWarning(manifest.Name); warning != "" {
		evidence.NamesquatWarning = warning
	}
	return evidence
}

func (e *StaticEvidence) add(capability, path string) {
	files := e.Capabilities[capability]
	if len(files) < maxFilesPerCapability {
		e.Capabilities[capability] = append(files, path)
	} else if len(files) == maxFilesPerCapability {
		e.Capabilities[capability] = append(files, "…")
	}
}

// CapabilityNames lists the capabilities present, sorted.
func (e StaticEvidence) CapabilityNames() []string {
	names := make([]string, 0, len(e.Capabilities))
	for name, files := range e.Capabilities {
		if len(files) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func isScript(path string) bool {
	for _, ext := range []string{".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".sh"} {
		if strings.HasSuffix(path, ext) && !strings.HasSuffix(path, ".d.ts") && !strings.HasSuffix(path, ".d.mts") && !strings.HasSuffix(path, ".d.cts") {
			return true
		}
	}
	return false
}

func isNativeBinary(path string, data []byte) bool {
	for _, ext := range []string{".node", ".so", ".dylib", ".dll", ".exe"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	if len(data) < 4 {
		return false
	}
	magic := data[:4]
	return bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'}) ||
		bytes.Equal(magic, []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(magic, []byte{0xce, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(magic, []byte{0xca, 0xfe, 0xba, 0xbe}) ||
		bytes.Equal(data[:2], []byte{'M', 'Z'}) && strings.HasSuffix(path, ".exe")
}

func looksObfuscated(text string) bool {
	return len(reHexIdent.FindAllStringIndex(text, 50)) >= 50 ||
		len(reHexEscape.FindAllStringIndex(text, 500)) >= 500 ||
		len(reFromCharCode.FindAllStringIndex(text, 150)) >= 150
}

// hasLongBase64Run reports a run of at least n base64 characters, the usual
// shape of an embedded encoded payload.
func hasLongBase64Run(text string, n int) bool {
	run := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func repositoryURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single
	}
	var obj struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.URL
	}
	return ""
}

func truncate(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n] + "…"
}
