package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/usharma123/rivet/registry/internal/artifacts"
	"github.com/usharma123/rivet/registry/internal/attest"
	"github.com/usharma123/rivet/registry/internal/audit"
	"github.com/usharma123/rivet/registry/internal/canon"
	"github.com/usharma123/rivet/registry/internal/mirror"
	"github.com/usharma123/rivet/registry/internal/npm"
	"github.com/usharma123/rivet/registry/internal/registry"
	"github.com/usharma123/rivet/registry/internal/signing"
)

const maxJSONBody = 1 << 20

type Config struct {
	Store     registry.Store
	Artifacts *artifacts.FileStore
	Pipeline  *audit.Pipeline
	Mirror    *mirror.Service
	Signer    *signing.Signer
	// Token authorizes publishing, mirroring and publisher-level state changes.
	Token string
	// AdminToken additionally authorizes registry-approved yanks and
	// security revocations of widely used releases.
	AdminToken string
	// PublicMirror lets unauthenticated clients request npm imports.
	PublicMirror   bool
	AttestationTTL time.Duration
	Now            func() time.Time
}

type Server struct {
	cfg Config
	mux *http.ServeMux
}

func NewServer(cfg Config) http.Handler {
	if cfg.AttestationTTL == 0 {
		cfg.AttestationTTL = attest.DefaultTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	server := &Server{cfg: cfg, mux: http.NewServeMux()}
	server.routes()
	return server
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.health)
	s.mux.HandleFunc("/v1/keys", s.keys)
	s.mux.HandleFunc("/v1/packages/", s.packages)
	s.mux.HandleFunc("/v1/audits/", s.auditByID)
	s.mux.HandleFunc("/v1/executables/", s.executables)
	s.mux.HandleFunc("/v1/npm/resolve", s.resolveNPM)
	s.mux.HandleFunc("/v1/import/npm", s.importNPM)
	s.mux.HandleFunc("/v1/attestations", s.attestations)
	s.mux.HandleFunc("/v1/evals", s.evals)
	s.mux.HandleFunc("/v1/search", s.search)
	s.mux.HandleFunc("/v1/artifacts/", s.artifact)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": []signing.PublicKey{s.cfg.Signer.Public()}})
}

func (s *Server) packages(w http.ResponseWriter, r *http.Request) {
	segments, err := pathSegments(r, "/v1/packages/")
	if err != nil || len(segments) == 0 {
		writeError(w, http.StatusNotFound, "package path not found")
		return
	}
	name := segments[0]
	ctx := r.Context()

	switch {
	case r.Method == http.MethodGet && len(segments) == 1:
		pkg, err := s.cfg.Store.GetPackage(ctx, name)
		writeStoreResult(w, pkg, err)
	case r.Method == http.MethodGet && len(segments) == 2:
		version, err := s.cfg.Store.GetVersion(ctx, name, segments[1])
		writeStoreResult(w, version, err)
	case r.Method == http.MethodGet && len(segments) == 3 && segments[2] == "attestation":
		version, err := s.cfg.Store.GetVersion(ctx, name, segments[1])
		if err != nil {
			writeStoreResult(w, nil, err)
			return
		}
		envelope, err := s.attestation(version)
		writeStoreResult(w, envelope, err)
	case r.Method == http.MethodPost && len(segments) == 3 && segments[2] == "publish":
		if !s.authorized(w, r) {
			return
		}
		var req registry.PublishRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := s.checkNativeName(ctx, name, s.isAdmin(r)); err != nil {
			writeStoreResult(w, nil, err)
			return
		}
		version, err := s.publishNative(ctx, name, segments[1], req)
		if err != nil {
			writeStoreResult(w, nil, err)
			return
		}
		s.writeVersion(w, version, nil)
	case len(segments) == 3 && segments[2] == "audits":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !s.authorized(w, r) {
			return
		}
		// Audits are only ever produced by the registry itself. Clients may
		// request a re-audit but can never submit verdicts or signatures.
		var req struct {
			Sandbox string `json:"sandbox,omitempty"`
		}
		if !decodeOptionalJSON(w, r, &req) {
			return
		}
		version, err := s.cfg.Store.GetVersion(ctx, name, segments[1])
		if err == nil {
			version, err = s.reaudit(ctx, version)
		}
		if err != nil {
			writeStoreResult(w, nil, err)
			return
		}
		auditRecord, err := s.cfg.Store.GetLatestAudit(ctx, version.Name, version.Version)
		writeStoreResult(w, auditRecord, err)
	case r.Method == http.MethodGet && len(segments) == 4 && segments[2] == "audits" && segments[3] == "latest":
		auditRecord, err := s.cfg.Store.GetLatestAudit(ctx, name, segments[1])
		writeStoreResult(w, auditRecord, err)
	case r.Method == http.MethodPost && len(segments) == 3 && (segments[2] == "revoke" || segments[2] == "yank"):
		if !s.authorized(w, r) {
			return
		}
		var req registry.StateChangeRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if !s.isAdmin(r) {
			// Only registry administrators may override the publisher window.
			req.RegistryApproved = false
			req.SecurityEvidence = false
		}
		target := registry.StateRevoked
		if segments[2] == "yank" {
			target = registry.StateYanked
		}
		version, err := s.cfg.Store.SetReleaseState(ctx, name, segments[1], target, req)
		writeStoreResult(w, version, err)
	default:
		writeError(w, http.StatusNotFound, "package route not found")
	}
}

func (s *Server) auditByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	segments, err := pathSegments(r, "/v1/audits/")
	if err != nil || len(segments) != 1 {
		writeError(w, http.StatusNotFound, "audit path not found")
		return
	}
	auditRecord, err := s.cfg.Store.GetAudit(r.Context(), segments[0])
	writeStoreResult(w, auditRecord, err)
}

func (s *Server) executables(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	segments, err := pathSegments(r, "/v1/executables/")
	if err != nil || len(segments) != 1 {
		writeError(w, http.StatusNotFound, "executable path not found")
		return
	}
	version, err := s.cfg.Store.FindExecutable(r.Context(), segments[0])
	writeStoreResult(w, version, err)
}

func (s *Server) resolveNPM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.mirrorAuthorized(w, r) {
		return
	}
	var req mirror.ResolveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Spec == "" {
		req.Spec = "latest"
	}
	if req.MinAgeHours < 0 {
		writeError(w, http.StatusBadRequest, "min_age_hours must not be negative")
		return
	}
	result, err := s.cfg.Mirror.Resolve(r.Context(), req)
	if err != nil {
		writeStoreResultWithDetail(w, err, map[string]any{"skipped": result.Skipped})
		return
	}
	s.writeVersion(w, result.Version, result.Skipped)
}

func (s *Server) importNPM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.mirrorAuthorized(w, r) {
		return
	}
	var req struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !npm.ValidName(req.Name) || req.Version == "" {
		writeError(w, http.StatusBadRequest, "name and exact version are required")
		return
	}
	version, err := s.cfg.Mirror.Import(r.Context(), req.Name, req.Version)
	if err != nil {
		writeStoreResult(w, nil, err)
		return
	}
	s.writeVersion(w, version, nil)
}

// attestations returns fresh signed statements for a batch of releases so
// clients can re-check revocation state before running anything.
func (s *Server) attestations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Packages) > 5000 {
		writeError(w, http.StatusBadRequest, "too many packages in one request")
		return
	}
	out := map[string]signing.Envelope{}
	missing := map[string]string{}
	for _, pkg := range req.Packages {
		key := pkg.Name + "@" + pkg.Version
		version, err := s.cfg.Store.GetVersion(r.Context(), pkg.Name, pkg.Version)
		if err != nil {
			missing[key] = err.Error()
			continue
		}
		envelope, err := s.attestation(version)
		if err != nil {
			missing[key] = err.Error()
			continue
		}
		out[key] = envelope
	}
	writeJSON(w, http.StatusOK, map[string]any{"attestations": out, "errors": missing})
}

func (s *Server) evals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authorized(w, r) {
		return
	}
	var req registry.EvalRecord
	if !decodeJSON(w, r, &req) {
		return
	}
	eval, err := s.cfg.Store.CreateEval(r.Context(), req)
	writeStoreResult(w, eval, err)
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	results, err := s.cfg.Store.Search(r.Context(), r.URL.Query().Get("q"))
	writeStoreResult(w, map[string]any{"results": results}, err)
}

func (s *Server) artifact(w http.ResponseWriter, r *http.Request) {
	segments, err := pathSegments(r, "/v1/artifacts/")
	if err != nil || len(segments) != 1 {
		writeError(w, http.StatusNotFound, "artifact path not found")
		return
	}
	hash := segments[0]
	switch r.Method {
	case http.MethodPut:
		if !s.authorized(w, r) {
			return
		}
		_, err := s.cfg.Artifacts.Put(hash, r.Body)
		switch {
		case errors.Is(err, artifacts.ErrHashMismatch), errors.Is(err, artifacts.ErrInvalidHash):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, artifacts.ErrTooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		case err != nil:
			writeError(w, http.StatusInternalServerError, err.Error())
		default:
			writeJSON(w, http.StatusCreated, map[string]string{"hash": hash})
		}
	case http.MethodGet:
		file, err := s.cfg.Artifacts.Get(hash)
		if err != nil {
			writeError(w, http.StatusNotFound, "artifact not found")
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = io.Copy(w, file)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) attestation(version registry.VersionRecord) (signing.Envelope, error) {
	statement, err := attest.Build(version, s.cfg.Now(), s.cfg.AttestationTTL)
	if err != nil {
		return signing.Envelope{}, err
	}
	return attest.Sign(s.cfg.Signer, statement)
}

func (s *Server) writeVersion(w http.ResponseWriter, version registry.VersionRecord, skipped []string) {
	envelope, err := s.attestation(version)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":     version,
		"attestation": envelope,
		"skipped":     skipped,
	})
}

// checkNativeName stops a publisher from shadowing an npm package: because
// native names take precedence during resolution, claiming one that npm
// already serves requires the admin token.
func (s *Server) checkNativeName(ctx context.Context, name string, admin bool) error {
	if pkg, err := s.cfg.Store.GetPackage(ctx, name); err == nil {
		if pkg.Source != "native" {
			return fmt.Errorf("%w: %s is mirrored from npm and cannot be published natively", registry.ErrConflict, name)
		}
		return nil
	}
	if admin || s.cfg.Mirror == nil {
		return nil
	}
	_, err := s.cfg.Mirror.NPM.Packument(ctx, name)
	switch {
	case err == nil:
		return fmt.Errorf("%w: %s exists on npm; publishing it natively would shadow npm and needs the admin token", registry.ErrPolicy, name)
	case errors.Is(err, npm.ErrNotFound):
		return nil
	default:
		return fmt.Errorf("cannot confirm %s is unused on npm: %w", name, err)
	}
}

// publishNative stores a Rivet-native release. Everything except the
// publisher's identity and manifest is derived from the uploaded artifact.
func (s *Server) publishNative(ctx context.Context, name, versionText string, req registry.PublishRequest) (registry.VersionRecord, error) {
	if !npm.ValidName(name) {
		return registry.VersionRecord{}, fmt.Errorf("%w: invalid package name", registry.ErrInvalidRequest)
	}
	if _, err := semver.StrictNewVersion(versionText); err != nil {
		return registry.VersionRecord{}, fmt.Errorf("%w: version must be semver", registry.ErrInvalidRequest)
	}
	data, err := s.cfg.Artifacts.Read(req.ArtifactHash)
	if err != nil {
		return registry.VersionRecord{}, fmt.Errorf("%w: artifact %s must be uploaded before publishing", registry.ErrInvalidRequest, req.ArtifactHash)
	}
	pkg, err := canon.ReadTarball(data)
	if err != nil {
		return registry.VersionRecord{}, fmt.Errorf("%w: %v", registry.ErrInvalidRequest, err)
	}
	manifest, executables, err := nativeManifest(name, versionText, req.Manifest, pkg)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	manifestJSON, _ := json.Marshal(manifest)
	sourceMetadata, _ := json.Marshal(map[string]any{"native": map[string]any{"manifest": req.Manifest}})
	static := audit.AnalyzeStaticWithManifest(pkg, &manifest)
	record := registry.VersionRecord{
		Name:              name,
		Version:           versionText,
		Source:            "native",
		State:             registry.StatePending,
		Manifest:          manifestJSON,
		ArtifactHash:      req.ArtifactHash,
		ArtifactURL:       "/v1/artifacts/" + req.ArtifactHash,
		TreeDigest:        pkg.TreeDigest,
		Publisher:         req.Publisher,
		SourceMetadata:    sourceMetadata,
		Executables:       executables,
		ArtifactSize:      int64(len(data)),
		LastPublishedBy:   req.Publisher,
		SourceRepo:        req.SourceRepo,
		SourceVisibility:  static.SourceVisibility,
		HasNativeBinaries: static.HasNativeBinaries,
		HasInstallScripts: static.HasInstallScripts,
	}
	stored, err := s.cfg.Store.UpsertVersion(ctx, record)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	if stored.LatestAudit != nil {
		return stored, nil
	}
	auditRecord, err := s.auditNative(ctx, stored, pkg, manifest)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	if err := s.storeAudit(ctx, auditRecord); err != nil {
		return registry.VersionRecord{}, err
	}
	return s.cfg.Store.GetVersion(ctx, name, versionText)
}

// auditNative audits a registry-native release against its previous release.
func (s *Server) auditNative(ctx context.Context, version registry.VersionRecord, pkg *canon.Package, manifest registry.PackageManifest) (registry.AuditRecord, error) {
	artifactPath, _ := s.cfg.Artifacts.Path(version.ArtifactHash)
	return s.cfg.Pipeline.Audit(ctx, audit.Input{
		Version:      version,
		Package:      pkg,
		ArtifactPath: artifactPath,
		Dependencies: manifest.Dependencies,
		Provenance:   &audit.ProvenanceEvidence{Status: string(npm.ProvenanceAbsent)},
		Previous:     s.previousNative(ctx, version.Name, version.Version),
	})
}

func (s *Server) previousNative(ctx context.Context, name, versionText string) *audit.PreviousRelease {
	current, err := semver.StrictNewVersion(versionText)
	if err != nil {
		return nil
	}
	pkg, err := s.cfg.Store.GetPackage(ctx, name)
	if err != nil {
		return nil
	}
	var best *registry.VersionRecord
	var bestVersion *semver.Version
	for i := range pkg.Versions {
		candidate, err := semver.StrictNewVersion(pkg.Versions[i].Version)
		if err != nil || !candidate.LessThan(current) {
			continue
		}
		if bestVersion == nil || candidate.GreaterThan(bestVersion) {
			best, bestVersion = &pkg.Versions[i], candidate
		}
	}
	if best == nil {
		return nil
	}
	data, err := s.cfg.Artifacts.Read(best.ArtifactHash)
	if err != nil {
		return nil
	}
	previous, err := canon.ReadTarball(data)
	if err != nil {
		return nil
	}
	var manifest registry.PackageManifest
	_ = json.Unmarshal(best.Manifest, &manifest)
	return &audit.PreviousRelease{
		Version:      best.Version,
		Static:       audit.AnalyzeStaticWithManifest(previous, &manifest),
		Dependencies: manifest.Dependencies,
		Publisher:    best.Publisher,
	}
}

func (s *Server) reaudit(ctx context.Context, version registry.VersionRecord) (registry.VersionRecord, error) {
	data, err := s.cfg.Artifacts.Read(version.ArtifactHash)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	pkg, err := canon.ReadTarball(data)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	if pkg.TreeDigest != version.TreeDigest {
		return registry.VersionRecord{}, fmt.Errorf("stored artifact for %s@%s no longer matches its tree digest", version.Name, version.Version)
	}
	var auditRecord registry.AuditRecord
	if version.Source == "npm" && s.cfg.Mirror != nil {
		artifactPath, _ := s.cfg.Artifacts.Path(version.ArtifactHash)
		auditRecord, err = s.cfg.Mirror.Reaudit(ctx, version, data, pkg, artifactPath)
	} else {
		var manifest registry.PackageManifest
		_ = json.Unmarshal(version.Manifest, &manifest)
		auditRecord, err = s.auditNative(ctx, version, pkg, manifest)
	}
	if err != nil {
		return registry.VersionRecord{}, err
	}
	if err := s.storeAudit(ctx, auditRecord); err != nil {
		return registry.VersionRecord{}, err
	}
	return s.cfg.Store.GetVersion(ctx, version.Name, version.Version)
}

func (s *Server) storeAudit(ctx context.Context, record registry.AuditRecord) error {
	if !audit.VerifyAuditSignature(record, s.cfg.Signer) {
		return errors.New("refusing to store an audit without a valid registry signature")
	}
	_, err := s.cfg.Store.CreateAudit(ctx, record)
	return err
}

type nativeManifestInput struct {
	Package struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description"`
	} `json:"package"`
	Dependencies map[string]string `json:"dependencies"`
	Executables  map[string]struct {
		Entry       string          `json:"entry"`
		Summary     string          `json:"summary"`
		Permissions json.RawMessage `json:"permissions"`
	} `json:"executables"`
	Scripts map[string]struct {
		Command string `json:"command"`
	} `json:"scripts"`
	Publisher *struct {
		Identity string `json:"identity"`
	} `json:"publisher"`
}

func nativeManifest(name, version string, raw json.RawMessage, pkg *canon.Package) (registry.PackageManifest, []registry.Executable, error) {
	var in nativeManifestInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return registry.PackageManifest{}, nil, fmt.Errorf("%w: invalid manifest: %v", registry.ErrInvalidRequest, err)
	}
	if in.Package.Name != name || in.Package.Version != version {
		return registry.PackageManifest{}, nil, fmt.Errorf("%w: manifest names %s@%s but publish targets %s@%s", registry.ErrInvalidRequest, in.Package.Name, in.Package.Version, name, version)
	}
	manifest := registry.PackageManifest{
		Name:         name,
		Version:      version,
		Description:  in.Package.Description,
		Dependencies: in.Dependencies,
		Bin:          map[string]string{},
	}
	for alias := range manifest.Dependencies {
		if !npm.ValidName(alias) {
			return registry.PackageManifest{}, nil, fmt.Errorf("%w: invalid dependency alias %q", registry.ErrInvalidRequest, alias)
		}
	}
	scripts := map[string]string{}
	for scriptName, script := range in.Scripts {
		scripts[scriptName] = script.Command
	}
	manifest.InstallScripts = map[string]string{}
	for _, lifecycle := range []string{"preinstall", "install", "postinstall"} {
		if command := scripts[lifecycle]; command != "" {
			manifest.InstallScripts[lifecycle] = command
		}
	}
	commands := make([]string, 0, len(in.Executables))
	for command := range in.Executables {
		commands = append(commands, command)
	}
	sort.Strings(commands)
	var executables []registry.Executable
	for _, command := range commands {
		if !npm.ValidCommand(command) {
			return registry.PackageManifest{}, nil, fmt.Errorf("%w: invalid executable command %q", registry.ErrInvalidRequest, command)
		}
		executable := in.Executables[command]
		entry := strings.TrimPrefix(executable.Entry, "./")
		if _, ok := pkg.Files[entry]; !ok {
			return registry.PackageManifest{}, nil, fmt.Errorf("%w: executable %s entry %s is not in the artifact", registry.ErrInvalidRequest, command, entry)
		}
		manifest.Bin[command] = entry
		permissions := executable.Permissions
		if len(permissions) == 0 {
			permissions = json.RawMessage(`{}`)
		}
		executables = append(executables, registry.Executable{
			Command:     command,
			Entry:       entry,
			Summary:     executable.Summary,
			Permissions: permissions,
		})
	}
	return manifest, executables, nil
}

func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.Token == "" && s.cfg.AdminToken == "" {
		writeError(w, http.StatusUnauthorized, "registry token is not configured")
		return false
	}
	if tokenMatches(r, s.cfg.Token) || tokenMatches(r, s.cfg.AdminToken) {
		return true
	}
	writeError(w, http.StatusUnauthorized, "invalid registry token")
	return false
}

func (s *Server) mirrorAuthorized(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.PublicMirror {
		return true
	}
	return s.authorized(w, r)
}

func (s *Server) isAdmin(r *http.Request) bool {
	return tokenMatches(r, s.cfg.AdminToken)
}

func tokenMatches(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	header := r.Header.Get("Authorization")
	return subtle.ConstantTimeCompare([]byte(header), []byte("Bearer "+token)) == 1
}

func writeStoreResult(w http.ResponseWriter, value any, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, value)
		return
	}
	writeStoreResultWithDetail(w, err, nil)
}

func writeStoreResultWithDetail(w http.ResponseWriter, err error, detail map[string]any) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, registry.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, registry.ErrPolicy):
		status = http.StatusForbidden
	case errors.Is(err, registry.ErrInvalidRequest):
		status = http.StatusBadRequest
	case errors.Is(err, registry.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, npm.ErrIntegrity):
		status = http.StatusBadGateway
	}
	body := map[string]any{"error": err.Error()}
	for key, value := range detail {
		body[key] = value
	}
	writeJSON(w, status, body)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return false
	}
	return true
}

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return true
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// pathSegments splits the escaped path so "%2F" inside a scoped package name
// ("@scope%2Fpkg") stays part of one segment.
func pathSegments(r *http.Request, prefix string) ([]string, error) {
	path := strings.TrimPrefix(r.URL.EscapedPath(), prefix)
	if path == "" {
		return nil, nil
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return nil, fmt.Errorf("invalid path segment: %w", err)
		}
		out = append(out, decoded)
	}
	return out, nil
}
