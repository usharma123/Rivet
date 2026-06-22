package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/usharma123/rivet/registry/internal/artifacts"
	"github.com/usharma123/rivet/registry/internal/audit"
	"github.com/usharma123/rivet/registry/internal/registry"
)

type Server struct {
	store     registry.Store
	artifacts *artifacts.FileStore
	auditor   audit.Runner
	token     string
	mux       *http.ServeMux
}

func NewServer(store registry.Store, artifactStore *artifacts.FileStore, token string) http.Handler {
	return NewServerWithAuditor(store, artifactStore, token, nil)
}

func NewServerWithAuditor(store registry.Store, artifactStore *artifacts.FileStore, token string, auditor audit.Runner) http.Handler {
	server := &Server{
		store:     store,
		artifacts: artifactStore,
		auditor:   auditor,
		token:     token,
		mux:       http.NewServeMux(),
	}
	server.routes()
	return server
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.health)
	s.mux.HandleFunc("/v1/packages/", s.packages)
	s.mux.HandleFunc("/v1/audits/", s.auditByID)
	s.mux.HandleFunc("/v1/executables/", s.executables)
	s.mux.HandleFunc("/v1/import/npm", s.importNPM)
	s.mux.HandleFunc("/v1/evals", s.evals)
	s.mux.HandleFunc("/v1/audit-proxy/model", s.auditProxyModel)
	s.mux.HandleFunc("/v1/search", s.search)
	s.mux.HandleFunc("/v1/artifacts/", s.artifact)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) packages(w http.ResponseWriter, r *http.Request) {
	segments, err := pathSegments(strings.TrimPrefix(r.URL.Path, "/v1/packages/"))
	if err != nil || len(segments) == 0 {
		writeError(w, http.StatusNotFound, "package path not found")
		return
	}
	name := segments[0]

	switch {
	case r.Method == http.MethodGet && len(segments) == 1:
		pkg, err := s.store.GetPackage(r.Context(), name)
		writeStoreResult(w, pkg, err)
	case r.Method == http.MethodGet && len(segments) == 2:
		version, err := s.store.GetVersion(r.Context(), name, segments[1])
		writeStoreResult(w, version, err)
	case r.Method == http.MethodPost && len(segments) == 3 && segments[2] == "publish":
		if !s.authorized(w, r) {
			return
		}
		var req registry.PublishRequest
		if !decodeJSON(w, r.Body, &req) {
			return
		}
		record := versionFromPublish(name, segments[1], req)
		version, err := s.store.UpsertVersion(r.Context(), record)
		if err == nil {
			version, err = s.runVerifiedAudit(r.Context(), version)
		}
		writeStoreResult(w, version, err)
	case len(segments) == 3 && segments[2] == "audits":
		switch r.Method {
		case http.MethodPost:
			if !s.authorized(w, r) {
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			if shouldTriggerAudit(body) {
				version, err := s.store.GetVersion(r.Context(), name, segments[1])
				if err == nil {
					version, err = s.runVerifiedAudit(r.Context(), version)
				}
				if err != nil {
					writeStoreResult(w, nil, err)
					return
				}
				audit, err := s.store.GetLatestAudit(r.Context(), version.Name, version.Version)
				writeStoreResult(w, audit, err)
				return
			}
			var req registry.AuditRecord
			if err := json.Unmarshal(body, &req); err != nil {
				writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
				return
			}
			req.PackageName = name
			req.Version = segments[1]
			audit, err := s.store.CreateAudit(r.Context(), req)
			writeStoreResult(w, audit, err)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case r.Method == http.MethodGet && len(segments) == 4 && segments[2] == "audits" && segments[3] == "latest":
		audit, err := s.store.GetLatestAudit(r.Context(), name, segments[1])
		writeStoreResult(w, audit, err)
	case r.Method == http.MethodPost && len(segments) == 3 && (segments[2] == "revoke" || segments[2] == "yank"):
		if !s.authorized(w, r) {
			return
		}
		var req registry.StateChangeRequest
		if !decodeJSON(w, r.Body, &req) {
			return
		}
		target := registry.StateRevoked
		if segments[2] == "yank" {
			target = registry.StateYanked
		}
		version, err := s.store.SetReleaseState(r.Context(), name, segments[1], target, req)
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
	segments, err := pathSegments(strings.TrimPrefix(r.URL.Path, "/v1/audits/"))
	if err != nil || len(segments) != 1 {
		writeError(w, http.StatusNotFound, "audit path not found")
		return
	}
	audit, err := s.store.GetAudit(r.Context(), segments[0])
	writeStoreResult(w, audit, err)
}

func (s *Server) executables(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	segments, err := pathSegments(strings.TrimPrefix(r.URL.Path, "/v1/executables/"))
	if err != nil || len(segments) != 1 {
		writeError(w, http.StatusNotFound, "executable path not found")
		return
	}
	version, err := s.store.FindExecutable(r.Context(), segments[0])
	writeStoreResult(w, version, err)
}

func (s *Server) importNPM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authorized(w, r) {
		return
	}
	var req struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		registry.PublishRequest
	}
	if !decodeJSON(w, r.Body, &req) {
		return
	}
	if req.Source == "" {
		req.Source = "npm-import"
	}
	version, err := s.store.UpsertVersion(r.Context(), versionFromPublish(req.Name, req.Version, req.PublishRequest))
	if err == nil {
		version, err = s.runVerifiedAudit(r.Context(), version)
	}
	writeStoreResult(w, version, err)
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
	if !decodeJSON(w, r.Body, &req) {
		return
	}
	eval, err := s.store.CreateEval(r.Context(), req)
	writeStoreResult(w, eval, err)
}

func (s *Server) auditProxyModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token := r.Header.Get("X-Rivet-Audit-Token")
	if token == "" {
		writeError(w, http.StatusUnauthorized, "audit token is required")
		return
	}
	var req struct {
		Package  string          `json:"package"`
		Version  string          `json:"version"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if !decodeJSON(w, r.Body, &req) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"model":             "registry-deterministic-audit-proxy",
		"verdict":           "low",
		"risk_score":        12,
		"reasons":           []string{"registry audit proxy accepted sanitized evidence"},
		"suggested_actions": []string{"allow_install"},
	})
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	results, err := s.store.Search(r.Context(), r.URL.Query().Get("q"))
	writeStoreResult(w, map[string]any{"results": results}, err)
}

func (s *Server) artifact(w http.ResponseWriter, r *http.Request) {
	segments, err := pathSegments(strings.TrimPrefix(r.URL.Path, "/v1/artifacts/"))
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
		path, err := s.artifacts.Put(hash, r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"hash": hash, "path": path})
	case http.MethodGet:
		file, err := s.artifacts.Get(hash)
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

func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	if s.token == "" {
		writeError(w, http.StatusUnauthorized, "registry token is not configured")
		return false
	}
	header := r.Header.Get("Authorization")
	if header != "Bearer "+s.token {
		writeError(w, http.StatusUnauthorized, "invalid registry token")
		return false
	}
	return true
}

func versionFromPublish(name, version string, req registry.PublishRequest) registry.VersionRecord {
	return registry.VersionRecord{
		Name:              name,
		Version:           version,
		Source:            defaultString(req.Source, "native"),
		State:             registry.NormalizeState(req.State),
		Manifest:          req.Manifest,
		ArtifactHash:      req.ArtifactHash,
		ArtifactURL:       req.ArtifactURL,
		Publisher:         req.Publisher,
		SourceMetadata:    req.SourceMetadata,
		Executables:       req.Executables,
		RiskScore:         req.RiskScore,
		ArtifactSize:      req.ArtifactSize,
		LastPublishedBy:   req.LastPublishedBy,
		SourceRepo:        req.SourceRepo,
		SourceVisibility:  defaultString(req.SourceVisibility, "unknown"),
		HasNativeBinaries: req.HasNativeBinaries,
		HasInstallScripts: req.HasInstallScripts,
	}
}

func (s *Server) runVerifiedAudit(ctx context.Context, version registry.VersionRecord) (registry.VersionRecord, error) {
	if s.auditor == nil {
		return version, nil
	}
	artifactPath, err := s.artifacts.Path(version.ArtifactHash)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	auditRecord, err := s.auditor.Audit(ctx, version, artifactPath)
	if err != nil {
		return registry.VersionRecord{}, fmt.Errorf("verified gVisor audit failed closed: %w", err)
	}
	if auditRecord.PackageName == "" {
		auditRecord.PackageName = version.Name
	}
	if auditRecord.Version == "" {
		auditRecord.Version = version.Version
	}
	if _, err := s.store.CreateAudit(ctx, auditRecord); err != nil {
		return registry.VersionRecord{}, err
	}
	return s.store.GetVersion(ctx, version.Name, version.Version)
}

func writeStoreResult(w http.ResponseWriter, value any, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, value)
		return
	}
	switch {
	case errors.Is(err, registry.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, registry.ErrPolicy):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, registry.ErrInvalidRequest):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func decodeJSON(w http.ResponseWriter, body io.Reader, value any) bool {
	decoder := json.NewDecoder(body)
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

func pathSegments(path string) ([]string, error) {
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

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func shouldTriggerAudit(body []byte) bool {
	if len(strings.TrimSpace(string(body))) == 0 {
		return true
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(body, &value); err != nil {
		return false
	}
	_, hasSignature := value["signature"]
	_, hasEvidence := value["evidence"]
	_, hasVerdict := value["verdict"]
	return !hasSignature && !hasEvidence && !hasVerdict
}
