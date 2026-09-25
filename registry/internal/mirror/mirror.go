// Package mirror imports packages from the upstream npm registry. The
// registry does all fetching, verification and auditing itself; clients only
// name the package and version (or range) they want.
package mirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/usharma123/rivet/registry/internal/artifacts"
	"github.com/usharma123/rivet/registry/internal/audit"
	"github.com/usharma123/rivet/registry/internal/canon"
	"github.com/usharma123/rivet/registry/internal/npm"
	"github.com/usharma123/rivet/registry/internal/registry"
)

const maxResolveAttempts = 4

type Service struct {
	Store      registry.Store
	Artifacts  *artifacts.FileStore
	NPM        *npm.Client
	Provenance *npm.ProvenanceVerifier
	Pipeline   *audit.Pipeline
	Now        func() time.Time

	group    singleflight.Group
	mu       sync.Mutex
	previous map[string]*audit.PreviousRelease
}

type ResolveRequest struct {
	Name string `json:"name"`
	Spec string `json:"spec"`
	// MinAgeHours is the cooldown: versions younger than this are skipped.
	MinAgeHours float64  `json:"min_age_hours"`
	Prefer      []string `json:"prefer,omitempty"`
}

type ResolveResult struct {
	Version registry.VersionRecord
	Skipped []string
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Resolve picks a version for spec, imports and audits it, and skips versions
// the registry has already found unsafe.
func (s *Service) Resolve(ctx context.Context, req ResolveRequest) (ResolveResult, error) {
	if !npm.ValidName(req.Name) {
		return ResolveResult{}, fmt.Errorf("%w: invalid package name %q", registry.ErrInvalidRequest, req.Name)
	}
	if err := npm.CheckSpec(req.Spec); err != nil {
		return ResolveResult{}, fmt.Errorf("%w: %v", registry.ErrInvalidRequest, err)
	}
	// Registry-native packages take precedence over npm (ADR 0006). A name
	// published here is never resolved from npm, which closes the
	// dependency-confusion hole of mixing private and public names.
	if native, ok := s.nativePackument(ctx, req.Name); ok {
		selection, err := npm.Select(native, req.Spec, npm.SelectOptions{
			MinAge: time.Duration(req.MinAgeHours * float64(time.Hour)),
			Now:    s.now(),
			Prefer: req.Prefer,
			Exclude: func(version string) (bool, string) {
				record, err := s.Store.GetVersion(ctx, req.Name, version)
				if err != nil || record.LatestAudit == nil {
					return true, "not audited"
				}
				if !record.State.Resolvable() {
					return true, "release is " + string(record.State)
				}
				return false, ""
			},
		})
		if err != nil {
			return ResolveResult{Skipped: selection.Skipped}, fmt.Errorf("%w: %v", registry.ErrPolicy, err)
		}
		record, err := s.Store.GetVersion(ctx, req.Name, selection.Version)
		return ResolveResult{Version: record, Skipped: selection.Skipped}, err
	}
	packument, err := s.NPM.Packument(ctx, req.Name)
	if err != nil {
		if errors.Is(err, npm.ErrNotFound) {
			return ResolveResult{}, fmt.Errorf("%w: %v", registry.ErrNotFound, err)
		}
		return ResolveResult{}, err
	}
	rejected := map[string]string{}
	var skipped []string
	for attempt := 0; attempt < maxResolveAttempts; attempt++ {
		selection, err := npm.Select(packument, req.Spec, npm.SelectOptions{
			MinAge: time.Duration(req.MinAgeHours * float64(time.Hour)),
			Now:    s.now(),
			Prefer: req.Prefer,
			Exclude: func(version string) (bool, string) {
				if reason, ok := rejected[version]; ok {
					return true, reason
				}
				record, err := s.Store.GetVersion(ctx, req.Name, version)
				if err == nil && record.LatestAudit != nil && !record.State.Resolvable() {
					return true, "release is " + string(record.State)
				}
				return false, ""
			},
		})
		skipped = selection.Skipped
		if err != nil {
			return ResolveResult{Skipped: skipped}, fmt.Errorf("%w: %v", registry.ErrPolicy, err)
		}
		record, err := s.Import(ctx, req.Name, selection.Version)
		if err != nil {
			return ResolveResult{Skipped: skipped}, err
		}
		if record.State.Resolvable() {
			return ResolveResult{Version: record, Skipped: skipped}, nil
		}
		rejected[selection.Version] = "audit marked release " + string(record.State)
	}
	return ResolveResult{Skipped: skipped}, fmt.Errorf("%w: no safe version of %s satisfies %q after %d attempts", registry.ErrPolicy, req.Name, req.Spec, maxResolveAttempts)
}

// nativePackument presents registry-native releases of name in packument
// form so the same selection rules apply.
func (s *Service) nativePackument(ctx context.Context, name string) (*npm.Packument, bool) {
	pkg, err := s.Store.GetPackage(ctx, name)
	if err != nil || pkg.Source != "native" {
		return nil, false
	}
	packument := &npm.Packument{
		Name:     name,
		DistTags: map[string]string{},
		Versions: map[string]npm.VersionMeta{},
		Time:     map[string]string{},
	}
	latest := ""
	for _, version := range pkg.Versions {
		packument.Versions[version.Version] = npm.VersionMeta{Name: name, Version: version.Version}
		packument.Time[version.Version] = version.PublishedAt.UTC().Format(time.RFC3339)
		if latest == "" || npm.VersionGreater(version.Version, latest) {
			latest = version.Version
		}
	}
	if latest != "" {
		packument.DistTags["latest"] = latest
	}
	return packument, true
}

// Import mirrors one exact npm version. It is idempotent and safe to call
// concurrently: an audited release is returned as stored.
func (s *Service) Import(ctx context.Context, name, version string) (registry.VersionRecord, error) {
	result, err, _ := s.group.Do(name+"@"+version, func() (any, error) {
		return s.importOnce(ctx, name, version)
	})
	if err != nil {
		return registry.VersionRecord{}, err
	}
	return result.(registry.VersionRecord), nil
}

func (s *Service) importOnce(ctx context.Context, name, version string) (registry.VersionRecord, error) {
	if existing, err := s.Store.GetVersion(ctx, name, version); err == nil && existing.LatestAudit != nil {
		return existing, nil
	}
	if pkg, err := s.Store.GetPackage(ctx, name); err == nil && pkg.Source == "native" {
		return registry.VersionRecord{}, fmt.Errorf("%w: %s is a registry-native package and is never imported from npm", registry.ErrPolicy, name)
	}
	packument, err := s.NPM.Packument(ctx, name)
	if err != nil {
		if errors.Is(err, npm.ErrNotFound) {
			return registry.VersionRecord{}, fmt.Errorf("%w: %v", registry.ErrNotFound, err)
		}
		return registry.VersionRecord{}, err
	}
	meta, ok := packument.Versions[version]
	if !ok {
		return registry.VersionRecord{}, fmt.Errorf("%w: npm has no %s@%s", registry.ErrNotFound, name, version)
	}
	tarball, algorithm, err := s.NPM.Tarball(ctx, meta)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	pkg, err := canon.ReadTarball(tarball)
	if err != nil {
		return registry.VersionRecord{}, fmt.Errorf("%w: %v", registry.ErrInvalidRequest, err)
	}
	hash, artifactPath, err := s.Artifacts.PutBytes(tarball)
	if err != nil {
		return registry.VersionRecord{}, err
	}

	evidence := s.releaseEvidence(ctx, packument, meta, pkg, tarball, algorithm)
	manifest := evidence.manifest
	static := audit.AnalyzeStaticWithManifest(pkg, &manifest)

	manifestJSON, _ := json.Marshal(manifest)
	sourceMetadata, _ := json.Marshal(map[string]any{"npm": evidence.upstream})
	record := registry.VersionRecord{
		Name:              name,
		Version:           version,
		Source:            "npm",
		State:             registry.StatePending,
		Manifest:          manifestJSON,
		ArtifactHash:      hash,
		ArtifactURL:       "/v1/artifacts/" + hash,
		TreeDigest:        pkg.TreeDigest,
		Publisher:         "npm:" + meta.Publisher(),
		SourceMetadata:    sourceMetadata,
		Executables:       executables(manifest.Bin),
		ArtifactSize:      int64(len(tarball)),
		LastPublishedBy:   meta.Publisher(),
		SourceRepo:        manifest.Repository,
		SourceVisibility:  static.SourceVisibility,
		HasNativeBinaries: static.HasNativeBinaries,
		HasInstallScripts: static.HasInstallScripts,
	}
	if evidence.provenance.Status == string(npm.ProvenanceVerified) {
		record.SourceRepo = evidence.provenance.SourceRepo
		record.SourceVisibility = "verified"
	}
	if published, ok := packument.PublishedAt(version); ok {
		record.PublishedAt = published
	}
	stored, err := s.Store.UpsertVersion(ctx, record)
	if err != nil {
		return registry.VersionRecord{}, err
	}

	auditRecord, err := s.audit(ctx, packument, stored, pkg, artifactPath, evidence)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	if !audit.VerifyAuditSignature(auditRecord, s.Pipeline.Signer) {
		return registry.VersionRecord{}, errors.New("audit pipeline produced an unsigned record")
	}
	if _, err := s.Store.CreateAudit(ctx, auditRecord); err != nil {
		return registry.VersionRecord{}, err
	}
	return s.Store.GetVersion(ctx, name, version)
}

// Reaudit re-runs the full npm audit for a stored release: provenance, the
// diff against the previous release and manifest checks are recomputed from
// the stored artifact, so a re-audit can never quietly drop evidence.
func (s *Service) Reaudit(ctx context.Context, record registry.VersionRecord, tarball []byte, pkg *canon.Package, artifactPath string) (registry.AuditRecord, error) {
	packument, err := s.NPM.Packument(ctx, record.Name)
	if err != nil {
		return registry.AuditRecord{}, err
	}
	meta, ok := packument.Versions[record.Version]
	if !ok {
		return registry.AuditRecord{}, fmt.Errorf("%w: npm no longer lists %s@%s", registry.ErrNotFound, record.Name, record.Version)
	}
	if _, err := npm.VerifyIntegrity(tarball, meta.Dist); err != nil {
		return registry.AuditRecord{}, fmt.Errorf("stored artifact no longer matches npm metadata: %w", err)
	}
	algorithm, err := npm.VerifyIntegrity(tarball, meta.Dist)
	if err != nil {
		return registry.AuditRecord{}, fmt.Errorf("stored artifact no longer matches npm metadata: %w", err)
	}
	evidence := s.releaseEvidence(ctx, packument, meta, pkg, tarball, algorithm)
	return s.audit(ctx, packument, record, pkg, artifactPath, evidence)
}

// releaseEvidence is what the registry derives about an npm release before
// auditing it: the signed manifest, upstream facts and provenance.
type releaseEvidence struct {
	manifest   registry.PackageManifest
	upstream   *audit.UpstreamEvidence
	provenance *audit.ProvenanceEvidence
}

func (s *Service) releaseEvidence(ctx context.Context, packument *npm.Packument, meta npm.VersionMeta, pkg *canon.Package, tarball []byte, algorithm string) releaseEvidence {
	manifest, mismatches := NormalizeManifest(pkg, meta)
	upstream := &audit.UpstreamEvidence{
		Registry:           s.NPM.BaseURL(),
		Tarball:            meta.Dist.Tarball,
		Integrity:          meta.Dist.Integrity,
		IntegrityAlgorithm: algorithm,
		Publisher:          meta.Publisher(),
		Deprecated:         meta.IsDeprecated(),
		ManifestMismatch:   mismatches,
	}
	if published, ok := packument.PublishedAt(meta.Version); ok {
		upstream.PublishedAt = published.UTC().Format(time.RFC3339)
	}
	return releaseEvidence{
		manifest:   manifest,
		upstream:   upstream,
		provenance: s.verifyProvenance(ctx, meta, tarball),
	}
}

func (s *Service) audit(ctx context.Context, packument *npm.Packument, record registry.VersionRecord, pkg *canon.Package, artifactPath string, evidence releaseEvidence) (registry.AuditRecord, error) {
	input := audit.Input{
		Version:      record,
		Package:      pkg,
		ArtifactPath: artifactPath,
		Dependencies: evidence.manifest.Dependencies,
		Upstream:     evidence.upstream,
		Provenance:   evidence.provenance,
		Previous:     s.previousRelease(ctx, packument, record.Version),
	}
	if audit.AnalyzeStaticWithManifest(pkg, &evidence.manifest).NamesquatWarning != "" {
		input.WeeklyDownloads = s.NPM.WeeklyDownloads(ctx, record.Name)
	}
	return s.Pipeline.Audit(ctx, input)
}

func (s *Service) verifyProvenance(ctx context.Context, meta npm.VersionMeta, tarball []byte) *audit.ProvenanceEvidence {
	if s.Provenance == nil {
		if meta.Dist.Attestations == nil {
			return &audit.ProvenanceEvidence{Status: string(npm.ProvenanceAbsent)}
		}
		return &audit.ProvenanceEvidence{Status: string(npm.ProvenanceUnverifiable), Detail: "provenance verification disabled"}
	}
	p := s.Provenance.Verify(ctx, meta, tarball)
	return &audit.ProvenanceEvidence{
		Status:       string(p.Status),
		SourceRepo:   p.SourceRepo,
		SourceCommit: p.SourceCommit,
		SourceRef:    p.SourceRef,
		BuildSigner:  p.BuildSigner,
		Issuer:       p.Issuer,
		DeclaredRepo: p.DeclaredRepo,
		RepoMatches:  p.RepoMatches,
		Detail:       p.Detail,
	}
}

// previousRelease statically analyzes the preceding stable version so the
// audit can report what changed. Failures only mean no diff is available.
func (s *Service) previousRelease(ctx context.Context, packument *npm.Packument, version string) *audit.PreviousRelease {
	previous := npm.PreviousVersion(packument, version)
	if previous == "" {
		return nil
	}
	key := packument.Name + "@" + previous
	s.mu.Lock()
	if s.previous == nil {
		s.previous = map[string]*audit.PreviousRelease{}
	}
	cached, ok := s.previous[key]
	s.mu.Unlock()
	if ok {
		return cached
	}
	meta := packument.Versions[previous]
	tarball, _, err := s.NPM.Tarball(ctx, meta)
	if err != nil {
		return nil
	}
	pkg, err := canon.ReadTarball(tarball)
	if err != nil {
		return nil
	}
	manifest, _ := NormalizeManifest(pkg, meta)
	release := &audit.PreviousRelease{
		Version:       previous,
		Static:        audit.AnalyzeStatic(pkg),
		Dependencies:  manifest.Dependencies,
		Publisher:     meta.Publisher(),
		HadProvenance: meta.Dist.Attestations != nil,
	}
	s.mu.Lock()
	if len(s.previous) > 2048 {
		s.previous = map[string]*audit.PreviousRelease{}
	}
	s.previous[key] = release
	s.mu.Unlock()
	return release
}

type packageJSON struct {
	Name                 string                     `json:"name"`
	Version              string                     `json:"version"`
	Description          any                        `json:"description"`
	Dependencies         map[string]any             `json:"dependencies"`
	OptionalDependencies map[string]any             `json:"optionalDependencies"`
	PeerDependencies     map[string]any             `json:"peerDependencies"`
	PeerDependenciesMeta map[string]map[string]any  `json:"peerDependenciesMeta"`
	Bin                  json.RawMessage            `json:"bin"`
	OS                   any                        `json:"os"`
	CPU                  any                        `json:"cpu"`
	Repository           json.RawMessage            `json:"repository"`
	Directories          map[string]json.RawMessage `json:"directories"`
}

// NormalizeManifest builds the signed manifest from the tarball's own
// package.json (what actually runs), and reports where the upstream registry
// metadata disagrees with it ("manifest confusion").
func NormalizeManifest(pkg *canon.Package, meta npm.VersionMeta) (registry.PackageManifest, []string) {
	var raw packageJSON
	if file, ok := pkg.Files["package.json"]; ok {
		_ = json.Unmarshal(file.Data, &raw)
	}
	manifest := registry.PackageManifest{
		Name:                 meta.Name,
		Version:              meta.Version,
		Dependencies:         stringMap(raw.Dependencies),
		OptionalDependencies: stringMap(raw.OptionalDependencies),
		PeerDependencies:     stringMap(raw.PeerDependencies),
		Bin:                  npm.BinEntries(meta.Name, raw.Bin),
		OS:                   stringList(raw.OS),
		CPU:                  stringList(raw.CPU),
		InstallScripts:       audit.InstallScripts(audit.ParseManifest(pkg.Files), pkg.Files),
		Deprecated:           meta.IsDeprecated(),
		Repository:           npm.RepositoryURL(raw.Repository),
	}
	if description, ok := raw.Description.(string); ok {
		manifest.Description = description
	}
	for name, meta := range raw.PeerDependenciesMeta {
		if optional, _ := meta["optional"].(bool); optional {
			manifest.PeerOptional = append(manifest.PeerOptional, name)
		}
	}
	sort.Strings(manifest.PeerOptional)
	// npm also installs optional dependencies listed only in "dependencies".
	for name := range manifest.OptionalDependencies {
		delete(manifest.Dependencies, name)
	}

	var mismatches []string
	if raw.Name != "" && raw.Name != meta.Name {
		mismatches = append(mismatches, fmt.Sprintf("name: registry says %q, tarball says %q", meta.Name, raw.Name))
	}
	if raw.Version != "" && raw.Version != meta.Version {
		mismatches = append(mismatches, fmt.Sprintf("version: registry says %q, tarball says %q", meta.Version, raw.Version))
	}
	if !sameKeys(union(meta.Dependencies, meta.OptionalDependencies), union(stringMap(raw.Dependencies), stringMap(raw.OptionalDependencies))) {
		mismatches = append(mismatches, "dependencies differ between registry metadata and tarball")
	}
	registryScripts := map[string]bool{}
	for name, value := range meta.Scripts {
		if text, ok := value.(string); ok && text != "" {
			registryScripts[name] = true
		}
	}
	for name := range manifest.InstallScripts {
		if !registryScripts[name] && name != "install" {
			mismatches = append(mismatches, "install script "+name+" present in tarball but hidden from registry metadata")
		}
	}
	return manifest, mismatches
}

func executables(bin map[string]string) []registry.Executable {
	names := make([]string, 0, len(bin))
	for name := range bin {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]registry.Executable, 0, len(names))
	for _, name := range names {
		out = append(out, registry.Executable{
			Command:     name,
			Entry:       strings.TrimPrefix(bin[name], "./"),
			Permissions: json.RawMessage(`{"filesystem":["read:cwd","write:cwd"],"network":false,"env":[]}`),
		})
	}
	return out
}

func stringMap(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, value := range in {
		if text, ok := value.(string); ok {
			out[key] = text
		}
	}
	return out
}

func stringList(in any) []string {
	switch value := in.(type) {
	case string:
		return []string{value}
	case []any:
		var out []string
		for _, item := range value {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}

func union(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for key, value := range m {
			out[key] = value
		}
	}
	return out
}

func sameKeys(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}
