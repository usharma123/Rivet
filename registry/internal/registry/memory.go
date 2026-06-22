package registry

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

type MemoryStore struct {
	mu       sync.Mutex
	packages map[string]PackageRecord
	versions map[string]VersionRecord
	evals    []EvalRecord
	now      func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		packages: map[string]PackageRecord{},
		versions: map[string]VersionRecord{},
		now:      time.Now,
	}
}

func (s *MemoryStore) GetPackage(_ context.Context, name string) (PackageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pkg, ok := s.packages[name]
	if !ok {
		return PackageRecord{}, ErrNotFound
	}
	for _, version := range s.versions {
		if version.Name == name {
			pkg.Versions = append(pkg.Versions, version)
		}
	}
	sort.Slice(pkg.Versions, func(i, j int) bool {
		return pkg.Versions[i].PublishedAt.After(pkg.Versions[j].PublishedAt)
	})
	return pkg, nil
}

func (s *MemoryStore) GetVersion(_ context.Context, name, version string) (VersionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.versions[key(name, version)]
	if !ok {
		return VersionRecord{}, ErrNotFound
	}
	return record, nil
}

func (s *MemoryStore) FindExecutable(_ context.Context, command string) (VersionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, version := range s.versions {
		for _, executable := range version.Executables {
			if executable.Command == command {
				return version, nil
			}
		}
	}
	return VersionRecord{}, ErrNotFound
}

func (s *MemoryStore) Search(_ context.Context, query string) ([]PackageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query = strings.ToLower(query)
	var out []PackageRecord
	for _, pkg := range s.packages {
		if query == "" || strings.Contains(strings.ToLower(pkg.Name), query) {
			out = append(out, pkg)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (s *MemoryStore) UpsertVersion(_ context.Context, version VersionRecord) (VersionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	version.State = NormalizeState(version.State)
	if err := ValidateReleaseState(version.State); err != nil {
		return VersionRecord{}, err
	}
	if version.PublishedAt.IsZero() {
		if old, ok := s.versions[key(version.Name, version.Version)]; ok {
			version.PublishedAt = old.PublishedAt
		} else {
			version.PublishedAt = now
		}
	}
	s.packages[version.Name] = PackageRecord{
		Name:      version.Name,
		Source:    version.Source,
		Publisher: version.Publisher,
		CreatedAt: now,
	}
	s.versions[key(version.Name, version.Version)] = version
	return version, nil
}

func (s *MemoryStore) SetReleaseState(_ context.Context, name, version string, state ReleaseState, req StateChangeRequest) (VersionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.versions[key(name, version)]
	if !ok {
		return VersionRecord{}, ErrNotFound
	}
	if err := AllowStateChange(record, state, req, s.now()); err != nil {
		return VersionRecord{}, err
	}
	record.State = state
	record.RevokeReason = req.Reason
	record.ReplacementVersion = req.ReplacementVersion
	if state == StateRevoked {
		now := s.now()
		record.RevokedAt = &now
	}
	s.versions[key(name, version)] = record
	return record, nil
}

func (s *MemoryStore) CreateEval(_ context.Context, eval EvalRecord) (EvalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if eval.CreatedAt.IsZero() {
		eval.CreatedAt = s.now()
	}
	s.evals = append(s.evals, eval)
	return eval, nil
}

func key(name, version string) string {
	return name + "@" + version
}
