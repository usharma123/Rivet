package npm

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

var ErrUnsupportedSpec = errors.New("unsupported dependency spec")

type SelectOptions struct {
	// MinAge excludes versions published more recently than this (cooldown).
	MinAge time.Duration
	Now    time.Time
	// Prefer lists versions already chosen elsewhere in the graph; the first
	// eligible one that satisfies the spec wins, which deduplicates the tree.
	Prefer []string
	// Exclude reports whether a version must be skipped and why.
	Exclude func(version string) (bool, string)
}

type Selection struct {
	Version string   `json:"version"`
	Skipped []string `json:"skipped,omitempty"`
}

// CheckSpec rejects dependency specs that bypass the registry (git, URLs,
// local paths). Those are a common supply-chain vector and cannot be audited.
func CheckSpec(spec string) error {
	lower := strings.ToLower(strings.TrimSpace(spec))
	for _, prefix := range []string{"git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:", "http:", "https:", "file:", "link:", "workspace:", "portal:", "patch:"} {
		if strings.HasPrefix(lower, prefix) {
			return fmt.Errorf("%w: %q does not resolve through a registry", ErrUnsupportedSpec, spec)
		}
	}
	if strings.Contains(lower, "/") && !strings.ContainsAny(lower, "<>=^~| ") {
		return fmt.Errorf("%w: %q looks like a hosted git shorthand", ErrUnsupportedSpec, spec)
	}
	if strings.HasPrefix(lower, "npm:") {
		return fmt.Errorf("%w: aliases must be expanded by the client", ErrUnsupportedSpec)
	}
	return nil
}

// Select picks a version for spec (a dist-tag, exact version or range).
func Select(p *Packument, spec string, opts SelectOptions) (Selection, error) {
	spec = strings.TrimSpace(spec)
	if err := CheckSpec(spec); err != nil {
		return Selection{}, err
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	var constraint *semver.Constraints
	var preferTag string
	if tagVersion, ok := p.DistTags[spec]; ok {
		preferTag = tagVersion
		tag, err := semver.StrictNewVersion(tagVersion)
		if err != nil {
			return Selection{}, fmt.Errorf("dist-tag %s points at invalid version %q", spec, tagVersion)
		}
		expr := "<=" + tagVersion
		if tag.Prerelease() != "" {
			expr = fmt.Sprintf(">=%d.%d.%d-0 <=%s", tag.Major(), tag.Minor(), tag.Patch(), tagVersion)
		}
		constraint, err = semver.NewConstraint(expr)
		if err != nil {
			return Selection{}, err
		}
	} else {
		expr := normalizeRange(spec)
		parsed, err := semver.NewConstraint(expr)
		if err != nil {
			if _, exact := p.Versions[spec]; !exact {
				return Selection{}, fmt.Errorf("%w: cannot parse range %q: %v", ErrUnsupportedSpec, spec, err)
			}
			parsed, _ = semver.NewConstraint("=" + spec)
		}
		constraint = parsed
	}

	var skipped []string
	eligible := func(version string) bool {
		if _, ok := p.Versions[version]; !ok {
			return false
		}
		if opts.MinAge > 0 {
			if published, ok := p.PublishedAt(version); ok && opts.Now.Sub(published) < opts.MinAge {
				skipped = append(skipped, fmt.Sprintf("%s: published %s ago, inside %s cooldown", version, opts.Now.Sub(published).Round(time.Minute), opts.MinAge))
				return false
			}
		}
		if opts.Exclude != nil {
			if excluded, reason := opts.Exclude(version); excluded {
				skipped = append(skipped, fmt.Sprintf("%s: %s", version, reason))
				return false
			}
		}
		return true
	}

	for _, preferred := range opts.Prefer {
		version, err := semver.StrictNewVersion(preferred)
		if err == nil && constraint.Check(version) && eligible(preferred) {
			return Selection{Version: preferred, Skipped: skipped}, nil
		}
	}
	if preferTag != "" && eligible(preferTag) {
		return Selection{Version: preferTag, Skipped: skipped}, nil
	}

	candidates := make([]*semver.Version, 0, len(p.Versions))
	for raw := range p.Versions {
		version, err := semver.StrictNewVersion(raw)
		if err != nil || !constraint.Check(version) {
			continue
		}
		candidates = append(candidates, version)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].GreaterThan(candidates[j]) })
	for _, candidate := range candidates {
		if candidate.Original() == preferTag {
			continue
		}
		if eligible(candidate.Original()) {
			return Selection{Version: candidate.Original(), Skipped: skipped}, nil
		}
	}
	if len(skipped) > 0 {
		return Selection{Skipped: skipped}, fmt.Errorf("no eligible version of %s satisfies %q (%s)", p.Name, spec, strings.Join(skipped, "; "))
	}
	return Selection{}, fmt.Errorf("no version of %s satisfies %q", p.Name, spec)
}

// Candidates lists versions satisfying spec, newest first, without applying
// any policy. The registry uses it to find a previous release for diffing.
func PreviousVersion(p *Packument, version string) string {
	current, err := semver.StrictNewVersion(version)
	if err != nil {
		return ""
	}
	var best *semver.Version
	for raw := range p.Versions {
		candidate, err := semver.StrictNewVersion(raw)
		if err != nil || candidate.Prerelease() != "" || !candidate.LessThan(current) {
			continue
		}
		if best == nil || candidate.GreaterThan(best) {
			best = candidate
		}
	}
	if best == nil {
		return ""
	}
	return best.Original()
}

func normalizeRange(spec string) string {
	switch strings.ToLower(spec) {
	case "", "*", "x", "latest":
		return "*"
	}
	// npm allows "x" wildcards and bare comparators with spaces ("> 1.0");
	// Masterminds handles both, but not a trailing "||".
	return strings.TrimSuffix(strings.TrimSpace(spec), "||")
}

// VersionGreater reports a > b for semver strings; invalid versions sort low.
func VersionGreater(a, b string) bool {
	left, err := semver.StrictNewVersion(a)
	if err != nil {
		return false
	}
	right, err := semver.StrictNewVersion(b)
	if err != nil {
		return true
	}
	return left.GreaterThan(right)
}
