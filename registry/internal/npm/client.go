// Package npm talks to the upstream npm registry on behalf of the Rivet
// mirror. Everything fetched here is treated as untrusted input: tarballs are
// only fetched from the configured registry host, integrity is always checked,
// and responses are size-limited.
package npm

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	DefaultRegistry   = "https://registry.npmjs.org"
	maxPackumentBytes = 128 << 20
	maxTarballBytes   = 256 << 20
	packumentTTL      = 5 * time.Minute
)

var (
	ErrNotFound  = errors.New("npm package not found")
	ErrIntegrity = errors.New("npm tarball integrity mismatch")
)

type Packument struct {
	Name     string                 `json:"name"`
	DistTags map[string]string      `json:"dist-tags"`
	Versions map[string]VersionMeta `json:"versions"`
	Time     map[string]string      `json:"time"`
}

type Person struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

type VersionMeta struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Description          string            `json:"description,omitempty"`
	Dist                 Dist              `json:"dist"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
	PeerDependenciesMeta map[string]struct {
		Optional bool `json:"optional"`
	} `json:"peerDependenciesMeta,omitempty"`
	Bin        json.RawMessage `json:"bin,omitempty"`
	Scripts    map[string]any  `json:"scripts,omitempty"`
	OS         []string        `json:"os,omitempty"`
	CPU        []string        `json:"cpu,omitempty"`
	Deprecated json.RawMessage `json:"deprecated,omitempty"`
	Repository json.RawMessage `json:"repository,omitempty"`
	NpmUser    *Person         `json:"_npmUser,omitempty"`
}

type Dist struct {
	Tarball      string        `json:"tarball"`
	Integrity    string        `json:"integrity,omitempty"`
	Shasum       string        `json:"shasum,omitempty"`
	Attestations *Attestations `json:"attestations,omitempty"`
}

type Attestations struct {
	URL        string `json:"url"`
	Provenance struct {
		PredicateType string `json:"predicateType"`
	} `json:"provenance"`
}

type Client struct {
	base *url.URL
	// DownloadsURL is npm's download-count API; empty disables lookups.
	DownloadsURL string
	http         *http.Client
	mu           sync.Mutex
	packuments   map[string]cachedPackument
	now          func() time.Time
}

type cachedPackument struct {
	value   *Packument
	fetched time.Time
}

func NewClient(baseURL string) (*Client, error) {
	if baseURL == "" {
		baseURL = DefaultRegistry
	}
	base, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, err
	}
	if base.Scheme != "https" && base.Hostname() != "127.0.0.1" && base.Hostname() != "localhost" {
		return nil, fmt.Errorf("npm upstream must use https: %s", baseURL)
	}
	downloads := ""
	if base.String() == DefaultRegistry {
		downloads = "https://api.npmjs.org"
	}
	return &Client{
		base:         base,
		DownloadsURL: downloads,
		http: &http.Client{Timeout: 120 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host {
				return fmt.Errorf("redirect outside configured npm registry: %s", req.URL)
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many npm redirects")
			}
			return nil
		}},
		packuments: map[string]cachedPackument{},
		now:        time.Now,
	}, nil
}

func (c *Client) BaseURL() string { return c.base.String() }

// ValidName rejects names npm itself would never publish, which also keeps
// them safe to embed in URLs and file names.
func ValidName(name string) bool {
	if name == "" || len(name) > 214 || strings.TrimSpace(name) != name {
		return false
	}
	rest := name
	if strings.HasPrefix(name, "@") {
		scope, pkg, ok := strings.Cut(name[1:], "/")
		if !ok || scope == "" || pkg == "" || strings.Contains(pkg, "/") || scope == "." || scope == ".." || pkg == "." || pkg == ".." || strings.HasPrefix(scope, ".") || strings.HasPrefix(pkg, ".") || strings.HasPrefix(scope, "_") || strings.HasPrefix(pkg, "_") {
			return false
		}
		rest = scope + pkg
	} else if strings.Contains(name, "/") {
		return false
	}
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return false
	}
	for _, ch := range rest {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case strings.ContainsRune("-._~!*'()", ch):
		default:
			return false
		}
	}
	return true
}

// ValidCommand permits a single, portable command filename. Package metadata
// must never become executable shell syntax or an option-like shim name.
func ValidCommand(command string) bool {
	if command == "" || len(command) > 214 || command[0] == '-' || command[0] == '.' {
		return false
	}
	for _, ch := range command {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.' {
			continue
		}
		return false
	}
	return true
}

func (c *Client) Packument(ctx context.Context, name string) (*Packument, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid npm package name %q", name)
	}
	c.mu.Lock()
	cached, ok := c.packuments[name]
	c.mu.Unlock()
	if ok && c.now().Sub(cached.fetched) < packumentTTL {
		return cached.value, nil
	}
	endpoint := c.base.String() + "/" + strings.Replace(url.PathEscape(name), "%2F", "%2f", 1)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch npm metadata for %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm metadata for %s: status %d", name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPackumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPackumentBytes {
		return nil, fmt.Errorf("npm metadata for %s exceeds size limit", name)
	}
	var packument Packument
	if err := json.Unmarshal(body, &packument); err != nil {
		return nil, fmt.Errorf("decode npm metadata for %s: %w", name, err)
	}
	if packument.Name != name {
		return nil, fmt.Errorf("npm metadata name mismatch: asked for %s, got %s", name, packument.Name)
	}
	c.mu.Lock()
	c.packuments[name] = cachedPackument{value: &packument, fetched: c.now()}
	c.mu.Unlock()
	return &packument, nil
}

// PublishedAt returns the upstream publish time for a version, if known.
func (p *Packument) PublishedAt(version string) (time.Time, bool) {
	value, ok := p.Time[version]
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// Tarball downloads a version tarball and verifies it against the upstream
// integrity metadata. It returns the bytes and the algorithm that was checked.
func (c *Client) Tarball(ctx context.Context, meta VersionMeta) ([]byte, string, error) {
	tarballURL, err := url.Parse(meta.Dist.Tarball)
	if err != nil {
		return nil, "", fmt.Errorf("invalid tarball url: %w", err)
	}
	if tarballURL.Scheme != c.base.Scheme || tarballURL.Host != c.base.Host {
		return nil, "", fmt.Errorf("tarball host %q is not the configured npm registry", tarballURL.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL.String(), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("download tarball: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("download tarball: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTarballBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > maxTarballBytes {
		return nil, "", errors.New("tarball exceeds size limit")
	}
	algorithm, err := VerifyIntegrity(body, meta.Dist)
	if err != nil {
		return nil, "", err
	}
	return body, algorithm, nil
}

// VerifyIntegrity checks the strongest digest npm published for the tarball.
// It never silently skips: a tarball without any recognised digest is rejected.
func VerifyIntegrity(data []byte, dist Dist) (string, error) {
	for _, entry := range strings.Fields(dist.Integrity) {
		algorithm, encoded, ok := strings.Cut(entry, "-")
		if !ok || algorithm != "sha512" {
			continue
		}
		sum := sha512.Sum512(data)
		if base64.StdEncoding.EncodeToString(sum[:]) != encoded {
			return "", fmt.Errorf("%w (sha512)", ErrIntegrity)
		}
		return "sha512", nil
	}
	if dist.Shasum != "" {
		sum := sha1.Sum(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), dist.Shasum) {
			return "", fmt.Errorf("%w (sha1)", ErrIntegrity)
		}
		return "sha1", nil
	}
	return "", fmt.Errorf("%w: no sha512 integrity or sha1 shasum published", ErrIntegrity)
}

func (c *Client) FetchJSON(ctx context.Context, rawURL string, limit int64, into any) error {
	target, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if target.Scheme != c.base.Scheme || target.Host != c.base.Host {
		return fmt.Errorf("refusing to fetch %q from outside the npm registry", target.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: status %d", target.Path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(into)
}

// BinEntries normalises the package.json "bin" field.
func BinEntries(name string, raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single != "" {
			command := name
			if i := strings.LastIndex(command, "/"); i >= 0 {
				command = command[i+1:]
			}
			if ValidCommand(command) {
				out[command] = single
			}
		}
		return out
	}
	var many map[string]string
	if err := json.Unmarshal(raw, &many); err == nil {
		for command, entry := range many {
			if ValidCommand(command) && entry != "" {
				out[command] = entry
			}
		}
	}
	return out
}

// RepositoryURL extracts a declared repository URL from package.json.
func RepositoryURL(raw json.RawMessage) string {
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

func (v VersionMeta) IsDeprecated() bool {
	if len(v.Deprecated) == 0 {
		return false
	}
	var text string
	if err := json.Unmarshal(v.Deprecated, &text); err == nil {
		return text != ""
	}
	var flag bool
	if err := json.Unmarshal(v.Deprecated, &flag); err == nil {
		return flag
	}
	return false
}

func (v VersionMeta) Publisher() string {
	if v.NpmUser == nil {
		return ""
	}
	return v.NpmUser.Name
}

// WeeklyDownloads returns last week's download count, or nil when unknown.
func (c *Client) WeeklyDownloads(ctx context.Context, name string) *int64 {
	if c.DownloadsURL == "" || !ValidName(name) {
		return nil
	}
	endpoint := c.DownloadsURL + "/downloads/point/last-week/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body struct {
		Downloads int64 `json:"downloads"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return nil
	}
	return &body.Downloads
}
