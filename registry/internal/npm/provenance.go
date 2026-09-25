package npm

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func supportedSLSA(value string) bool {
	return value == "https://slsa.dev/provenance/v1" || value == "https://slsa.dev/provenance/v0.2"
}

type ProvenanceStatus string

const (
	// ProvenanceVerified: a Sigstore bundle verified against the public-good
	// trust root and binds this exact tarball to a CI build.
	ProvenanceVerified ProvenanceStatus = "verified"
	// ProvenanceAbsent: npm has no provenance for this version.
	ProvenanceAbsent ProvenanceStatus = "absent"
	// ProvenanceInvalid: provenance was advertised but did not verify.
	ProvenanceInvalid ProvenanceStatus = "invalid"
	// ProvenanceUnverifiable: provenance exists but the trust root could not be
	// loaded, so nothing is claimed either way.
	ProvenanceUnverifiable ProvenanceStatus = "unverifiable"
)

type Provenance struct {
	Status        ProvenanceStatus `json:"status"`
	SourceRepo    string           `json:"source_repo,omitempty"`
	SourceCommit  string           `json:"source_commit,omitempty"`
	SourceRef     string           `json:"source_ref,omitempty"`
	BuildSigner   string           `json:"build_signer,omitempty"`
	Issuer        string           `json:"issuer,omitempty"`
	DeclaredRepo  string           `json:"declared_repo,omitempty"`
	RepoMatches   *bool            `json:"repo_matches,omitempty"`
	Detail        string           `json:"detail,omitempty"`
	PredicateType string           `json:"predicate_type,omitempty"`
}

// ProvenanceVerifier checks npm's Sigstore provenance bundles.
// The Sigstore trusted root is fetched lazily, once, via TUF.
type ProvenanceVerifier struct {
	client *Client
	once   sync.Once
	root   root.TrustedMaterial
	err    error
}

func NewProvenanceVerifier(client *Client) *ProvenanceVerifier {
	return &ProvenanceVerifier{client: client}
}

func (v *ProvenanceVerifier) trustedRoot() (root.TrustedMaterial, error) {
	v.once.Do(func() {
		v.root, v.err = root.FetchTrustedRoot()
	})
	return v.root, v.err
}

type attestationsResponse struct {
	Attestations []struct {
		PredicateType string          `json:"predicateType"`
		Bundle        json.RawMessage `json:"bundle"`
	} `json:"attestations"`
}

func (v *ProvenanceVerifier) Verify(ctx context.Context, meta VersionMeta, tarball []byte) Provenance {
	declared := RepositoryURL(meta.Repository)
	result := Provenance{Status: ProvenanceAbsent, DeclaredRepo: declared}
	if meta.Dist.Attestations == nil || meta.Dist.Attestations.URL == "" {
		return result
	}
	result.PredicateType = meta.Dist.Attestations.Provenance.PredicateType
	var response attestationsResponse
	if err := v.client.FetchJSON(ctx, meta.Dist.Attestations.URL, 16<<20, &response); err != nil {
		result.Status = ProvenanceUnverifiable
		result.Detail = "fetch attestations: " + err.Error()
		return result
	}
	var raw json.RawMessage
	for _, attestation := range response.Attestations {
		if supportedSLSA(attestation.PredicateType) {
			raw = attestation.Bundle
			result.PredicateType = attestation.PredicateType
			break
		}
	}
	if raw == nil {
		result.Status = ProvenanceInvalid
		result.Detail = "attestations advertised but no SLSA provenance bundle present"
		return result
	}
	material, err := v.trustedRoot()
	if err != nil {
		result.Status = ProvenanceUnverifiable
		result.Detail = "load sigstore trusted root: " + err.Error()
		return result
	}
	summary, err := verifyBundle(material, raw, meta, tarball, result.PredicateType)
	if err != nil {
		result.Status = ProvenanceInvalid
		result.Detail = err.Error()
		return result
	}
	summary.DeclaredRepo = declared
	if declared != "" && summary.SourceRepo != "" {
		matches := SameRepository(declared, summary.SourceRepo)
		summary.RepoMatches = &matches
	}
	return summary
}

func verifyBundle(material root.TrustedMaterial, raw json.RawMessage, meta VersionMeta, tarball []byte, wrapperPredicate string) (Provenance, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return Provenance{}, fmt.Errorf("decode provenance bundle: %w", err)
	}
	verifier, err := verify.NewVerifier(material,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return Provenance{}, err
	}
	identity, err := verify.NewShortCertificateIdentity("", `^https://(token\.actions\.githubusercontent\.com|gitlab\.com)$`, "", ".+")
	if err != nil {
		return Provenance{}, err
	}
	digest := sha512.Sum512(tarball)
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha512", digest[:]), verify.WithCertificateIdentity(identity))
	outcome, err := verifier.Verify(&b, policy)
	if err != nil {
		return Provenance{}, fmt.Errorf("sigstore verification failed: %w", err)
	}
	if outcome.Statement == nil {
		return Provenance{}, errors.New("provenance bundle has no in-toto statement")
	}
	if !supportedSLSA(outcome.Statement.PredicateType) || outcome.Statement.PredicateType != wrapperPredicate {
		return Provenance{}, fmt.Errorf("signed predicate type %q does not match supported SLSA wrapper %q", outcome.Statement.PredicateType, wrapperPredicate)
	}
	expected := PackageURL(meta.Name, meta.Version)
	if !subjectBindsArtifact(outcome.Statement.Subject, expected, hex.EncodeToString(digest[:])) {
		return Provenance{}, fmt.Errorf("provenance subject does not bind %s to the tarball sha512", expected)
	}
	out := Provenance{Status: ProvenanceVerified}
	if outcome.Signature != nil && outcome.Signature.Certificate != nil {
		cert := outcome.Signature.Certificate
		out.SourceRepo = cert.SourceRepositoryURI
		out.SourceCommit = cert.SourceRepositoryDigest
		out.SourceRef = cert.SourceRepositoryRef
		out.BuildSigner = cert.BuildSignerURI
		out.Issuer = cert.Issuer
	}
	return out, nil
}

func subjectBindsArtifact(subjects []*in_toto.ResourceDescriptor, name, sha512Hex string) bool {
	for _, subject := range subjects {
		if subject != nil && subject.Name == name && strings.EqualFold(subject.Digest["sha512"], sha512Hex) {
			return true
		}
	}
	return false
}

// PackageURL renders the purl npm uses as the provenance subject.
func PackageURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		return "pkg:npm/%40" + name[1:] + "@" + version
	}
	return "pkg:npm/" + name + "@" + version
}

// SameRepository compares repository URLs across git+https, ssh and shorthand forms.
func SameRepository(a, b string) bool {
	return normalizeRepo(a) != "" && normalizeRepo(a) == normalizeRepo(b)
}

func normalizeRepo(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "git+")
	value = strings.TrimSuffix(value, "/")
	value = strings.TrimSuffix(value, ".git")
	if strings.HasPrefix(value, "github:") {
		value = "https://github.com/" + strings.TrimPrefix(value, "github:")
	}
	if strings.HasPrefix(value, "git@") {
		value = "https://" + strings.Replace(strings.TrimPrefix(value, "git@"), ":", "/", 1)
	}
	if !strings.Contains(value, "://") && strings.Count(value, "/") == 1 {
		value = "https://github.com/" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return ""
	}
	path := strings.Trim(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}
	return parsed.Hostname() + "/" + parts[0] + "/" + parts[1]
}
