package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/usharma123/rivet/registry/internal/artifacts"
	"github.com/usharma123/rivet/registry/internal/registry"
)

func TestPublishRequiresDevToken(t *testing.T) {
	handler := testServer(t)
	body := bytes.NewBufferString(`{"manifest":{},"artifact_hash":"sha512-test"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/packages/demo/0.1.0/publish", body)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPublishGetRevokeFlow(t *testing.T) {
	handler := testServer(t)
	publish := `{
		"source": "native",
		"publisher": "github:usharma123/demo",
		"manifest": {"package":{"name":"demo","version":"0.1.0"}},
		"artifact_hash": "sha512-demo",
		"executables": [{"command":"demo","entry":"./bin/demo.js"}]
	}`
	req := authedRequest(http.MethodPost, "/v1/packages/demo/0.1.0/publish", publish)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish failed: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/executables/demo", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("executable lookup failed: %d %s", rec.Code, rec.Body.String())
	}

	req = authedRequest(http.MethodPost, "/v1/packages/demo/0.1.0/revoke", `{"reason":"bad build"}`)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d %s", rec.Code, rec.Body.String())
	}
	var got registry.VersionRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.State != registry.StateRevoked || got.RevokeReason != "bad build" {
		t.Fatalf("unexpected revoke result: %#v", got)
	}
}

func TestArtifactPutGet(t *testing.T) {
	handler := testServer(t)
	req := authedRequest(http.MethodPut, "/v1/artifacts/sha512-artifact", "artifact bytes")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("put failed: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/artifacts/sha512-artifact", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "artifact bytes" {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}

func testServer(t *testing.T) http.Handler {
	t.Helper()
	root := filepath.Join(t.TempDir(), "artifacts")
	store, err := artifacts.NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return NewServer(registry.NewMemoryStore(), store, "dev-token")
}

func authedRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer dev-token")
	req.Header.Set("Content-Type", "application/json")
	return req
}
