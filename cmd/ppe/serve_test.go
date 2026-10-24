package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Vibrouz/whoa/internal/appauth"
	"github.com/Vibrouz/whoa/internal/repofetch"
	"github.com/Vibrouz/whoa/internal/webhook"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	testKeyErr  error
)

func appKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		testKey, testKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if testKeyErr != nil {
		t.Fatal(testKeyErr)
	}
	return testKey
}

type tarEntry struct {
	name string
	body string
}

func testTarball(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	if err := tw.WriteHeader(&tar.Header{Name: "repo-sha/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     "repo-sha/" + e.name,
			Mode:     0o644,
			Size:     int64(len(e.body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeGitHub answers the three calls a scan makes.
type fakeGitHub struct {
	t        *testing.T
	tarballs map[string][]byte
	checks   []map[string]any
	mints    int
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/app/installations/1/access_tokens":
		f.mints++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			f.t.Error("the mint request has no app token")
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "tok",
			"expires_at": time.Now().Add(time.Hour),
		})

	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tar.gz/"):
		body, ok := f.tarballs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/check-runs"):
		if r.Header.Get("Authorization") != "Bearer tok" {
			f.t.Errorf("check run authorization is %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Fatal(err)
		}
		f.checks = append(f.checks, body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":1}`))

	default:
		http.NotFound(w, r)
	}
}

func serveCleanWorkflow() string {
	return "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
}

func serveInjectionWorkflow() string {
	return "name: ci\non: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n"
}

func delivery() webhook.Delivery {
	return webhook.Delivery{
		Event:          "pull_request",
		ID:             "delivery-1",
		Action:         "opened",
		InstallationID: 1,
		Repo:           "o/r",
		Owner:          "o",
		Name:           "r",
		Number:         2,
		HeadSHA:        "sha",
		BaseSHA:        "base",
		HeadRepo:       "o/r",
	}
}

func runDelivery(t *testing.T, gh *fakeGitHub, d webhook.Delivery) []map[string]any {
	t.Helper()
	if gh.tarballs == nil {
		gh.tarballs = map[string][]byte{}
	}
	gh.t = t
	server := httptest.NewServer(gh)
	defer server.Close()

	sc := &scanner{
		auth: appauth.NewClient(
			appauth.Config{AppID: 1, Key: appKey(t)},
			appauth.WithBaseURL(server.URL),
		),
		fetcher: &repofetch.Fetcher{
			Client:        server.Client(),
			BaseURL:       server.URL,
			MaxCompressed: 1 << 20,
			MaxExtracted:  1 << 20,
			MaxFiles:      100,
		},
		checkBaseURL: server.URL,
		timeout:      10 * time.Second,
		log:          log.New(io.Discard, "", 0),
	}
	sc.process(context.Background(), d)
	return gh.checks
}

func conclusionOf(t *testing.T, check map[string]any) string {
	t.Helper()
	got, _ := check["conclusion"].(string)
	if got == "" {
		t.Fatalf("check has no conclusion: %v", check)
	}
	return got
}

func outputOf(t *testing.T, check map[string]any) map[string]any {
	t.Helper()
	out, ok := check["output"].(map[string]any)
	if !ok {
		t.Fatalf("check has no output: %v", check)
	}
	return out
}

func TestScannerPostsACleanCheck(t *testing.T) {
	gh := &fakeGitHub{tarballs: map[string][]byte{
		"/o/r/tar.gz/sha": testTarball(t,
			tarEntry{name: ".github/workflows/ci.yml", body: serveCleanWorkflow()},
		),
	}}
	checks := runDelivery(t, gh, delivery())

	if len(checks) != 1 {
		t.Fatalf("posted %d checks, want 1", len(checks))
	}
	if got := conclusionOf(t, checks[0]); got != "success" {
		t.Errorf("conclusion is %q, want success", got)
	}
	if got := checks[0]["name"]; got != "piplyzer" {
		t.Errorf("check name is %v", got)
	}
	if got := checks[0]["head_sha"]; got != "sha" {
		t.Errorf("head sha is %v", got)
	}
	if gh.mints != 1 {
		t.Errorf("minted %d tokens, want 1", gh.mints)
	}
}

func TestScannerPostsAFailureForABlockingFinding(t *testing.T) {
	gh := &fakeGitHub{tarballs: map[string][]byte{
		"/o/r/tar.gz/sha": testTarball(t,
			tarEntry{name: ".github/workflows/ci.yml", body: serveInjectionWorkflow()},
		),
	}}
	checks := runDelivery(t, gh, delivery())

	if len(checks) != 1 {
		t.Fatalf("posted %d checks, want 1", len(checks))
	}
	if got := conclusionOf(t, checks[0]); got != "failure" {
		t.Errorf("conclusion is %q, want failure", got)
	}
	if text, _ := outputOf(t, checks[0])["text"].(string); !strings.Contains(text, "PPE-002") {
		t.Errorf("text does not name the rule: %s", text)
	}
}

func TestScannerPassesWhenThereAreNoWorkflows(t *testing.T) {
	// The tree is the repository root, so no workflows means there is no
	// Actions attack surface to check. A repository that does not use Actions
	// can require the check from day one without blocking every pull request.
	gh := &fakeGitHub{tarballs: map[string][]byte{
		"/o/r/tar.gz/sha": testTarball(t, tarEntry{name: "README.md", body: "hi\n"}),
	}}
	checks := runDelivery(t, gh, delivery())

	if len(checks) != 1 {
		t.Fatalf("posted %d checks, want 1", len(checks))
	}
	if got := conclusionOf(t, checks[0]); got != "success" {
		t.Errorf("conclusion is %q, want success", got)
	}
	if title, _ := outputOf(t, checks[0])["title"].(string); title != "No workflows found" {
		t.Errorf("title is %q", title)
	}
}

func TestScannerFailsWhenTheTreeCannotBeFetched(t *testing.T) {
	gh := &fakeGitHub{}
	checks := runDelivery(t, gh, delivery())

	if len(checks) != 1 {
		t.Fatalf("posted %d checks, want 1", len(checks))
	}
	if got := conclusionOf(t, checks[0]); got != "failure" {
		t.Errorf("conclusion is %q, want failure", got)
	}
	if title, _ := outputOf(t, checks[0])["title"].(string); title != "Could not fetch the pull request" {
		t.Errorf("title is %q", title)
	}
}

func TestScannerFallsBackToTheFork(t *testing.T) {
	gh := &fakeGitHub{tarballs: map[string][]byte{
		"/someone/r/tar.gz/sha": testTarball(t,
			tarEntry{name: ".github/workflows/ci.yml", body: serveCleanWorkflow()},
		),
	}}
	d := delivery()
	d.HeadRepo = "someone/r"
	d.IsFork = true

	checks := runDelivery(t, gh, d)
	if len(checks) != 1 {
		t.Fatalf("posted %d checks, want 1", len(checks))
	}
	if got := conclusionOf(t, checks[0]); got != "success" {
		t.Errorf("conclusion is %q, want success", got)
	}
}

func TestScannerRunsTheDependencyCheck(t *testing.T) {
	lock := `{
		"name": "x",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"requires": true,
		"packages": {
			"": {"name": "x", "version": "1.0.0"},
			"node_modules/evil": {
				"version": "1.0.0",
				"resolved": "https://evil.example.com/evil/-/evil-1.0.0.tgz",
				"integrity": "sha512-x"
			}
		}
	}`
	gh := &fakeGitHub{tarballs: map[string][]byte{
		"/o/r/tar.gz/sha": testTarball(t,
			tarEntry{name: ".github/workflows/ci.yml", body: serveCleanWorkflow()},
			tarEntry{name: ".npmrc", body: "registry=https://registry.npmjs.org/\n"},
			tarEntry{name: "package-lock.json", body: lock},
		),
	}}
	checks := runDelivery(t, gh, delivery())

	if len(checks) != 1 {
		t.Fatalf("posted %d checks, want 1", len(checks))
	}
	if got := conclusionOf(t, checks[0]); got != "failure" {
		t.Errorf("conclusion is %q, want failure", got)
	}
	if text, _ := outputOf(t, checks[0])["text"].(string); !strings.Contains(text, "DEP-D3") {
		t.Errorf("text does not name the dependency rule: %s", text)
	}
}
