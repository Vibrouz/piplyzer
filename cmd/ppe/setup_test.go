package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupHandlerCreatesApp(t *testing.T) {
	var gotPath string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"id":123,"slug":"ppe-x","pem":"PEMDATA","webhook_secret":"sekret"}`)
	}))
	defer fake.Close()

	dir := filepath.Join(t.TempDir(), "ppe")
	handler, results := newSetupHandler("state", `{"name":"x"}`, dir, fake.URL)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?code=code&state=state", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	res := <-results
	if res.err != nil {
		t.Fatalf("setup: %v", res.err)
	}
	if res.slug != "ppe-x" {
		t.Errorf("slug = %q", res.slug)
	}
	if gotPath != "/app-manifests/code/conversions" {
		t.Errorf("conversion path = %q", gotPath)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("config dir mode = %o, want 700", info.Mode().Perm())
	}

	keyPath := filepath.Join(dir, "app.pem")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != "PEMDATA\n" {
		t.Errorf("key = %q", key)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o, want 600", keyInfo.Mode().Perm())
	}

	configPath := filepath.Join(dir, "config.env")
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PPE_APP_ID=123\n",
		"PPE_WEBHOOK_SECRET=sekret\n",
		"PPE_APP_SLUG=ppe-x\n",
		"PPE_PRIVATE_KEY_PATH='" + keyPath + "'\n",
	} {
		if !strings.Contains(string(config), want) {
			t.Errorf("config is missing %q:\n%s", want, config)
		}
	}
	configInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if configInfo.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %o, want 600", configInfo.Mode().Perm())
	}
}

func TestSetupHandlerRejectsWrongState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ppe")
	handler, results := newSetupHandler("state", `{}`, dir, "http://127.0.0.1:1")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?code=code&state=wrong", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.env")); !os.IsNotExist(err) {
		t.Errorf("credentials were written: %v", err)
	}
	select {
	case res := <-results:
		t.Fatalf("unexpected result: %+v", res)
	default:
	}
}

func TestSetupPageCarriesManifestAndState(t *testing.T) {
	handler, _ := newSetupHandler("state", `{"name":"x"}`, t.TempDir(), "http://127.0.0.1:1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	body := rec.Body.String()
	for _, want := range []string{"settings/apps/new?state=state", `name="manifest"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q:\n%s", want, body)
		}
	}
}

func TestShellValue(t *testing.T) {
	got := shellValue("/tmp/a b/it's")
	want := `'/tmp/a b/it'\''s'`
	if got != want {
		t.Errorf("shellValue = %s, want %s", got, want)
	}
}

// GitHub rejects a manifest without a hook, even though the real URL is not
// known until the runner has a tunnel.
func TestManifestHasHook(t *testing.T) {
	manifest, err := newManifest("http://127.0.0.1:8081/callback", "https://example.com/ppe-webhook")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.HookAttributes == nil || manifest.HookAttributes.URL == "" || !manifest.HookAttributes.Active {
		t.Errorf("hook attributes = %+v", manifest.HookAttributes)
	}
}
