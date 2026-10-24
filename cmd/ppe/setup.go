package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// setup creates the GitHub App through the manifest flow and writes the
// credentials where serve expects them. It exists so that a new install is a
// local command rather than a sequence of settings pages: the private key is
// shown exactly once, by GitHub, and it must land on disk before the browser
// tab is closed.
//
// GitHub requires a hook URL in the manifest even though a local setup has no
// public address. The placeholder is replaced by the local runner as soon as
// it has a tunnel.
const (
	setupHomepage        = "https://github.com/Vibrouz/whoa"
	setupAPIBase         = "https://api.github.com"
	setupPlaceholderHook = "https://example.com/ppe-webhook"
)

type hookAttributes struct {
	URL    string `json:"url"`
	Active bool   `json:"active"`
}

type appManifest struct {
	Name               string            `json:"name"`
	URL                string            `json:"url"`
	HookAttributes     *hookAttributes   `json:"hook_attributes,omitempty"`
	RedirectURL        string            `json:"redirect_url"`
	Description        string            `json:"description"`
	Public             bool              `json:"public"`
	DefaultPermissions map[string]string `json:"default_permissions"`
	DefaultEvents      []string          `json:"default_events"`
}

type manifestConversion struct {
	ID            int64  `json:"id"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	PEM           string `json:"pem"`
	WebhookSecret string `json:"webhook_secret"`
}

type setupOptions struct {
	Addr      string
	ConfigDir string
	APIBase   string
	HookURL   string // empty = placeholder
	Out       io.Writer
}

type setupResult struct {
	slug string
	err  error
}

func setup(cmd command, stdout, stderr io.Writer, env func(string) string) int {
	dir, err := setupConfigDir(cmd.configDir, env)
	if err != nil {
		fmt.Fprintf(stderr, "ppe: %v\n", err)
		return exitIncomplete
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = runSetup(ctx, setupOptions{
		Addr:      cmd.addr,
		ConfigDir: dir,
		APIBase:   setupAPIBase,
		HookURL:   cmd.hookUrl,
		Out:       stdout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "ppe: %v\n", err)
		return exitIncomplete
	}
	return exitOK
}

func setupConfigDir(flag string, env func(string) string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if dir := env("PPE_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("no config directory: %w", err)
	}
	return filepath.Join(base, "ppe"), nil
}

func runSetup(ctx context.Context, opts setupOptions) error {
	if opts.APIBase == "" {
		opts.APIBase = setupAPIBase
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	// Refuse before the browser opens. The App's private key is shown once, so
	// creating an App and only then discovering that the credentials cannot be
	// written would strand it.
	if err := os.MkdirAll(opts.ConfigDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(opts.ConfigDir, 0o700); err != nil {
		return err
	}
	if err := checkConfigDir(opts.ConfigDir); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	local := fmt.Sprintf("http://127.0.0.1:%d", port)
	state, err := randomHex(16)
	if err != nil {
		return err
	}
	hookURL := setupPlaceholderHook
	if opts.HookURL != "" {
		hookURL = opts.HookURL
	}
	manifest, err := newManifest(local+"/callback", hookURL)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	handler, results := newSetupHandler(state, string(raw), opts.ConfigDir, opts.APIBase)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	fmt.Fprintf(opts.Out, "ppe: open %s/ in your browser\n", local)

	var res setupResult
	select {
	case res = <-results:
	case err := <-serveErr:
		srv.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return errors.New("setup server stopped before the App was created")
		}
		return err
	case <-ctx.Done():
		shutdownSetup(srv)
		return ctx.Err()
	}

	shutdownSetup(srv)
	if res.err != nil {
		return res.err
	}

	install := "https://github.com/apps/" + url.PathEscape(res.slug) + "/installations/new"
	fmt.Fprintf(opts.Out, "ppe: created app %s\n", res.slug)
	fmt.Fprintf(opts.Out, "ppe: credentials written to %s\n", opts.ConfigDir)
	fmt.Fprintf(opts.Out, "ppe: install it: %s\n", install)
	fmt.Fprintf(opts.Out, "ppe: then add a branch ruleset that requires the ppe check\n")
	return nil
}

func shutdownSetup(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func newManifest(redirect, hookURL string) (appManifest, error) {
	suffix, err := randomHex(4)
	if err != nil {
		return appManifest{}, err
	}
	return appManifest{
		Name:        "ppe-" + suffix,
		URL:         setupHomepage,
		RedirectURL: redirect,
		HookAttributes: &hookAttributes{
			URL:    hookURL,
			Active: true,
		},
		Description: "External ppe check for GitHub Actions workflows.",
		Public:      false,
		DefaultPermissions: map[string]string{
			"checks":        "write",
			"contents":      "read",
			"metadata":      "read",
			"pull_requests": "read",
		},
		DefaultEvents: []string{"pull_request"},
	}, nil
}

const setupPage = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Continue to GitHub</title></head>
<body>
<form id="create" method="post" action="{{.Action}}">
<input type="hidden" name="manifest" value="{{.Manifest}}">
<noscript><button type="submit">Continue to GitHub</button></noscript>
</form>
<script>document.getElementById("create").submit()</script>
</body>
</html>
`

var setupTemplate = template.Must(template.New("setup").Parse(setupPage))

func newSetupHandler(state, manifestJSON, configDir, apiBase string) (http.Handler, <-chan setupResult) {
	results := make(chan setupResult, 1)
	var mu sync.Mutex
	started := false
	sent := false

	finish := func(res setupResult) {
		mu.Lock()
		if sent {
			mu.Unlock()
			return
		}
		sent = true
		mu.Unlock()
		results <- res
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data := struct {
			Action   string
			Manifest string
		}{
			Action:   "https://github.com/settings/apps/new?state=" + url.QueryEscape(state),
			Manifest: manifestJSON,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := setupTemplate.Execute(w, data); err != nil {
			http.Error(w, "could not render setup page", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		got := r.URL.Query().Get("state")
		if subtle.ConstantTimeCompare([]byte(got), []byte(state)) != 1 {
			http.Error(w, "state did not match; start setup again", http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "GitHub did not return a code; start setup again", http.StatusBadRequest)
			return
		}

		mu.Lock()
		if started {
			mu.Unlock()
			http.Error(w, "setup already started", http.StatusConflict)
			return
		}
		started = true
		mu.Unlock()

		app, err := exchangeManifest(r.Context(), apiBase, code)
		if err != nil {
			finish(setupResult{err: err})
			http.Error(w, "could not create the App: "+err.Error(), http.StatusBadGateway)
			return
		}
		if err := writeApp(configDir, app); err != nil {
			finish(setupResult{err: err})
			http.Error(w, "could not write credentials: "+err.Error(), http.StatusInternalServerError)
			return
		}

		install := "https://github.com/apps/" + url.PathEscape(app.Slug) + "/installations/new"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ppe setup complete</title></head>
<body><h1>App created</h1><p>You can close this tab.</p>
<p><a href="%s">Install %s</a></p></body></html>
`, html.EscapeString(install), html.EscapeString(app.Slug))
		finish(setupResult{slug: app.Slug})
	})

	return mux, results
}

func exchangeManifest(ctx context.Context, apiBase, code string) (manifestConversion, error) {
	endpoint := strings.TrimRight(apiBase, "/") + "/app-manifests/" + url.PathEscape(code) + "/conversions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return manifestConversion{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return manifestConversion{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return manifestConversion{}, fmt.Errorf("GitHub returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var app manifestConversion
	if err := json.NewDecoder(resp.Body).Decode(&app); err != nil {
		return manifestConversion{}, err
	}
	if app.ID <= 0 || app.Slug == "" || app.PEM == "" {
		return manifestConversion{}, errors.New("GitHub returned an incomplete App")
	}
	return app, nil
}

func writeApp(dir string, app manifestConversion) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if err := checkConfigDir(dir); err != nil {
		return err
	}

	keyPath := filepath.Join(dir, "app.pem")
	configPath := filepath.Join(dir, "config.env")

	secret := app.WebhookSecret
	if secret == "" {
		var err error
		secret, err = randomHex(32)
		if err != nil {
			return err
		}
	}

	pem := app.PEM
	if !strings.HasSuffix(pem, "\n") {
		pem += "\n"
	}
	if err := os.WriteFile(keyPath, []byte(pem), 0o600); err != nil {
		return err
	}

	config := fmt.Sprintf("PPE_APP_ID=%d\nPPE_WEBHOOK_SECRET=%s\nPPE_APP_SLUG=%s\nPPE_PRIVATE_KEY_PATH=%s\n",
		app.ID, secret, app.Slug, shellValue(keyPath))
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

// shellValue quotes a value for the config.env file, which is sourced by a
// shell. A config directory with a space in it otherwise turns the assignment
// into a command.
func shellValue(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func checkConfigDir(dir string) error {
	for _, name := range []string{"app.pem", "config.env"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; remove it or choose another --config-dir", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
