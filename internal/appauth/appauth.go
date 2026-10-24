// Package appauth authenticates as a GitHub App.
//
// A GitHub App has two credentials and they are not interchangeable. A short
// lived JWT signed with the app's private key identifies the app itself, and it
// can only do app-level things such as minting an installation token. An
// installation token identifies one installation of the app, is what can write
// a check run, and expires after an hour.
//
// Both stay in this package. Nothing here logs a token, and no caller needs the
// private key after Load has read it.
package appauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// apiVersion is the GitHub REST API version this client targets. Pinning it
// means a change on GitHub's side is a deliberate upgrade here, not a surprise.
const apiVersion = "2022-11-28"

// Config is the app's identity.
type Config struct {
	AppID int64
	Key   *rsa.PrivateKey
}

// Load reads the app id and private key.
//
// The id is a string because that is how it arrives from the environment, and
// the key path is read here rather than by every caller so that the PEM is
// parsed once and never handled as bytes again.
func Load(appID, keyPath string) (Config, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(appID), 10, 64)
	if err != nil || id <= 0 {
		return Config{}, errors.New("the app id must be a positive integer")
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return Config{}, fmt.Errorf("reading the private key: %w", err)
	}

	key, err := parsePrivateKey(data)
	if err != nil {
		return Config{}, err
	}
	if key.N.BitLen() < 2048 {
		return Config{}, errors.New("the private key is smaller than 2048 bits")
	}
	return Config{AppID: id, Key: key}, nil
}

// parsePrivateKey accepts both PEM shapes GitHub hands out.
//
// The downloaded key is PKCS#1 ("RSA PRIVATE KEY"), but a key that has been
// through openssl or a secret manager is often PKCS#8 ("PRIVATE KEY"), and
// refusing that would be a support question for no gain.
func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the private key is not PEM encoded")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the private key is not an RSA private key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the private key is not an RSA private key")
	}
	return key, nil
}

// JWT returns a token that identifies the app.
//
// The issued-at time is a minute in the past so that a runner whose clock is
// slightly behind GitHub's is not rejected. The lifetime is nine minutes rather
// than the maximum ten: a token that expires mid-request is indistinguishable
// from a bad signature, and the minute of headroom costs nothing.
func (c Config) JWT(now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": c.AppID,
	}

	head, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	unsigned := base64.RawURLEncoding.EncodeToString(head) + "." +
		base64.RawURLEncoding.EncodeToString(body)

	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.Key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing the app token: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Client mints and caches installation tokens.
type Client struct {
	cfg        Config
	httpClient *http.Client
	baseURL    string
	now        func() time.Time

	mu     sync.Mutex
	tokens map[int64]token
}

type token struct {
	value     string
	expiresAt time.Time
}

// Option changes a Client, for tests and for GitHub Enterprise.
type Option func(*Client)

// WithHTTPClient replaces the HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(cl *Client) { cl.httpClient = c } }

// WithBaseURL points the client at a different API, such as a GHES install.
func WithBaseURL(u string) Option {
	return func(cl *Client) { cl.baseURL = strings.TrimRight(u, "/") }
}

// WithClock replaces the clock, so that expiry can be tested without waiting.
func WithClock(f func() time.Time) Option { return func(cl *Client) { cl.now = f } }

// NewClient returns a client for cfg.
func NewClient(cfg Config, opts ...Option) *Client {
	c := &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.github.com",
		now:        time.Now,
		tokens:     map[int64]token{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// tokenRefreshMargin is how long before expiry a token is replaced.
//
// One minute is enough for a scan to finish, and small enough that a token is
// not minted on every request. GitHub's tokens last an hour, so this is the
// steady state, not a hot path.
const tokenRefreshMargin = time.Minute

// Token returns an installation token, minting one if the cached token is
// missing or about to expire.
//
// A second goroutine can mint a duplicate while the first is in flight. That is
// deliberate: the duplicate is harmless, and serialising every scan behind one
// network call would make the worker pool wait on the slowest mint.
func (c *Client) Token(ctx context.Context, installationID int64) (string, error) {
	if installationID <= 0 {
		return "", errors.New("the installation id must be positive")
	}

	now := c.now()
	c.mu.Lock()
	cached, ok := c.tokens[installationID]
	c.mu.Unlock()
	if ok && now.Before(cached.expiresAt.Add(-tokenRefreshMargin)) {
		return cached.value, nil
	}

	value, expiresAt, err := c.mint(ctx, installationID, now)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.tokens[installationID] = token{value: value, expiresAt: expiresAt}
	c.mu.Unlock()
	return value, nil
}

// Invalidate drops a cached token.
//
// A caller that gets a 401 says so here before retrying, because the token may
// have been revoked rather than merely expired.
func (c *Client) Invalidate(installationID int64) {
	c.mu.Lock()
	delete(c.tokens, installationID)
	c.mu.Unlock()
}

func (c *Client) mint(ctx context.Context, installationID int64, now time.Time) (string, time.Time, error) {
	jwt, err := c.cfg.JWT(now)
	if err != nil {
		return "", time.Time{}, err
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("minting an installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("minting an installation token: %s", responseMessage(resp))
	}

	var body struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", time.Time{}, fmt.Errorf("reading the installation token: %w", err)
	}
	if body.Token == "" || body.ExpiresAt.IsZero() {
		return "", time.Time{}, errors.New("GitHub returned an incomplete installation token")
	}
	return body.Token, body.ExpiresAt, nil
}

// responseMessage describes a failed response without echoing the body.
//
// GitHub's error bodies are small and useful ("Bad credentials"), but a body
// read blindly from a proxy could be anything. Only the known message field is
// used, and only when it decodes as JSON with a reasonable length.
func responseMessage(resp *http.Response) string {
	var body struct {
		Message string `json:"message"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err == nil && json.Unmarshal(data, &body) == nil && body.Message != "" && len(body.Message) < 200 {
		return fmt.Sprintf("%s: %s", resp.Status, body.Message)
	}
	return resp.Status
}
