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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestJWTCarriesTheAppIDAndAVerifiableSignature(t *testing.T) {
	key := testKey(t)
	cfg := Config{AppID: 12345, Key: key}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

	raw, err := cfg.JWT(now)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}

	var head map[string]string
	decodePart(t, parts[0], &head)
	if head["alg"] != "RS256" || head["typ"] != "JWT" {
		t.Errorf("header is %v", head)
	}

	var claims struct {
		Iss int64 `json:"iss"`
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	decodePart(t, parts[1], &claims)
	if claims.Iss != 12345 {
		t.Errorf("iss is %d, want 12345", claims.Iss)
	}
	if claims.Iat != now.Add(-time.Minute).Unix() {
		t.Errorf("iat is %d, want %d", claims.Iat, now.Add(-time.Minute).Unix())
	}
	if claims.Exp != now.Add(9*time.Minute).Unix() {
		t.Errorf("exp is %d, want %d", claims.Exp, now.Add(9*time.Minute).Unix())
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func decodePart(t *testing.T, part string, into any) {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAcceptsBothPEMShapes(t *testing.T) {
	key := testKey(t)

	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	for name, data := range map[string][]byte{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load("42", path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.AppID != 42 {
				t.Errorf("app id is %d, want 42", cfg.AppID)
			}
			if cfg.Key.N.Cmp(key.N) != 0 {
				t.Error("loaded the wrong key")
			}
		})
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		appID string
		key   string
	}{
		"empty app id":  {"", path},
		"bad app id":    {"nope", path},
		"zero app id":   {"0", path},
		"missing key":   {"1", filepath.Join(t.TempDir(), "nope.pem")},
		"not a pem key": {"1", path},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(tc.appID, tc.key); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestTokenIsCachedUntilItIsAboutToExpire(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	mints := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mints++
		if r.Method != http.MethodPost {
			t.Errorf("method is %s, want POST", r.Method)
		}
		if r.URL.Path != "/app/installations/7/access_tokens" {
			t.Errorf("path is %s", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") || len(auth) < 20 {
			t.Errorf("authorization header is %q", auth)
		}
		var claims struct {
			Iss int64 `json:"iss"`
		}
		parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
		if len(parts) == 3 {
			decodePart(t, parts[1], &claims)
			if claims.Iss != 99 {
				t.Errorf("iss is %d, want 99", claims.Iss)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_test",
			"expires_at": now.Add(time.Hour),
		})
	}))
	defer server.Close()

	client := NewClient(
		Config{AppID: 99, Key: testKey(t)},
		WithBaseURL(server.URL),
		WithClock(clock),
	)

	ctx := context.Background()
	first, err := client.Token(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if first != "ghs_test" {
		t.Errorf("token is %q", first)
	}

	if _, err := client.Token(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if mints != 1 {
		t.Errorf("minted %d times, want 1", mints)
	}

	// Inside the refresh margin, so it is replaced even though it has not
	// expired yet.
	now = now.Add(59*time.Minute + 30*time.Second)
	if _, err := client.Token(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if mints != 2 {
		t.Errorf("minted %d times, want 2", mints)
	}

	client.Invalidate(7)
	if _, err := client.Token(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if mints != 3 {
		t.Errorf("minted %d times, want 3", mints)
	}
}

func TestTokenReportsAFailedMint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	client := NewClient(Config{AppID: 1, Key: testKey(t)}, WithBaseURL(server.URL))
	_, err := client.Token(context.Background(), 7)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Bad credentials") {
		t.Errorf("error is %q", err)
	}
}

func TestTokenRejectsANonPositiveInstallation(t *testing.T) {
	client := NewClient(Config{AppID: 1, Key: testKey(t)})
	if _, err := client.Token(context.Background(), 0); err == nil {
		t.Fatal("expected an error")
	}
}
