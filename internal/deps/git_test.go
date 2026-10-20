package deps_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These helpers build a real git repository, because the code under test runs
// git and a stub would only test the stub.

// initRepo makes a repository with one commit and a known identity.
func initRepo(t *testing.T, dir string) string {
	t.Helper()

	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	return dir
}

// writeFile writes a file into the repository.
func writeFile(t *testing.T, dir string, name string, body string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// removeFile removes a file from the repository.
func removeFile(t *testing.T, dir string, name string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatalf("remove %s: %v", name, err)
	}
}

// commitAll commits everything in the repository.
func commitAll(t *testing.T, dir string, message string) {
	t.Helper()
	for _, args := range [][]string{
		{"add", "-A"},
		{"commit", "-q", "-m", message},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
}

// revParse resolves a revision to a SHA.
func revParse(t *testing.T, dir string, rev string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", rev)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse %s: %v", rev, err)
	}
	return strings.TrimSpace(string(out))
}

// contains reports whether a string holds a substring, so the test file does not
// need the strings package for one use.
func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
