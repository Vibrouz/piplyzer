package deps_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Vibrouz/whoa/internal/deps"
)

// writeEvent writes an event payload to a file and returns its path.
func writeEvent(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write event: %v", err)
	}
	return path
}

// The base SHA comes from the event payload, because the git history is not
// there to resolve it from.
//
// actions/checkout defaults to fetch-depth: 1, so a checkout has one commit and
// no history, and git merge-base has nothing to work with. The event payload
// names the base commit directly.
func TestBaseCommitFromTheEventPayload(t *testing.T) {
	path := writeEvent(t, `{
  "pull_request": {
    "number": 42,
    "base": {"ref": "main", "sha": "0123456789abcdef0123456789abcdef01234567"},
    "head": {"ref": "feature", "sha": "fedcba9876543210fedcba9876543210fedcba98"}
  }
}`)

	sha, ok := deps.BaseCommit(path)
	if !ok {
		t.Fatal("BaseCommit did not find a base commit")
	}
	if sha != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("sha = %q, want the base SHA", sha)
	}
}

// Every way of not having a base commit is a skip rather than an error.
//
// None of them is unusual: a local run has no event payload, a push event has
// no pull request, and a workflow that is not a pull request has no base. The
// caller turns a skip into a message rather than a crash.
func TestBaseCommitNotFound(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "no event path at all",
			path: "",
		},
		{
			name: "the event file does not exist",
			path: "/nonexistent/event.json",
		},
		{
			name: "the payload is not JSON",
			path: writeEvent(t, "this is not json"),
		},
		{
			name: "the payload is a different event",
			path: writeEvent(t, `{"push": {"ref": "refs/heads/main"}}`),
		},
		{
			name: "the pull request has no base",
			path: writeEvent(t, `{"pull_request": {"number": 42}}`),
		},
		{
			name: "the base has no sha",
			path: writeEvent(t, `{"pull_request": {"base": {"ref": "main"}}}`),
		},
		{
			name: "the base sha is blank",
			path: writeEvent(t, `{"pull_request": {"base": {"sha": "   "}}}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sha, ok := deps.BaseCommit(tt.path)
			if ok {
				t.Errorf("BaseCommit found %q, want none", sha)
			}
			if sha != "" {
				t.Errorf("sha = %q, want the empty string", sha)
			}
		})
	}
}

// The base lockfile is read out of a commit with git show.
//
// The test uses a real repository rather than a stub, because the thing being
// tested is a git invocation and a stub would only test the stub.
func TestLockfileAtCommit(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)

	// A commit with a lockfile in it.
	writeFile(t, dir, "package-lock.json", `{"lockfileVersion":3,"packages":{}}`)
	commitAll(t, dir, "add a lockfile")

	// And a commit without one.
	removeFile(t, dir, "package-lock.json")
	commitAll(t, dir, "remove the lockfile")

	// The first commit has the lockfile.
	first := revParse(t, dir, "HEAD~1")

	data, err := deps.LockfileAtCommit(dir, first, "package-lock.json")
	if err != nil {
		t.Fatalf("LockfileAtCommit: %v", err)
	}
	if !contains(string(data), "lockfileVersion") {
		t.Errorf("the file read back is not the lockfile:\n%s", data)
	}

	// The second does not.
	if _, err := deps.LockfileAtCommit(dir, "HEAD", "package-lock.json"); err == nil {
		t.Error("LockfileAtCommit succeeded for a file that is not in the commit, want an error")
	}
}

// A path that is not in the repository at all is an error.
func TestLockfileAtCommitMissingPath(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)
	writeFile(t, dir, "README.md", "hello")
	commitAll(t, dir, "add a readme")

	if _, err := deps.LockfileAtCommit(dir, "HEAD", "package-lock.json"); err == nil {
		t.Error("LockfileAtCommit succeeded for a path that is not there, want an error")
	}
}

// The fetch is shallow and single-commit, and a failure is reported rather than
// swallowed.
//
// A caller that cannot fetch the base cannot diff against it, and that has to
// be said out loud rather than turned into a silent pass.
func TestFetchCommit(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)
	writeFile(t, dir, "README.md", "hello")
	commitAll(t, dir, "add a readme")

	// A remote to fetch from, which is a second bare repository.
	remote := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}
	// The command has to run in the repository. Without the directory set it
	// would run wherever the test happens to be, which is the repository this
	// test suite lives in rather than the one it made.
	addRemote := exec.Command("git", "remote", "add", "origin", remote)
	addRemote.Dir = dir
	if out, err := addRemote.CombinedOutput(); err != nil {
		t.Fatalf("git remote add: %v: %s", err, out)
	}
	push := exec.Command("git", "push", "-q", "origin", "HEAD:refs/heads/main")
	push.Dir = dir
	if out, err := push.CombinedOutput(); err != nil {
		t.Fatalf("git push: %v: %s", err, out)
	}

	sha := revParse(t, dir, "HEAD")

	// Fetching a commit that is there works.
	if err := deps.FetchCommit(dir, "origin", sha); err != nil {
		t.Errorf("FetchCommit: %v", err)
	}

	// Fetching one that does not exist does not, and says so.
	err := deps.FetchCommit(dir, "origin", "0123456789abcdef0123456789abcdef01234567")
	if err == nil {
		t.Error("FetchCommit succeeded for a commit that does not exist, want an error")
	}
}

// A repository with no remote cannot fetch, and that is reported.
func TestFetchCommitWithoutARemote(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)
	writeFile(t, dir, "README.md", "hello")
	commitAll(t, dir, "add a readme")

	if err := deps.FetchCommit(dir, "origin", revParse(t, dir, "HEAD")); err == nil {
		t.Error("FetchCommit succeeded with no remote, want an error")
	}
}
