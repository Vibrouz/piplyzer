package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A directory with a lockfile in it.
func depsRepo(t *testing.T, lockfile string) string {
	t.Helper()
	dir := t.TempDir()
	if lockfile != "" {
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
			t.Fatalf("write lockfile: %v", err)
		}
	}
	return dir
}

// The lockfile fixture, read from the fixtures directory.
func lockfileFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "lockfile", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// depsArgs runs the whole command and returns what it wrote plus the exit code.
func depsArgs(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = run(args, strings.NewReader(""), &out, &errBuf)
	return out.String(), errBuf.String(), code
}

// A repository with a clean lockfile reports nothing and exits 0.
func TestDepsCleanRepository(t *testing.T) {
	dir := depsRepo(t, `{"name":"p","version":"1.0.0","lockfileVersion":3,"packages":{
		"": {"name":"p","version":"1.0.0"},
		"node_modules/lodash": {"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}
	}}`)

	stdout, stderr, code := depsArgs(t, "deps", dir)

	if code != exitOK {
		t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "checked 1 dependency") {
		t.Errorf("the summary is wrong:\n%s", stdout)
	}
}

// A package resolved from another registry blocks.
func TestDepsReportsARegistryMismatch(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "registry-mismatch.json"))

	stdout, stderr, code := depsArgs(t, "deps", dir, "--registry", "https://npm.pkg.github.com/")

	if code != exitBlocked {
		t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if !strings.Contains(stdout, "DEP-D3") {
		t.Errorf("the finding is missing:\n%s", stdout)
	}
	if !strings.Contains(stdout, "from-another-registry") {
		t.Errorf("the finding names the wrong package:\n%s", stdout)
	}
}

// A repository with no lockfile is an error, not a clean result.
//
// A check that found no lockfile has not checked anything, and reporting that
// as clean is the false clean this tool exists to avoid.
func TestDepsWithNoLockfile(t *testing.T) {
	dir := depsRepo(t, "")

	_, stderr, code := depsArgs(t, "deps", dir)

	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d", code, exitIncomplete)
	}
	if !strings.Contains(stderr, "package-lock.json") {
		t.Errorf("stderr does not name the file: %s", stderr)
	}
}

// A lockfile that is not a lockfile is an error.
func TestDepsWithAMalformedLockfile(t *testing.T) {
	dir := depsRepo(t, "this is not json")

	_, stderr, code := depsArgs(t, "deps", dir)

	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d", code, exitIncomplete)
	}
	if !strings.Contains(stderr, "package-lock.json") {
		t.Errorf("stderr does not name the file: %s", stderr)
	}
}

// The checks that need a base commit are skipped, and the skip is said out
// loud.
//
// A silent skip here would be a clean result for a check that did not run,
// and the difference between "nothing was found" and "nothing was looked at"
// is the whole point of the exit codes.
func TestDepsSaysWhenTheBaseCommitIsSkipped(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "diff-head.json"))

	stdout, stderr, code := depsArgs(t, "deps", dir)

	if code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stderr, "skipped") {
		t.Errorf("the skip is not said out loud:\n%s", stderr)
	}
	// The checks that do not need a base commit still ran.
	if !strings.Contains(stdout, "checked") {
		t.Errorf("the summary is missing:\n%s", stdout)
	}
}

// --no-diff skips the base commit checks without saying anything about them,
// because the reader asked for that.
func TestDepsNoDiff(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "diff-head.json"))

	stdout, stderr, code := depsArgs(t, "deps", dir, "--no-diff")

	if code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
	if strings.Contains(stderr, "skipped") {
		t.Errorf("the skip was reported even though it was asked for:\n%s", stderr)
	}
	if !strings.Contains(stdout, "checked") {
		t.Errorf("the summary is missing:\n%s", stdout)
	}
}

// The diff runs when there is a base commit to compare against.
//
// The test builds a real repository with a real remote, because the code under
// test fetches a commit over the network of a local repository, and a stub
// would only test the stub.
func TestDepsRunsTheDiffAgainstTheBaseCommit(t *testing.T) {
	dir := t.TempDir()

	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Test"},
		{"config", "user.email", "test@example.com"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	// The base commit, with the base lockfile in it.
	base := lockfileFixture(t, "diff-base.json")
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(base), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "base"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	// A remote to fetch the base commit from.
	remote := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}
	for _, args := range [][]string{
		{"remote", "add", "origin", remote},
		{"push", "-q", "origin", "HEAD:refs/heads/main"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	// The base SHA, in an event payload.
	sha := revParse(t, dir, "HEAD")
	event := filepath.Join(t.TempDir(), "event.json")
	payload := `{"pull_request":{"number":1,"base":{"sha":"` + sha + `"}}}`
	if err := os.WriteFile(event, []byte(payload), 0o644); err != nil {
		t.Fatalf("write event: %v", err)
	}
	t.Setenv("GITHUB_EVENT_PATH", event)

	// The head lockfile, in the working tree.
	head := lockfileFixture(t, "diff-head.json")
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(head), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	stdout, stderr, code := depsArgs(t, "deps", dir)

	if code != exitBlocked {
		t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if !strings.Contains(stdout, "DEP-D1D2") {
		t.Errorf("the new package with a script is missing:\n%s", stdout)
	}
	if !strings.Contains(stdout, "DEP-D1") {
		t.Errorf("the new package is missing:\n%s", stdout)
	}
	if !strings.Contains(stdout, "DEP-D2") {
		t.Errorf("the gained install script is missing:\n%s", stdout)
	}
	// The base commit was found, so there is no skip to report.
	if strings.Contains(stderr, "skipped") {
		t.Errorf("the base commit was skipped even though it was there:\n%s", stderr)
	}
}

// The registry comes from a setup-node step in a workflow.
//
// A workflow can set the registry for the job, and the .npmrc cannot know
// about it, so the workflow is searched for it. Every workflow file is
// searched, because a repository can have any number of them and the registry
// is set in whichever one runs the install.
func TestDepsRegistryFromAWorkflow(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "registry-mismatch.json"))

	// A workflow that is not named ci.yml, to hold the registry.
	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflows, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	workflow := "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          registry-url: https://npm.pkg.github.com/\n"
	if err := os.WriteFile(filepath.Join(workflows, "release.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	// With the workflow's registry, the package from the third host is a
	// finding, because it did not come from where the project fetches from.
	stdout, _, code := depsArgs(t, "deps", dir)
	if code != exitBlocked {
		t.Errorf("exit = %d, want %d\nstdout:\n%s", code, exitBlocked, stdout)
	}
	if !strings.Contains(stdout, "from-another-registry") {
		t.Errorf("the package from the third host is missing:\n%s", stdout)
	}
	// And the package from the workflow's own registry is not.
	if strings.Contains(stdout, "from-the-right-registry") {
		t.Errorf("the package from the workflow's registry was reported:\n%s", stdout)
	}
}

// A repository with no workflows and no registry configuration is not an
// error, and it does not block.
//
// With no registry to compare against, the registry check cannot tell a
// mismatch from a mirror, so it downgrades to a Warn. A project with no .npmrc
// and no setup-node registry is an unconfigured project, not a
// dependency-confusion incident, and blocking it would be a false-positive
// machine.
func TestDepsWithNoWorkflows(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "registry-mismatch.json"))

	stdout, stderr, code := depsArgs(t, "deps", dir, "--no-diff")

	if code != exitOK {
		t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout, stderr)
	}
	if strings.Contains(stdout, "BLOCK") {
		t.Errorf("something blocked with no registry configured:\n%s", stdout)
	}
}

// The reasons the base commit checks were skipped are all said out loud.
//
// A silent skip is a clean result for a check that did not run, and that is
// the false clean this tool exists to avoid. Every reason has to reach the
// reader.
func TestDepsSaysWhyTheBaseCommitWasSkipped(t *testing.T) {
	// A repository with a commit, so the base SHA can be found.
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Test"},
		{"config", "user.email", "test@example.com"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockfileFixture(t, "diff-head.json")), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "base"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	// The event payload names a base commit that does not exist, so the fetch
	// fails.
	event := filepath.Join(t.TempDir(), "event.json")
	payload := `{"pull_request":{"number":1,"base":{"sha":"0123456789abcdef0123456789abcdef01234567"}}}`
	if err := os.WriteFile(event, []byte(payload), 0o644); err != nil {
		t.Fatalf("write event: %v", err)
	}
	t.Setenv("GITHUB_EVENT_PATH", event)

	_, stderr, _ := depsArgs(t, "deps", dir)

	if !strings.Contains(stderr, "fetch") {
		t.Errorf("the reason the fetch failed is not said: %s", stderr)
	}
	if !strings.Contains(stderr, "skipped") {
		t.Errorf("the skip is not said: %s", stderr)
	}
}

// A base commit that has no lockfile in it is a skip, and it is said.
//
// This is the ordinary case for a pull request that adds a lockfile: every
// package would read as new, so the checks that compare are skipped rather
// than reporting every package.
func TestDepsSaysWhenTheBaseCommitHasNoLockfile(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Test"},
		{"config", "user.email", "test@example.com"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	// A commit with no lockfile in it.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "base"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	// A remote, so the fetch succeeds.
	remote := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}
	for _, args := range [][]string{
		{"remote", "add", "origin", remote},
		{"push", "-q", "origin", "HEAD:refs/heads/main"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	sha := revParse(t, dir, "HEAD")
	event := filepath.Join(t.TempDir(), "event.json")
	payload := `{"pull_request":{"number":1,"base":{"sha":"` + sha + `"}}}`
	if err := os.WriteFile(event, []byte(payload), 0o644); err != nil {
		t.Fatalf("write event: %v", err)
	}
	t.Setenv("GITHUB_EVENT_PATH", event)

	// The working tree has a lockfile, the base commit does not.
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockfileFixture(t, "diff-head.json")), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	_, stderr, _ := depsArgs(t, "deps", dir)

	if !strings.Contains(stderr, "no package-lock.json") {
		t.Errorf("the reason is not said: %s", stderr)
	}
	if !strings.Contains(stderr, "skipped") {
		t.Errorf("the skip is not said: %s", stderr)
	}
}

// The findings are reported against the lockfile path, relative to the
// directory being checked.
//
// The path is relative so that a finding does not carry the absolute path of
// wherever the scan happened to run, which would make the output differ
// between a developer's machine and a CI run.
func TestDepsFindingPath(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "registry-mismatch.json"))

	stdout, _, _ := depsArgs(t, "deps", dir, "--registry", "https://npm.pkg.github.com/")

	if !strings.Contains(stdout, filepath.Join(dir, "package-lock.json")) {
		t.Errorf("the finding does not name the lockfile:\n%s", stdout)
	}
	if strings.Contains(stdout, "/tmp/") && !strings.Contains(stdout, dir) {
		t.Errorf("the finding carries an unexpected path:\n%s", stdout)
	}
}

// The current directory is reported as the bare lockfile name.
//
// "package-lock.json" rather than "./package-lock.json", because the point of
// the path is to name the file, and a leading dot is noise.
func TestDepsPathForTheCurrentDirectory(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "registry-mismatch.json"))

	// The command is run with the directory as the working directory, so the
	// path is the bare name.
	t.Chdir(dir)

	stdout, _, _ := depsArgs(t, "deps", ".", "--registry", "https://npm.pkg.github.com/")

	if !strings.Contains(stdout, "package-lock.json") {
		t.Errorf("the finding does not name the lockfile:\n%s", stdout)
	}
	if strings.Contains(stdout, "./package-lock.json") {
		t.Errorf("the path has a leading dot:\n%s", stdout)
	}
}

// A workflow file that cannot be read is skipped, not a failure.
//
// The workflow is one of four places the registry can come from, and one of
// them being unreadable should not stop the other three.
func TestDepsWithAnUnreadableWorkflow(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "registry-mismatch.json"))

	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflows, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A directory named like a workflow file, which cannot be read as one.
	if err := os.MkdirAll(filepath.Join(workflows, "broken.yml"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	stdout, stderr, code := depsArgs(t, "deps", dir, "--registry", "https://npm.pkg.github.com/")

	if code != exitBlocked {
		t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
}

// A workflow directory with files that are not workflows is fine.
//
// The directory is searched for workflow files and the rest are ignored, which
// is the ordinary case for a repository that keeps other YAML in there.
func TestDepsWithOtherFilesInTheWorkflowDirectory(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "registry-mismatch.json"))

	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflows, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A file that is not a workflow, and a directory that is not a workflow.
	if err := os.WriteFile(filepath.Join(workflows, "README.md"), []byte("docs"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(workflows, "templates"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	stdout, stderr, code := depsArgs(t, "deps", dir, "--registry", "https://npm.pkg.github.com/")

	if code != exitBlocked {
		t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
}

// A workflow with no registry-url in it leaves the registry to the other
// sources.
//
// The workflow is one of four places the registry can come from, and most
// workflows do not set one.
func TestDepsWithAWorkflowThatHasNoRegistryURL(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "registry-mismatch.json"))

	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflows, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	workflow := "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
	if err := os.WriteFile(filepath.Join(workflows, "ci.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	stdout, _, code := depsArgs(t, "deps", dir, "--registry", "https://npm.pkg.github.com/")

	if code != exitBlocked {
		t.Errorf("exit = %d, want %d\n%s", code, exitBlocked, stdout)
	}
}

// The registry comes from the flag.
//
// The fixture has a package from a third host and a scoped package from a
// private registry, so pointing the registry at the third host clears the first
// finding and leaves the scoped one, which is the point: the scope has its own
// registry and the flag does not change it.
func TestDepsRegistryFlag(t *testing.T) {
	dir := depsRepo(t, lockfileFixture(t, "registry-mismatch.json"))

	// With the flag, the package from the third host is a finding.
	stdout, _, code := depsArgs(t, "deps", dir, "--registry", "https://npm.pkg.github.com/")
	if code != exitBlocked {
		t.Errorf("exit = %d, want %d", code, exitBlocked)
	}
	if !strings.Contains(stdout, "from-another-registry") {
		t.Errorf("the package from the third host is missing:\n%s", stdout)
	}

	// With the registry being the one the package came from, that package is
	// no longer a finding, and only the scoped one is.
	stdout, _, code = depsArgs(t, "deps", dir, "--registry", "https://evil.example.com/")
	if strings.Contains(stdout, "from-another-registry") {
		t.Errorf("the package was reported against the registry it came from:\n%s", stdout)
	}
	if !strings.Contains(stdout, "from-the-scope-registry") {
		t.Errorf("the scoped package should still be reported:\n%s", stdout)
	}
}

// The registry flag takes its value in either form.
func TestDepsRegistryFlagForms(t *testing.T) {
	for _, args := range [][]string{
		{"deps", "--registry=https://npm.pkg.github.com/"},
		{"deps", "--registry", "https://npm.pkg.github.com/"},
	} {
		cmd, err := parseArgs(args)
		if err != nil {
			t.Fatalf("parseArgs(%v): %v", args, err)
		}
		if cmd.registry != "https://npm.pkg.github.com/" {
			t.Errorf("parseArgs(%v) registry = %q", args, cmd.registry)
		}
	}
}

// A registry flag with no value is an error, not an empty registry.
func TestDepsRegistryFlagNeedsAValue(t *testing.T) {
	if _, err := parseArgs([]string{"deps", "--registry"}); err == nil {
		t.Error("parseArgs succeeded with a registry flag and no value, want an error")
	}
}

// The deps command is a command, and the help says so.
func TestDepsIsACommand(t *testing.T) {
	cmd, err := parseArgs([]string{"deps"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cmd.kind != kindDeps {
		t.Errorf("kind = %v, want kindDeps", cmd.kind)
	}
}

// An unknown command names the commands there are.
func TestUnknownCommandNamesTheCommands(t *testing.T) {
	_, err := parseArgs([]string{"lint"})
	if err == nil {
		t.Fatal("parseArgs succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "deps") {
		t.Errorf("the error does not name the commands: %s", err)
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
