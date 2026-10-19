package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree materialises a map of relative path to content under a temporary
// directory and returns its path.
//
// Written by hand rather than pulled from a fixture directory so that each test
// states exactly the tree it needs and there is no shared fixture that silently
// grows a file and changes another test's meaning.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

// workflow is a minimal valid workflow, enough to parse.
const workflow = "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"

// A repository root is the common case, and the workflows have to be found
// beneath .github/workflows without sweeping up every other YAML file in the tree.
func TestCollectFromRepositoryRoot(t *testing.T) {
	root := writeTree(t, map[string]string{
		".github/workflows/ci.yml":         workflow,
		".github/workflows/release.yaml":   workflow,
		".github/workflows/notes.md":       "not a workflow",
		".github/dependabot.yml":           workflow,
		"README.md":                        "docs",
		"config/docker-compose.yml":        workflow,
		".github/actions/build/action.yml": workflow,
	})

	got, err := collect(mustCmd(t, []string{"scan", root}), strings.NewReader(""))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := []string{
		filepath.Join(root, ".github/workflows/ci.yml"),
		filepath.Join(root, ".github/workflows/release.yaml"),
	}
	assertPaths(t, got, want)

	// Only files inside the workflow directory are ever considered, because
	// WalkDir stops descending once it reaches it. notes.md sits there and is
	// counted; the dependabot config and compose file are never looked at, which
	// is why the count is 1 and not 4.
	if got.skipped[skipNotWorkflow] != 1 {
		t.Errorf("skipped = %v, want 1 not-a-workflow file", got.skipped)
	}
}

// Pointing at the workflow directory itself has to work too. Looking for
// .github/workflows inside .github/workflows finds nothing, which is a confusing
// way to report a clean repository.
func TestCollectFromWorkflowDirectory(t *testing.T) {
	root := writeTree(t, map[string]string{
		".github/workflows/ci.yml":          workflow,
		".github/workflows/release.yml":     workflow,
		".github/workflows/nested/deep.yml": workflow,
	})

	got, err := collect(mustCmd(t, []string{"scan", filepath.Join(root, ".github/workflows")}), strings.NewReader(""))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := []string{
		filepath.Join(root, ".github/workflows/ci.yml"),
		filepath.Join(root, ".github/workflows/nested/deep.yml"),
		filepath.Join(root, ".github/workflows/release.yml"),
	}
	assertPaths(t, got, want)
}

// Two paths are additive, and a file can be mixed in with a directory.
func TestCollectMixedPaths(t *testing.T) {
	root := writeTree(t, map[string]string{
		".github/workflows/a.yml": workflow,
		"loose.yml":               workflow,
		"README.md":               "docs",
	})

	got, err := collect(mustCmd(t, []string{
		"scan", root,
		filepath.Join(root, "loose.yml"),
		filepath.Join(root, "README.md"),
	}), strings.NewReader(""))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := []string{
		filepath.Join(root, ".github/workflows/a.yml"),
		filepath.Join(root, "loose.yml"),
	}
	assertPaths(t, got, want)
	if got.skipped[skipNotWorkflow] != 1 {
		t.Errorf("skipped = %v, want the README counted", got.skipped)
	}
}

// Standard input has no path, so it gets a printable name and sorts first.
func TestCollectFromStdin(t *testing.T) {
	got, err := collect(mustCmd(t, []string{"scan", "-"}), strings.NewReader(workflow))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got.sources) != 1 {
		t.Fatalf("got %d sources, want 1", len(got.sources))
	}
	if got.sources[0].name() != "<stdin>" {
		t.Errorf("name = %q, want <stdin>", got.sources[0].name())
	}
	if string(got.sources[0].data) != workflow {
		t.Error("the stdin content was not read through")
	}
}

// stdin alongside a path scans both. This is how a CI job checks the workflow it
// just generated and the repository it generated it into.
func TestCollectStdinAndPaths(t *testing.T) {
	root := writeTree(t, map[string]string{".github/workflows/a.yml": workflow})

	got, err := collect(mustCmd(t, []string{"scan", "-", root}), strings.NewReader(workflow))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got.sources) != 2 {
		t.Fatalf("got %d sources, want 2", len(got.sources))
	}
	// Empty path sorts before the real one.
	if got.sources[0].path != "" {
		t.Errorf("stdin should sort first, got %q", got.sources[0].path)
	}
}

// A path the user named that does not exist is their mistake. Reporting a clean
// repository for a typo would be the worst possible answer.
func TestCollectMissingPathIsAnError(t *testing.T) {
	_, err := collect(mustCmd(t, []string{"scan", "does-not-exist"}), strings.NewReader(""))
	if err == nil {
		t.Fatal("collect succeeded on a missing path, want an error")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error = %q, want it to name the path", err)
	}
}

// Empty stdin is an error rather than a zero finding run.
func TestCollectEmptyStdinIsAnError(t *testing.T) {
	_, err := collect(mustCmd(t, []string{"scan", "-"}), strings.NewReader("   \n"))
	if err == nil {
		t.Fatal("collect succeeded on empty stdin, want an error")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %q, want it to mention emptiness", err)
	}
}

// Two runs over the same tree must produce the same order, or the golden files
// for the end to end tests would be flaky.
func TestCollectIsDeterministic(t *testing.T) {
	root := writeTree(t, map[string]string{
		".github/workflows/z.yml":     workflow,
		".github/workflows/a.yml":     workflow,
		".github/workflows/m/m.yml":   workflow,
		".github/workflows/b/c/d.yml": workflow,
	})

	var first []string
	for run := 0; run < 3; run++ {
		got, err := collect(mustCmd(t, []string{"scan", root}), strings.NewReader(""))
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		var paths []string
		for _, s := range got.sources {
			paths = append(paths, s.path)
		}
		if run == 0 {
			first = paths
			continue
		}
		if len(paths) != len(first) {
			t.Fatalf("run %d had %d sources, run 0 had %d", run, len(paths), len(first))
		}
		for i := range paths {
			if paths[i] != first[i] {
				t.Fatalf("run %d order differs at %d: %q vs %q", run, i, paths[i], first[i])
			}
		}
	}
}

// A repository with no workflows is empty, not broken.
func TestCollectNoWorkflows(t *testing.T) {
	root := writeTree(t, map[string]string{"README.md": "docs", "src/main.go": "package main"})

	got, err := collect(mustCmd(t, []string{"scan", root}), strings.NewReader(""))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got.sources) != 0 {
		t.Errorf("got %d sources, want 0: %v", len(got.sources), got.sources)
	}
}

// The same file named twice is scanned once.
//
// Naming a path twice is the most ordinary way to reach the same file, and
// scanning it twice printed every finding twice and counted it twice, which
// reads as two problems where there is one.
func TestCollectScansARepeatedPathOnce(t *testing.T) {
	root := writeTree(t, map[string]string{
		".github/workflows/ci.yml": workflow,
	})
	file := filepath.Join(root, ".github/workflows/ci.yml")

	got, err := collect(mustCmd(t, []string{"scan", file, file}), strings.NewReader(""))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got.sources) != 1 {
		t.Errorf("got %d sources, want 1: %v", len(got.sources), got.sources)
	}
}

// Two spellings of the same path are the same file, and the comparison is on
// the resolved path rather than on the string the user typed.
func TestCollectTreatsEquivalentPathsAsOne(t *testing.T) {
	root := writeTree(t, map[string]string{
		".github/workflows/ci.yml": workflow,
	})
	dir := filepath.Join(root, ".github/workflows")

	got, err := collect(mustCmd(t, []string{"scan",
		filepath.Join(dir, "ci.yml"),
		filepath.Join(dir, ".", "ci.yml"),
	}), strings.NewReader(""))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got.sources) != 1 {
		t.Errorf("got %d sources, want 1: %v", len(got.sources), got.sources)
	}
}

// A file named on the command line and also found by a directory walk is
// scanned once, not twice.
func TestCollectScansAnExplicitlyNamedFileOnce(t *testing.T) {
	root := writeTree(t, map[string]string{
		".github/workflows/ci.yml": workflow,
	})
	file := filepath.Join(root, ".github/workflows/ci.yml")

	got, err := collect(mustCmd(t, []string{"scan", root, file}), strings.NewReader(""))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got.sources) != 1 {
		t.Errorf("got %d sources, want 1: %v", len(got.sources), got.sources)
	}
}

// A directory whose name ends in .yml is an error, not an empty scan.
//
// Walking it would find no workflows, so the scan would report nothing and
// exit 0, which reads as a clean result. The path cannot be read as a workflow
// and saying so is the truth.
func TestCollectRejectsADirectoryNamedLikeAWorkflow(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "workflows.yml")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := collect(mustCmd(t, []string{"scan", dir}), strings.NewReader(""))
	if err == nil {
		t.Fatal("collect succeeded, want an error for a directory named like a workflow")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error = %q, want it to say it is a directory", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error = %q, want it to name the path", err)
	}
}

// The key used for recognising an already-scanned file is the resolved path,
// so the spellings of one file agree.
func TestAbsolutePathResolvesSpellings(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "ci.yml")

	same := []string{
		file,
		filepath.Join(dir, ".", "ci.yml"),
		filepath.Join(dir, "sub", "..", "ci.yml"),
	}
	want := absolutePath(file)

	for _, path := range same {
		if got := absolutePath(path); got != want {
			t.Errorf("absolutePath(%q) = %q, want %q", path, got, want)
		}
	}
}

// The fallback for a path that cannot be made absolute.
//
// Making a path absolute needs the working directory, and the working
// directory can be deleted out from under the process. The scan still has to
// produce a key in that case, and the path as written is the best one
// available.
func TestAbsolutePathFallsBackWhenTheWorkingDirectoryIsGone(t *testing.T) {
	dir, err := os.MkdirTemp("", "gonewd")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}

	// Move into it, then delete it. The process is now in a directory that
	// does not exist.
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		// Restore the working directory before the temporary directory is
		// removed, or the cleanup itself fails.
		os.Chdir(previous)
		os.RemoveAll(dir)
	})
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove: %v", err)
	}

	// The key is still a usable one, and the same path always gives the same
	// key, which is what deduplication needs.
	first := absolutePath("workflows/ci.yml")
	second := absolutePath("workflows/ci.yml")
	if first != second {
		t.Errorf("the fallback is not stable: %q and %q", first, second)
	}
	if first == "" {
		t.Error("the fallback produced an empty key")
	}
}

func mustCmd(t *testing.T, args []string) command {
	t.Helper()
	cmd, err := parseArgs(args)
	if err != nil {
		t.Fatalf("parseArgs(%v): %v", args, err)
	}
	return cmd
}

func assertPaths(t *testing.T, got collection, want []string) {
	t.Helper()
	if len(got.sources) != len(want) {
		var actual []string
		for _, s := range got.sources {
			actual = append(actual, s.path)
		}
		t.Fatalf("got %d sources %v, want %d %v", len(got.sources), actual, len(want), want)
	}
	for i := range want {
		if got.sources[i].path != want[i] {
			t.Errorf("source %d = %q, want %q", i, got.sources[i].path, want[i])
		}
	}
}
