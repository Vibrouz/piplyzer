package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTreeFile(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTreeReadsWorkflowsRelativeToTheRoot(t *testing.T) {
	root := t.TempDir()
	writeTreeFile(t, root, ".github/workflows/z.yml", "on: push\n")
	writeTreeFile(t, root, ".github/workflows/a.yaml", "on: push\n")
	writeTreeFile(t, root, ".github/workflows/nested/b.yml", "on: push\n")
	writeTreeFile(t, root, ".github/workflows/notes.txt", "not a workflow\n")

	rep, err := Tree(root)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{".github/workflows/a.yaml", ".github/workflows/nested/b.yml", ".github/workflows/z.yml"}
	if len(rep.Sources) != len(want) {
		t.Fatalf("got %d sources, want %d", len(rep.Sources), len(want))
	}
	for i, path := range want {
		if rep.Sources[i].Path != path {
			t.Errorf("source %d is %q, want %q", i, rep.Sources[i].Path, path)
		}
	}
	if rep.Skipped != 1 {
		t.Errorf("skipped %d, want 1", rep.Skipped)
	}
	if rep.Unreadable != 0 {
		t.Errorf("unreadable %d, want 0", rep.Unreadable)
	}

	// The paths are relative so that a finding names the file the way a reader
	// of the pull request does, not the way the extraction directory does.
	for _, src := range rep.Sources {
		if filepath.IsAbs(src.Path) {
			t.Errorf("source %q is absolute", src.Path)
		}
	}
}

func TestTreeWithoutAWorkflowDirectory(t *testing.T) {
	rep, err := Tree(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sources) != 0 || rep.Skipped != 0 || rep.Unreadable != 0 {
		t.Fatalf("got %+v, want an empty report", rep)
	}
}

func TestTreeRefusesASymlinkedWorkflow(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yml")
	if err := os.WriteFile(outside, []byte("on: push\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeTreeFile(t, root, ".github/workflows/real.yml", "on: push\n")
	if err := os.Symlink(outside, filepath.Join(root, ".github/workflows/link.yml")); err != nil {
		t.Skip("symlinks are not available")
	}

	rep, err := Tree(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sources) != 1 {
		t.Fatalf("got %d sources, want 1", len(rep.Sources))
	}
	if rep.Unreadable != 1 {
		t.Errorf("unreadable %d, want 1", rep.Unreadable)
	}
}
