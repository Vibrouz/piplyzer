package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// workflowDir is the directory GitHub reads workflows from, relative to a
// repository root. It is the only place a workflow can live and still run.
const workflowDir = ".github/workflows"

// workflowExts are the extensions GitHub accepts for a workflow file. Both are
// documented; neither is a subset of the other.
var workflowExts = map[string]bool{".yml": true, ".yaml": true}

// TreeReport is what Tree found under a repository root.
type TreeReport struct {
	// Sources are the workflow files, named relative to the root and sorted by
	// that name.
	Sources []Source
	// Skipped counts files that were present but are not workflows.
	Skipped int
	// Unreadable names files that look like workflows but could not be read,
	// relative to the root. A caller that is a merge gate has to treat this as
	// a failure, because a file it could not read is a file it did not check.
	Unreadable []string
}

// Tree reads the workflows under a repository root.
//
// This is the collection side of the webhook server: it has a directory on
// disk rather than a list of paths from a command line, and it reports paths
// relative to the root so that a finding names the file the way a reader of the
// pull request does, not the way a temporary directory happens to.
//
// A root with no workflow directory is not an error. The caller decides whether
// "looked and found nothing" is a failure, and for a merge gate it is.
func Tree(root string) (TreeReport, error) {
	var rep TreeReport

	dir := filepath.Join(root, workflowDir)
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return rep, nil
		}
		return rep, fmt.Errorf("reading %s: %w", dir, err)
	}
	if !info.IsDir() {
		return rep, fmt.Errorf("reading %s: it is not a directory", dir)
	}

	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			rep.Unreadable = append(rep.Unreadable, relPath(root, path))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !isWorkflowFile(path) {
			rep.Skipped++
			return nil
		}
		// A symlink could point outside the extracted tree, and a tarball is
		// attacker-controlled. Refusing anything that is not a regular file
		// keeps a pull request from turning a scan into a read of the runner.
		if !d.Type().IsRegular() {
			rep.Unreadable = append(rep.Unreadable, relPath(root, path))
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			rep.Unreadable = append(rep.Unreadable, relPath(root, path))
			return nil
		}
		rep.Sources = append(rep.Sources, Source{Path: relPath(root, path), Data: data})
		return nil
	})
	if walkErr != nil {
		return rep, fmt.Errorf("walking %s: %w", dir, walkErr)
	}

	sort.Slice(rep.Sources, func(i, j int) bool { return rep.Sources[i].Path < rep.Sources[j].Path })
	return rep, nil
}

// relPath names a path the way output should, relative to the root.
func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	return filepath.ToSlash(rel)
}

// isWorkflowFile reports whether a path has a workflow extension.
//
// Deliberately only the extension. Whether a file is a workflow is not decided
// here: a workflow named deploy.txt is still a workflow to the person who wrote
// it, and a YAML file that turns out not to parse as a workflow is reported as a
// parse error rather than quietly skipped.
func isWorkflowFile(path string) bool {
	return workflowExts[strings.ToLower(filepath.Ext(path))]
}
