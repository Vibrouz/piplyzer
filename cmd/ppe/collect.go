package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// workflowDir is the directory GitHub reads workflows from, relative to a
// repository root. It is the only place a workflow can live and still run, so it
// is the only place a directory scan looks.
const workflowDir = ".github/workflows"

// workflowExts are the extensions GitHub accepts for a workflow file. Both are
// documented; neither is a subset of the other.
var workflowExts = map[string]bool{".yml": true, ".yaml": true}

// source is one workflow file waiting to be parsed.
//
// The bytes are read up front rather than lazily so that a permission error or a
// missing file is reported during collection, where it can be attributed to a
// path, instead of in the middle of reporting findings.
type source struct {
	// path is how the file is named in output. Empty for standard input, which
	// has no path of its own.
	path string
	// data is the raw file content.
	data []byte
}

// name returns something printable whether or not the source has a path.
func (s source) name() string {
	if s.path == "" {
		return "<stdin>"
	}
	return s.path
}

// collection is everything a scan found, plus what it deliberately left out.
type collection struct {
	sources []source
	// skipped counts files that were considered and not scanned, with the reason
	// recorded rather than the file. A walk of a repository root skips a great
	// many YAML files that are not workflows, and naming them all would bury the
	// output in noise that means nothing to the reader.
	skipped map[string]int
}

// skippedTotal is how many files were passed over in all.
func (c collection) skippedTotal() int {
	total := 0
	for _, n := range c.skipped {
		total += n
	}
	return total
}

// skip reasons, phrased for output.
const (
	skipNotWorkflow = "not a workflow file"
	skipUnreadable  = "could not be read"
)

// collect gathers every workflow reachable from the parsed paths.
//
// Three shapes, because all three are how this gets used: a repository root, a
// single file, and standard input for a workflow that has not been written to
// disk yet.
func collect(cmd command, stdin io.Reader) (collection, error) {
	var c collection
	c.skipped = map[string]int{}

	for _, path := range cmd.paths {
		info, err := os.Stat(path)
		if err != nil {
			// A path the user named that does not exist is their mistake and
			// stops the scan. Silently finding nothing would report a clean
			// repository for a typo.
			return c, fmt.Errorf("cannot read %s: %w", path, err)
		}

		if info.IsDir() {
			if err := collectDir(&c, path); err != nil {
				return c, err
			}
			continue
		}

		if !isWorkflowFile(path) {
			c.skipped[skipNotWorkflow]++
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return c, fmt.Errorf("cannot read %s: %w", path, err)
		}
		c.sources = append(c.sources, source{path: path, data: data})
	}

	if cmd.stdin {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return c, fmt.Errorf("cannot read standard input: %w", err)
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			return c, errors.New("standard input was empty")
		}
		c.sources = append(c.sources, source{data: data})
	}

	// Sorted so that two runs over the same tree produce identical output, and so
	// that a test can compare against a fixed list. filepath.WalkDir already
	// walks in lexical order, but stdin has no position, and an explicit sort
	// states the intent rather than relying on that.
	sort.Slice(c.sources, func(i, j int) bool { return c.sources[i].path < c.sources[j].path })

	return c, nil
}

// collectDir walks a directory for workflows.
//
// Two shapes have to work, because both are how people point at this:
//
//	ppe scan                          the repository root, which contains
//	                                  .github/workflows
//	ppe scan .github/workflows        the workflow directory itself
//
// Treating the second as "look for .github/workflows inside it" finds nothing,
// which is a confusing way for a valid command to report a clean repository.
func collectDir(c *collection, root string) error {
	if isWorkflowDir(root) {
		return walkWorkflows(c, root)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory is worth naming, since it may hold
			// workflows that were never checked. Not fatal, because the rest of
			// the tree is still worth scanning.
			c.skipped[skipUnreadable]++
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if isWorkflowDir(path) {
			return walkWorkflows(c, path)
		}
		return nil
	})
}

// isWorkflowDir reports whether a directory is a workflow directory, either
// spelled out or reached from a repository root.
func isWorkflowDir(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return strings.HasSuffix(clean, "/"+workflowDir) || clean == workflowDir
}

// walkWorkflows collects every workflow file under a workflow directory.
func walkWorkflows(c *collection, root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			c.skipped[skipUnreadable]++
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !isWorkflowFile(path) {
			c.skipped[skipNotWorkflow]++
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			c.skipped[skipUnreadable]++
			return nil
		}
		c.sources = append(c.sources, source{path: path, data: data})
		return nil
	})
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
