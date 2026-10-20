package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Vibrouz/whoa/internal/deps"
	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/lockfile"
)

// lockfileName is the file the dependency checks read.
const lockfileName = "package-lock.json"

// deps is the entry point for "ppe deps".
//
// It is a separate command from "ppe scan" rather than a flag on it, because
// the two read different things and can fail in different ways. A scan reads
// workflow files and needs a directory that holds them. A dependency check
// reads a lockfile and needs a repository, because the checks that matter most
// compare the lockfile against the one at the base commit, and a lockfile on
// its own says nothing about what changed.
//
// The exit codes are the same as the scan's, for the same reason. Zero means
// the check finished and nothing blocks. One means something blocks. Two means
// the check did not finish, and its result says nothing either way.
func depsCommand(cmd command, stdout, stderr io.Writer, env func(string) string) int {
	dir := "."
	if len(cmd.paths) > 0 {
		dir = cmd.paths[0]
	}

	lock, err := readLockfile(dir)
	if err != nil {
		fmt.Fprintf(stderr, "ppe: %v\n", err)
		return exitIncomplete
	}

	registry := discoverRegistry(cmd, dir, env)

	var found findings.Findings

	// The checks that need no base commit run first and always.
	//
	// The registry check needs no diff, so it works in a shallow checkout, a
	// tarball, or a Docker context, where the ones that need a base commit
	// cannot run at all.
	found = append(found, deps.D3(lock, registry, lockfilePath(dir))...)

	// The checks that compare against the base commit.
	if !cmd.noDiff {
		base, reason := baseLockfile(cmd, dir, env)
		switch {
		case base != nil:
			found = append(found, deps.Diff(base, lock, lockfilePath(dir))...)
		case reason != "":
			// The reason is printed, because a check that could not run must
			// not look like a check that passed. A silent skip here would be
			// a clean result for a scan that did not happen.
			fmt.Fprintf(stderr, "ppe: %s\n", reason)
		}
	}

	reportDeps(stdout, found, lock, dir)
	return depsExit(found)
}

// readLockfile reads the lockfile in a directory.
func readLockfile(dir string) (*lockfile.Lockfile, error) {
	path := filepath.Join(dir, lockfileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	lock, err := lockfile.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return lock, nil
}

// lockfilePath is the path the findings are reported against, relative to the
// directory being checked.
func lockfilePath(dir string) string {
	if dir == "." {
		return lockfileName
	}
	return filepath.Join(dir, lockfileName)
}

// discoverRegistry works out which registry the project uses.
//
// The workflow is searched for a setup-node registry-url, because a workflow
// can set a registry for the job and the .npmrc cannot know about it. Every
// workflow file is searched, not just one, because a repository can have any
// number of them and the registry is set in whichever one runs the install.
//
// The search is a plain text search rather than a parse, because the workflow
// is not the thing being checked and a malformed one should not stop the
// dependency checks.
func discoverRegistry(cmd command, dir string, env func(string) string) deps.Registry {
	registry, _ := deps.DiscoverRegistry(cmd.registry, dir, env, findRegistryURL(dir))
	return registry
}

// findRegistryURL finds a setup-node registry-url in the project's workflows.
//
// It returns the first one it finds. A repository that sets different
// registries in different workflows is unusual, and picking one of them is
// better than picking none: the check that uses this compares against a
// registry, and any registry the project names is a better answer than no
// registry at all.
func findRegistryURL(dir string) string {
	entries, err := os.ReadDir(filepath.Join(dir, ".github", "workflows"))
	if err != nil {
		return ""
	}

	// Sorted, so the answer does not depend on the order the filesystem
	// happens to return the names in.
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", name))
		if err != nil {
			continue
		}
		if url := registryURLIn(string(data)); url != "" {
			return url
		}
	}
	return ""
}

// registryURLIn finds a setup-node registry-url in one workflow.
func registryURLIn(workflow string) string {
	for _, line := range strings.Split(workflow, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "registry-url:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "registry-url:"))
		value = strings.Trim(value, `"'`)
		if value != "" {
			return value
		}
	}
	return ""
}

// baseLockfile reads the lockfile at the commit the pull request is based on.
//
// It returns the lockfile, or nil and the reason it could not be read.
//
// Every failure is a skip with a reason, and never an error, because a
// dependency check that cannot find a base commit has not found anything
// wrong. It has failed to look, and the difference has to be visible.
func baseLockfile(cmd command, dir string, env func(string) string) (*lockfile.Lockfile, string) {
	eventPath := env("GITHUB_EVENT_PATH")
	sha, ok := deps.BaseCommit(eventPath)
	if !ok {
		return nil, "no pull request base commit, so the checks that compare against it were skipped"
	}

	if err := deps.FetchCommit(dir, "origin", sha); err != nil {
		return nil, "could not fetch the base commit, so the checks that compare against it were skipped"
	}

	data, err := deps.LockfileAtCommit(dir, sha, lockfileName)
	if err != nil {
		return nil, "the base commit has no " + lockfileName + ", so the checks that compare against it were skipped"
	}

	base, err := lockfile.Parse(data)
	if err != nil {
		return nil, "the base commit's " + lockfileName + " could not be read, so the checks that compare against it were skipped"
	}
	return base, ""
}

// reportDeps writes the result.
//
// It is the same shape as the workflow report, so a reader who has seen one
// knows the other.
func reportDeps(w io.Writer, found findings.Findings, lock *lockfile.Lockfile, dir string) {
	var warns int
	for _, f := range found {
		if !f.Severity.Blocking() {
			warns++
		}
	}
	blocks := 0
	for _, f := range found {
		if f.Severity.Blocking() {
			blocks++
		}
	}

	fmt.Fprintf(w, "checked %d dependenc%s, %d block%s, %d warning%s",
		len(lock.Packages), plural(len(lock.Packages), "y", "ies"),
		blocks, plural(blocks, "", "s"),
		warns, plural(warns, "", "s"))
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	if len(found) == 0 {
		fmt.Fprintln(w, "nothing to report.")
		return
	}

	for _, f := range found {
		tier := "warn"
		if f.Severity.Blocking() {
			tier = "BLOCK"
		}
		fmt.Fprintf(w, "  %-6s %s  %s\n", tier, f.RuleID, f.Location)
		fmt.Fprintf(w, "         %s\n", summarise(f.Message))
	}
}

// depsExit is the exit code for a dependency check.
//
// A Block outranks an incomplete scan, for the same reason the workflow scan
// does it: a confirmed problem is the more actionable news, and reporting
// "could not complete" there would understate it.
func depsExit(found findings.Findings) int {
	for _, f := range found {
		if f.Severity.Blocking() {
			return exitBlocked
		}
	}
	return exitOK
}
