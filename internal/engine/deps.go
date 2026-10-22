package engine

import (
	"fmt"
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

// DepsOptions controls a dependency check.
type DepsOptions struct {
	// Registry is the registry named by --registry, or empty.
	Registry string
	// NoDiff skips the checks that need a base commit. A caller that has no
	// git history, such as the webhook server reading a tarball, sets this.
	NoDiff bool
	// Env is the environment lookup, for NPM_CONFIG_REGISTRY and
	// GITHUB_EVENT_PATH. A nil Env is treated as empty.
	Env func(string) string
}

// DepsReport is the result of a dependency check.
type DepsReport struct {
	Lockfile *lockfile.Lockfile
	Findings findings.Findings
	// Skips are the reasons a check could not run. A skipped check is not a
	// passed one, and the caller is expected to say so.
	Skips []string
}

// CheckDeps runs the dependency checks for the repository at dir.
//
// The checks that need no base commit run first and always. The registry check
// needs no diff, so it works in a shallow checkout, a tarball, or a Docker
// context, where the ones that need a base commit cannot run at all.
func CheckDeps(dir string, opts DepsOptions) (DepsReport, error) {
	var rep DepsReport

	env := opts.Env
	if env == nil {
		env = func(string) string { return "" }
	}

	lock, err := ReadLockfile(dir)
	if err != nil {
		return rep, err
	}
	rep.Lockfile = lock

	registry, _ := deps.DiscoverRegistry(opts.Registry, dir, env, findRegistryURL(dir))

	path := lockfilePath(dir)
	rep.Findings = append(rep.Findings, deps.D3(lock, registry, path)...)

	if !opts.NoDiff {
		base, reason := baseLockfile(dir, env)
		switch {
		case base != nil:
			rep.Findings = append(rep.Findings, deps.Diff(base, lock, path)...)
		case reason != "":
			rep.Skips = append(rep.Skips, reason)
		}
	}

	return rep, nil
}

// ReadLockfile reads the lockfile in a directory.
func ReadLockfile(dir string) (*lockfile.Lockfile, error) {
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

// findRegistryURL finds a setup-node registry-url in the project's workflows.
//
// It returns the first one it finds. A repository that sets different
// registries in different workflows is unusual, and picking one of them is
// better than picking none: the check that uses this compares against a
// registry, and any registry the project names is a better answer than no
// registry at all.
func findRegistryURL(dir string) string {
	entries, err := os.ReadDir(filepath.Join(dir, workflowDir))
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
		data, err := os.ReadFile(filepath.Join(dir, workflowDir, name))
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
func baseLockfile(dir string, env func(string) string) (*lockfile.Lockfile, string) {
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
