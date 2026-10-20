package deps

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// BaseCommit finds the commit a pull request is based on.
//
// It reads the base SHA out of the event payload that GitHub writes, rather
// than resolving it from the git history, and the reason is that the history
// is not there to resolve it from.
//
// actions/checkout defaults to fetch-depth: 1, so a checkout has one commit and
// no history, and git merge-base has nothing to work with. On a pull_request
// event the checkout also fetches a synthetic merge ref, which distorts the
// graph further. The event payload names the base commit directly, so it is
// read from there.
//
// It returns the SHA and true when it found one, and an empty string and false
// when it did not.
//
// The reasons it can fail are all ordinary and none of them is an error worth
// stopping for:
//
//   - GITHUB_EVENT_PATH is not set, which is a local run or a push event.
//   - The file is missing or unreadable.
//   - The payload is not JSON, or is JSON of a different event.
//   - The event is not a pull request, so it has no base.
//
// A caller that cannot find a base cannot diff against one, and that is a skip
// rather than a failure.
func BaseCommit(eventPath string) (string, bool) {
	if eventPath == "" {
		return "", false
	}

	data, err := os.ReadFile(eventPath)
	if err != nil {
		return "", false
	}

	var payload struct {
		PullRequest *struct {
			Base *struct {
				SHA string `json:"sha"`
			} `json:"base"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", false
	}

	if payload.PullRequest == nil || payload.PullRequest.Base == nil {
		return "", false
	}

	sha := strings.TrimSpace(payload.PullRequest.Base.SHA)
	if sha == "" {
		return "", false
	}
	return sha, true
}

// FetchCommit fetches one commit from the remote, so that its tree can be
// read.
//
// The fetch is shallow and single-commit on purpose. The only thing needed is
// the tree of one commit, and a full history fetch is slow and does nothing
// for the check.
//
// A failure is returned rather than swallowed. The caller decides what a
// failure means, and for the checks that need a base commit it means the
// checks are skipped, which the caller has to say out loud.
func FetchCommit(repoDir string, remote string, sha string) error {
	cmd := exec.Command("git", "fetch", "--depth", "1", remote, sha)
	cmd.Dir = repoDir
	// The output goes nowhere. A fetch prints progress to stderr and the
	// caller reports the outcome in its own words.
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("fetching %s from %s: %w", sha, remote, err)
	}
	return nil
}

// LockfileAtCommit reads a file out of a commit, using git show.
//
// It is the same thing as "git show <sha>:<path>", done in process rather than
// by running git and capturing its output, so that a path with spaces or other
// awkward characters in it is passed as one argument and not re-parsed by a
// shell.
//
// It returns the file's contents and true, or an error when the file is not in
// that commit. A missing file is the normal case for a pull request that adds
// a lockfile, and the caller treats it as a skip.
func LockfileAtCommit(repoDir string, sha string, path string) ([]byte, error) {
	cmd := exec.Command("git", "show", sha+":"+path)
	cmd.Dir = repoDir
	cmd.Stderr = nil

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("reading %s at %s: %w", path, sha, err)
	}
	return out, nil
}
