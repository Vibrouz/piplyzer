package rules

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// Fixtures are the spec. Every test here asserts an exact finding count and the
// exact rule IDs, because an assertion that matches "at least one" lets a rule
// degrade into a partial check with nothing going red.

const fixtureRoot = "../../tests/fixtures"

// sha is a fabricated 40 character object name for inline test workflows.
const sha = "0123456789abcdef0123456789abcdef01234567"

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func parseFixture(t *testing.T, name string) (*parse.File, []byte) {
	t.Helper()
	data := fixtureBytes(t, name)
	path := filepath.Join(".github/workflows", name)
	file, err := parse.ParseFile(path, data)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return file, data
}

// urlPattern matches a link so message assertions can look at prose only.
var urlPattern = regexp.MustCompile(`https?://\S+`)

// lineOf returns the 1-based line of the first occurrence of substr, counted
// from the raw file bytes. A line number assertion measured against the parsed
// tree only proves the parser agrees with itself.
func lineOf(t *testing.T, data []byte, substr string) int {
	t.Helper()
	idx := bytes.Index(data, []byte(substr))
	if idx < 0 {
		t.Fatalf("fixture does not contain %q", substr)
	}
	return 1 + bytes.Count(data[:idx], []byte("\n"))
}

type want struct {
	rule string
	sev  findings.Severity
	line int
}

// assertFindings checks the exact count, the rule IDs, the severities and the
// lines.
func assertFindings(t *testing.T, got findings.Findings, expected []want) {
	t.Helper()

	if len(got) != len(expected) {
		t.Fatalf("got %d findings, want %d: %v", len(got), len(expected), got)
	}
	for i, w := range expected {
		g := got[i]
		if g.RuleID != w.rule {
			t.Errorf("finding %d rule = %q, want %q", i, g.RuleID, w.rule)
		}
		if g.Severity != w.sev {
			t.Errorf("finding %d severity = %q, want %q", i, g.Severity, w.sev)
		}
		if g.Location.Line != w.line {
			t.Errorf("finding %d line = %d, want %d", i, g.Location.Line, w.line)
		}
		if !g.Severity.Valid() {
			t.Errorf("finding %d has severity %q, which is not a tier this product defines", i, g.Severity)
		}
		if g.RulesetVersion != findings.RulesetVersion {
			t.Errorf("finding %d ruleset version = %q, want %q", i, g.RulesetVersion, findings.RulesetVersion)
		}
		if g.Message == "" {
			t.Errorf("finding %d has an empty message", i)
		}
	}
}

// ---------------------------------------------------------------- rule 1

func TestRule1FlagsMutableRefsAtEveryLocation(t *testing.T) {
	file, data := parseFixture(t, "ppe-001/unpinned.yml")

	got := Rule1(file)

	assertFindings(t, got, []want{
		{Rule1ID, findings.SeverityBlock, lineOf(t, data, "uses: example/ci/.github/workflows/reusable.yml@main")},
		{Rule1ID, findings.SeverityBlock, lineOf(t, data, "uses: other-org/infra/.github/workflows/build.yml@release")},
		{Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/checkout@v4")},
		{Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/setup-node@main")},
	})

	// Locations have to distinguish a step from the job it is in, because the
	// two are different fixes and a report that conflates them sends a
	// maintainer to the wrong place.
	if got[2].Location.JobID != "build" || got[2].Location.StepNumber != 1 {
		t.Errorf("step finding location = %+v, want job build step 1", got[2].Location)
	}
	if got[1].Location.JobID != "call-reusable" || got[1].Location.StepNumber != 0 {
		t.Errorf("reusable workflow finding location = %+v, want job call-reusable with no step", got[1].Location)
	}
	if got[0].Location.JobID != "" || got[0].Location.StepNumber != 0 {
		t.Errorf("workflow level finding location = %+v, want no job and no step", got[0].Location)
	}
}

func TestRule1DoesNotFireWhenPinned(t *testing.T) {
	file, _ := parseFixture(t, "ppe-001/pinned.yml")

	if got := Rule1(file); len(got) != 0 {
		for _, f := range got {
			t.Errorf("unexpected finding on a pinned workflow: %s at %s", f.RuleID, f.Location)
		}
	}
}

func TestRule1TreatsAbbreviatedSHAAsMutable(t *testing.T) {
	file, data := parseFixture(t, "ppe-001/short-sha.yml")

	got := Rule1(file)

	assertFindings(t, got, []want{
		{Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/checkout@5f3b1c0")},
		{Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/cache@a1b2c3d4e5f6")},
	})
	if !strings.Contains(got[0].Message, "abbreviated commit SHA") {
		t.Errorf("message does not say what is wrong with the ref: %s", got[0].Message)
	}
}

// The message leads with the stronger control. Recommending SHA pinning first
// would be recommending the weaker one.
func TestRule1MessageLeadsWithLockfiles(t *testing.T) {
	file, _ := parseFixture(t, "ppe-001/unpinned.yml")
	got := Rule1(file)
	if len(got) == 0 {
		t.Fatal("no findings")
	}

	msg := got[0].Message

	// The ordering is checked on the prose with URLs stripped. The word
	// "lockfile" also appears inside the documentation link, so a message that
	// merely links to the doc would satisfy an assertion on the raw string.
	prose := urlPattern.ReplaceAllString(msg, "")

	lockfiles := strings.Index(prose, "lockfile")
	sha := strings.Index(prose, "SHA")
	if lockfiles < 0 || sha < 0 {
		t.Fatalf("message prose does not mention both controls: %s", prose)
	}
	if lockfiles > sha {
		t.Errorf("message mentions SHA pinning before workflow dependency lockfiles: %s", prose)
	}

	// Leading with the link is not leading with the control. The claim that
	// lockfiles supersede SHA pinning is the part a maintainer acts on.
	if !strings.Contains(prose, "superseding") {
		t.Errorf("message does not say lockfiles supersede SHA pinning: %s", prose)
	}

	// The real case is what makes the finding land rather than read as a style
	// preference, so it stays named.
	if !strings.Contains(prose, "tj-actions/changed-files") {
		t.Errorf("message no longer names the incident it prevents: %s", prose)
	}

	// A figure in user-facing copy needs a source.
	for _, want := range []string{
		"https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles",
		"https://nvd.nist.gov/vuln/detail/cve-2025-30066",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message is missing the source %s: %s", want, msg)
		}
	}
}

// A mistyped SHA in a fixture is 39 or 41 characters instead of 40, and it
// fails as "rule 1 fired on a pinned workflow", which reads like a rule bug and
// is not one. This turns that into the actual problem.
func TestPinnedFixtureSHAsAreFortyCharacters(t *testing.T) {
	data := fixtureBytes(t, "ppe-001/pinned.yml")

	re := regexp.MustCompile(`uses:\s*(\S+?)@([0-9a-fA-F]+)\s*$`)
	found := 0
	for i, line := range strings.Split(string(data), "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		found++
		if len(m[2]) != 40 {
			t.Errorf("pinned.yml:%d: %s@%s is %d characters, not 40. Every SHA in this fixture has to be a full commit name or rule 1 will flag it", i+1, m[1], m[2], len(m[2]))
		}
	}
	if found == 0 {
		t.Fatal("found no SHA references in pinned.yml: the negative fixture no longer covers pinning")
	}
}

func TestRefKind(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		{"v4", "a version tag, which can be moved to point at new code"},
		{"v4.1.2", "a version tag, which can be moved to point at new code"},
		{"4.1.2", "a version tag, which can be moved to point at new code"},
		{"1.0.0-rc1", "a version tag, which can be moved to point at new code"},
		{"main", "a branch or other mutable reference"},
		{"master", "a branch or other mutable reference"},
		{"release/v1", "a branch or other mutable reference"},
		{"5f3b1c0", "an abbreviated commit SHA, which can be extended into a different commit"},
		{"a1b2c3d4e5f6", "an abbreviated commit SHA, which can be extended into a different commit"},
		{"deadbeef", "an abbreviated commit SHA, which can be extended into a different commit"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			if got := refKind(tt.ref); got != tt.want {
				t.Errorf("refKind(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestCommitSHA(t *testing.T) {
	tests := []struct {
		ref     string
		pinned  bool
		comment string
	}{
		{"1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", true, "40 hex characters"},
		{"5f3b1c0d4e8a9b2c7d6e5f4a3b2c1d0e9f8a7b6c", true, "40 hex characters"},
		{"1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D", true, "uppercase hex is still 40 characters, and GitHub does not emit it but it is not a real ambiguity"},
		{"a1b2c3d4e5f6", false, "12 characters"},
		{"5f3b1c0", false, "7 characters"},
		{"1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4", false, "39 characters"},
		{"1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4dd", false, "41 characters"},
		{"z1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", false, "not hex"},
		{"sha256:0123456789abcdef0123456789abcdef", false, "a digest, not a git object name"},
		{"v4", false, "a version tag"},
		{"main", false, "a branch"},
	}

	for _, tt := range tests {
		t.Run(tt.comment, func(t *testing.T) {
			if got := commitSHA.MatchString(tt.ref); got != tt.pinned {
				t.Errorf("commitSHA.MatchString(%q) = %v, want %v", tt.ref, got, tt.pinned)
			}
		})
	}
}

// The exclusions are decisions. Each one is a way a naive implementation
// over-fires or under-fires.
func TestRule1Exclusions(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		flagged bool
		reason  string
	}{
		{"local action", "./.github/actions/build", false, "no ref is reported for a local action, so nothing to repoint"},
		{"local action, parent", "../shared/action", false, "same"},
		{"local action written with a ref", "./.github/actions/build@v4", false, "parse reports no ref for a local path even when it contains an @"},
		{"container action", "docker://alpine:3.19", false, "different supply chain with different controls"},
		{"container action, digest", "docker://alpine@sha256:abc", false, "same"},
		{"no ref at all", "actions/checkout", false, "a workflow that does not run, not one that runs unreviewed code"},
		{"full sha", "actions/checkout@1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", false, "pinned"},
		{"full sha in a subdirectory", "actions/aws/ec2@1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", false, "pinned, and subdirectory is part of the path not the ref"},
		{"version tag", "actions/checkout@v4", true, "the shape most repositories have"},
		{"branch", "actions/setup-node@main", true, "a branch"},
		{"branch with a slash", "actions/setup-node@release/v1", true, "the ref, not the subpath"},
		{"sha as a tag", "actions/checkout@5f3b1c0", true, "abbreviated, so not a pin"},
		{"digest prefix", "actions/checkout@sha256:0123456789abcdef", true, "not a 40 character git object name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parse.Parse([]byte("uses: " + tt.target + "\n"))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := len(Rule1(file)) > 0; got != tt.flagged {
				t.Errorf("flagged = %v, want %v (%s)", got, tt.flagged, tt.reason)
			}
		})
	}
}

// ---------------------------------------------------------------- rule 7

func TestRule7FlagsUnfilteredPush(t *testing.T) {
	file, data := parseFixture(t, "ppe-007/unfiltered.yml")

	got := Rule7(file)

	assertFindings(t, got, []want{
		{Rule7ID, findings.SeverityWarn, lineOf(t, data, "push:")},
	})
	// It is about the workflow, not a job or a step.
	if got[0].Location.JobID != "" || got[0].Location.StepNumber != 0 {
		t.Errorf("location = %+v, want no job and no step", got[0].Location)
	}
	// No incident figure, because plan.md still has the GhostAction counts
	// marked vendor-sourced pending confirmation.
	if strings.Contains(got[0].Message, "772") || strings.Contains(got[0].Message, "2,577") {
		t.Errorf("message quotes an unverified incident figure: %s", got[0].Message)
	}
}

func TestRule7DoesNotFireWhenFiltered(t *testing.T) {
	file, _ := parseFixture(t, "ppe-007/filtered.yml")

	if got := Rule7(file); len(got) != 0 {
		for _, f := range got {
			t.Errorf("unexpected finding on a filtered push: %s at %s", f.RuleID, f.Location)
		}
	}
}

// Every way of writing a push trigger, and whether it counts as filtered. The
// fixture covers branches because that is the case build_plan.md names; the
// rest are inline because a workflow file has exactly one on: block, so each
// shape needs its own.
func TestRule7TriggerShapes(t *testing.T) {
	tests := []struct {
		name      string
		on        string
		flagged   bool
		reasoning string
	}{
		{"scalar, no filter", "on: push", true, "the most common shape and the one GhostAction uses"},
		{"mapping, empty body", "on:\n  push:", true, "same trigger, written out"},
		{"branches", "on:\n  push:\n    branches: [main]", false, "restricted to main"},
		{"branches-ignore", "on:\n  push:\n    branches-ignore: ['wip/**']", false, "an ignore list is still a filter"},
		{"tags", "on:\n  push:\n    tags: ['v*']", false, "only tag pushes, so it is not a ref push"},
		{"tags-ignore", "on:\n  push:\n    tags-ignore: ['nightly/**']", false, "same"},
		{"paths", "on:\n  push:\n    paths: ['src/**']", false, "only runs when src changes"},
		{"paths-ignore", "on:\n  push:\n    paths-ignore: ['docs/**']", false, "same"},
		{"no push event", "on:\n  pull_request:", false, "rule 7 is about push"},
		{"list form with push", "on: [push, pull_request]", true, "still an unfiltered push"},
		{"push with an empty branches list", "on:\n  push:\n    branches: []", true, "an empty list filters nothing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := tt.on + "\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
			file, err := parse.Parse([]byte(src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := len(Rule7(file)) > 0; got != tt.flagged {
				t.Errorf("flagged = %v, want %v (%s)", got, tt.flagged, tt.reasoning)
			}
		})
	}
}

// Rule 7 fires on a large share of legitimate workflows, which is why it is a
// Warn. The block tier is what the exit code hangs on, so getting this wrong
// would make ppe fail on repositories that are doing nothing wrong.
func TestRule7WarnsAndDoesNotBlock(t *testing.T) {
	unfiltered, _ := parseFixture(t, "ppe-007/unfiltered.yml")
	got := Rule7(unfiltered)
	if len(got) == 0 {
		t.Fatal("no findings")
	}
	if got.HasBlock() {
		t.Error("an unfiltered push blocks: a noisy gate gets disabled, and it takes the real rules down with it")
	}

	filtered, _ := parseFixture(t, "ppe-007/filtered.yml")
	if Rule7(filtered).HasBlock() {
		t.Error("a filtered push blocks")
	}
}

// ---------------------------------------------------------------- engine

// Each rule is also asserted through the engine, so a rule that exists but was
// never added to the checks slice fails its own test. Without this the rule's
// fixture passes and the finding never reaches a user.
func TestRulesRunThroughTheEngine(t *testing.T) {
	tests := []struct {
		fixture string
		ids     []string
	}{
		{"ppe-001/unpinned.yml", []string{Rule1ID, Rule1ID, Rule1ID, Rule1ID}},
		{"ppe-001/pinned.yml", nil},
		{"ppe-007/unfiltered.yml", []string{Rule7ID}},
		{"ppe-007/filtered.yml", nil},
		{"ppe-008/dispatch-sensitive.yml", []string{Rule8ID, Rule8ID, Rule8ID}},
		{"ppe-008/dispatch-clean.yml", nil},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			file, _ := parseFixture(t, tt.fixture)
			got := NewEngine().Run(file)

			var ids []string
			for _, f := range got {
				ids = append(ids, f.RuleID)
			}
			if len(ids) != len(tt.ids) {
				t.Fatalf("engine returned %v, want %v", ids, tt.ids)
			}
			for i := range ids {
				if ids[i] != tt.ids[i] {
					t.Errorf("engine finding %d = %s, want %s", i, ids[i], tt.ids[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------- rule 8

func TestRule8FlagsDispatchOnSensitiveJobs(t *testing.T) {
	file, data := parseFixture(t, "ppe-008/dispatch-sensitive.yml")

	got := Rule8(file)

	assertFindings(t, got, []want{
		{Rule8ID, findings.SeverityWarn, lineOf(t, data, "secrets-inherit:")},
		{Rule8ID, findings.SeverityWarn, lineOf(t, data, "deploy-env:")},
		{Rule8ID, findings.SeverityWarn, lineOf(t, data, "  oidc:")},
	})
	// The job has to be named, or a report points at a file with several jobs
	// and no way to tell which one to fix.
	for i, id := range []string{"secrets-inherit", "deploy-env", "oidc"} {
		if got[i].Location.JobID != id {
			t.Errorf("finding %d job = %q, want %q", i, got[i].Location.JobID, id)
		}
	}
}

func TestRule8DoesNotFireOnAnOrdinaryDispatchWorkflow(t *testing.T) {
	file, _ := parseFixture(t, "ppe-008/dispatch-clean.yml")

	if got := Rule8(file); len(got) != 0 {
		for _, f := range got {
			t.Errorf("unexpected finding on an ordinary dispatch workflow: %s at %s", f.RuleID, f.Location)
		}
	}
}

// Rule 8 is Warn, not Block. It fires on real deploy buttons, and a gate that
// blocks on those gets disabled.
func TestRule8WarnsAndDoesNotBlock(t *testing.T) {
	file, _ := parseFixture(t, "ppe-008/dispatch-sensitive.yml")
	if got := Rule8(file); got.HasBlock() {
		t.Error("rule 8 blocks: workflow_dispatch with a privileged job is a normal pattern")
	}
}

// Each way a job becomes sensitive, and each way it does not. The fixture
// covers secrets: and a secret in env; the rest are inline because they differ
// in one line each and a file per case would be a directory of near-identical
// workflows.
func TestRule8SensitivityShapes(t *testing.T) {
	dispatch := "on:\n  workflow_dispatch:\n"
	plain := "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"

	tests := []struct {
		name      string
		src       string
		fired     bool
		reasoning string
	}{
		{
			name:      "secrets: inherit",
			src:       dispatch + "jobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@" + sha + "\n    secrets: inherit\n",
			fired:     true,
			reasoning: "receives every secret the caller made available",
		},
		{
			name:      "explicit secrets mapping",
			src:       dispatch + "jobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@" + sha + "\n    secrets:\n      token: ${{ secrets.T }}\n",
			fired:     true,
			reasoning: "same, written out",
		},
		{
			name:      "empty secrets block is still declared",
			src:       dispatch + "jobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@" + sha + "\n    secrets:\n",
			fired:     true,
			reasoning: "a secrets: key is a chance to hold credentials",
		},
		{
			name:      "secret in job env",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      T: ${{ secrets.T }}\n    steps:\n      - run: echo hi\n",
			fired:     true,
			reasoning: "holds a credential in its environment",
		},
		{
			name:      "secret in a step with:",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: o/r@v1\n        with:\n          token: ${{ secrets.T }}\n",
			fired:     true,
			reasoning: "handed to an action",
		},
		{
			name:      "secret in a run: block",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.T }}\n",
			fired:     true,
			reasoning: "used in a script",
		},
		{
			name:      "secret in an if: condition",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    if: ${{ secrets.T != '' }}\n    steps:\n      - run: echo hi\n",
			fired:     true,
			reasoning: "reads it",
		},
		{
			name:      "github.token",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh api\n        env:\n          GH_TOKEN: ${{ github.token }}\n",
			fired:     true,
			reasoning: "plan.md counts any github.token reference as sensitive, and ordinary API workflows do this",
		},
		{
			name:      "id-token: write at job level",
			src:       dispatch + "jobs:\n  a:\n    permissions:\n      id-token: write\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
			fired:     true,
			reasoning: "can mint a cloud credential",
		},
		{
			name:      "id-token: write inherited from the workflow",
			src:       dispatch + "permissions:\n  id-token: write\n" + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
			fired:     true,
			reasoning: "a job block is not required to hold it",
		},
		{
			name:      "id-token: read is not write",
			src:       dispatch + "jobs:\n  a:\n    permissions:\n      id-token: read\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
			fired:     false,
			reasoning: "cannot mint a credential",
		},
		{
			name:      "checkout with no pull request trigger",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
			fired:     false,
			reasoning: "there is no fork PR to check out",
		},
		{
			name:      "checkout on a pull request event",
			src:       "on:\n  workflow_dispatch:\n  pull_request:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
			fired:     true,
			reasoning: "checks out code on an event a contributor can trigger",
		},
		{
			name:      "checkout on pull_request_target",
			src:       "on:\n  workflow_dispatch:\n  pull_request_target:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
			fired:     true,
			reasoning: "same, and the more dangerous trigger",
		},
		{
			name:      "checkout on workflow_run",
			src:       "on:\n  workflow_dispatch:\n  workflow_run:\n    workflows: [ci]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
			fired:     true,
			reasoning: "same, fixed by decision 18",
		},
		{
			name:      "checkout after a step with no uses: on a pull request event",
			src:       "on:\n  workflow_dispatch:\n  pull_request:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n      - uses: actions/checkout@v4\n",
			fired:     true,
			reasoning: "the walk has to step over steps that have no uses: at all",
		},
		{
			name:      "an action whose name merely contains checkout",
			src:       "on:\n  workflow_dispatch:\n  pull_request:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: some-org/checkout-helper@0123456789abcdef0123456789abcdef01234567\n",
			fired:     false,
			reasoning: "only actions/checkout puts pull request code in the workspace",
		},
		{
			name:      "a different checkout action on a pull request event",
			src:       "on:\n  workflow_dispatch:\n  pull_request:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout-path@0123456789abcdef0123456789abcdef01234567\n",
			fired:     false,
			reasoning: "checkout-path is a different action",
		},
		{
			name:      "run steps only on a pull request event",
			src:       "on:\n  workflow_dispatch:\n  pull_request:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
			fired:     false,
			reasoning: "a pull request event alone is not sensitive: nothing checks code out",
		},
		{
			name:      "an action that is not checkout on a pull request event",
			src:       "on:\n  workflow_dispatch:\n  pull_request:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-node@0123456789abcdef0123456789abcdef01234567\n",
			fired:     false,
			reasoning: "setup-node does not put pull request code in the workspace",
		},
		{
			name:      "nothing sensitive at all",
			src:       dispatch + plain,
			fired:     false,
			reasoning: "the ordinary case",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parse.Parse([]byte(tt.src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := len(Rule8(file)) > 0; got != tt.fired {
				t.Errorf("fired = %v, want %v (%s)", got, tt.fired, tt.reasoning)
			}
		})
	}
}

// Without a workflow_dispatch trigger there is nothing to be dormant, so rule 8
// has no subject.
func TestRule8NeedsTheDispatchTrigger(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"no trigger at all", "jobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@" + sha + "\n    secrets: inherit\n"},
		{"push only", "on:\n  push:\n    branches: [main]\njobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@" + sha + "\n    secrets: inherit\n"},
		{"pull_request only", "on:\n  pull_request:\njobs:\n  a:\n    uses: o/r/.github/workflows/x.yml@" + sha + "\n    secrets: inherit\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parse.Parse([]byte(tt.src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := Rule8(file); len(got) != 0 {
				t.Errorf("rule 8 fired without workflow_dispatch: %v", got)
			}
		})
	}
}

// Every part of a job can hide a secret reference. A check that skips one of
// them is a job that walks through.
func TestSensitiveJobLooksEverywhere(t *testing.T) {
	tokens := []string{"secrets.TOKEN", "github.token"}
	places := []string{
		"jobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      V: %s\n    steps:\n      - run: echo hi\n",
		"jobs:\n  a:\n    runs-on: ubuntu-latest\n    if: \"${{ %s }}\"\n    steps:\n      - run: echo hi\n",
		"jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo %s\n",
		"jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        env:\n          V: %s\n",
		"jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        if: \"${{ %s }}\"\n",
		"jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: o/r@v1\n        with:\n          v: %s\n",
		"jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: o/r@v1\n        env:\n          V: %s\n",
	}
	for _, token := range tokens {
		for i, place := range places {
			t.Run(token+" in place", func(t *testing.T) {
				src := "on:\n  workflow_dispatch:\n" + fmt.Sprintf(place, token)
				file, err := parse.Parse([]byte(src))
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				if len(Rule8(file)) == 0 {
					t.Errorf("secret in place %d was not detected", i)
				}
			})
		}
	}
}
