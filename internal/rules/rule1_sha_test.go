package rules_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
	"github.com/Vibrouz/whoa/internal/rules"
)

const fixtureDir = "../../tests/fixtures/ppe-001"

// urlPattern matches a link so message assertions can look at prose only.
var urlPattern = regexp.MustCompile(`https?://\S+`)

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, name))
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

// assertFindings checks the exact count, the rule IDs, the severities and the
// lines. An assertion that matches "at least one" lets a rule degrade into a
// partial check with nothing going red.
func assertFindings(t *testing.T, got findings.Findings, want []struct {
	rule string
	sev  findings.Severity
	line int
}) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for i, w := range want {
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

func TestRule1FlagsMutableRefsAtEveryLocation(t *testing.T) {
	file, data := parseFixture(t, "unpinned.yml")

	got := rules.Rule1(file)

	assertFindings(t, got, []struct {
		rule string
		sev  findings.Severity
		line int
	}{
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "uses: example/ci/.github/workflows/reusable.yml@main")},
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "uses: other-org/infra/.github/workflows/build.yml@release")},
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/checkout@v4")},
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/setup-node@main")},
	})

	// Locations have to distinguish a step from the job it is in, because the
	// two are different fixes and a report that conflates them sends a
	// maintainer to the wrong place.
	first := got[2]
	if first.Location.JobID != "build" {
		t.Errorf("step finding job = %q, want build", first.Location.JobID)
	}
	if first.Location.StepNumber != 1 {
		t.Errorf("step finding step = %d, want 1", first.Location.StepNumber)
	}
	if jobFinding := got[1]; jobFinding.Location.JobID != "call-reusable" || jobFinding.Location.StepNumber != 0 {
		t.Errorf("reusable workflow finding location = %+v, want job call-reusable with no step", jobFinding.Location)
	}
	if workflowFinding := got[0]; workflowFinding.Location.JobID != "" || workflowFinding.Location.StepNumber != 0 {
		t.Errorf("workflow level finding location = %+v, want no job and no step", workflowFinding.Location)
	}
}

func TestRule1DoesNotFireWhenPinned(t *testing.T) {
	file, _ := parseFixture(t, "pinned.yml")

	if got := rules.Rule1(file); len(got) != 0 {
		for _, f := range got {
			t.Errorf("unexpected finding on a pinned workflow: %s at %s", f.RuleID, f.Location)
		}
	}
}

func TestRule1TreatsAbbreviatedSHAAsMutable(t *testing.T) {
	file, data := parseFixture(t, "short-sha.yml")

	got := rules.Rule1(file)

	assertFindings(t, got, []struct {
		rule string
		sev  findings.Severity
		line int
	}{
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/checkout@5f3b1c0")},
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/cache@a1b2c3d4e5f6")},
	})
	if !strings.Contains(got[0].Message, "abbreviated commit SHA") {
		t.Errorf("message does not say what is wrong with the ref: %s", got[0].Message)
	}
}

// The message leads with the stronger control. Recommending SHA pinning first
// would be recommending the weaker one.
func TestRule1MessageLeadsWithLockfiles(t *testing.T) {
	file, _ := parseFixture(t, "unpinned.yml")
	got := rules.Rule1(file)
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

// The exit code contract, without the CLI. A Block finding has to block.
func TestRule1Blocks(t *testing.T) {
	malicious, _ := parseFixture(t, "unpinned.yml")
	if !rules.Rule1(malicious).HasBlock() {
		t.Error("unpinned workflow does not block")
	}

	benign, _ := parseFixture(t, "pinned.yml")
	if rules.Rule1(benign).HasBlock() {
		t.Error("pinned workflow blocks: a false positive on a gate takes the real rules down with it")
	}
}

func TestEngineRunsRulesAndSorts(t *testing.T) {
	file, data := parseFixture(t, "unpinned.yml")

	got := rules.NewEngine().Run(file)

	assertFindings(t, got, []struct {
		rule string
		sev  findings.Severity
		line int
	}{
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "uses: example/ci/.github/workflows/reusable.yml@main")},
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "uses: other-org/infra/.github/workflows/build.yml@release")},
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/checkout@v4")},
		{rules.Rule1ID, findings.SeverityBlock, lineOf(t, data, "- uses: actions/setup-node@main")},
	})
}

// A mistyped SHA in a fixture is 39 or 41 characters instead of 40, and it
// fails as "rule 1 fired on a pinned workflow", which reads like a rule bug and
// is not one. This turns that into the actual problem.
func TestPinnedFixtureSHAsAreFortyCharacters(t *testing.T) {
	data := fixtureBytes(t, "pinned.yml")

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

func TestEngineOnACleanWorkflow(t *testing.T) {
	file, _ := parseFixture(t, "pinned.yml")

	if got := rules.NewEngine().Run(file); len(got) != 0 {
		t.Errorf("engine produced %d findings on a pinned workflow: %+v", len(got), got)
	}
}
