package findings_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/findings"
)

func TestNewStampsRulesetVersion(t *testing.T) {
	f := findings.New("PPE-001", findings.SeverityBlock, "action is not pinned to a SHA", findings.At(".github/workflows/ci.yml", 12))

	if f.RulesetVersion != findings.RulesetVersion {
		t.Errorf("RulesetVersion = %q, want %q", f.RulesetVersion, findings.RulesetVersion)
	}
	if f.RulesetVersion == "" {
		t.Error("RulesetVersion is empty: a finding must always carry the version that produced it")
	}
}

func TestSeverity(t *testing.T) {
	tests := []struct {
		severity findings.Severity
		valid    bool
		blocking bool
	}{
		{findings.SeverityBlock, true, true},
		{findings.SeverityWarn, true, false},
		{findings.Severity("info"), false, false},
		{findings.Severity(""), false, false},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			if got := tt.severity.Valid(); got != tt.valid {
				t.Errorf("Valid() = %v, want %v", got, tt.valid)
			}
			if got := tt.severity.Blocking(); got != tt.blocking {
				t.Errorf("Blocking() = %v, want %v", got, tt.blocking)
			}
			if !tt.valid && tt.severity.Blocking() {
				t.Error("an unknown severity must not be treated as blocking")
			}
		})
	}
}

func TestLocationString(t *testing.T) {
	tests := []struct {
		name string
		loc  findings.Location
		want string
	}{
		{
			name: "file level",
			loc:  findings.At(".github/workflows/ci.yml", 1),
			want: ".github/workflows/ci.yml:1",
		},
		{
			name: "file level with column",
			loc:  findings.Location{File: ".github/workflows/ci.yml", Line: 1, Column: 3},
			want: ".github/workflows/ci.yml:1:3",
		},
		{
			name: "job level",
			loc:  findings.Location{File: ".github/workflows/ci.yml", Line: 20, JobID: "build"},
			want: ".github/workflows/ci.yml:20 in job build",
		},
		{
			name: "step level",
			loc:  findings.AtStep(".github/workflows/ci.yml", 24, "build", 2, "lint"),
			want: ".github/workflows/ci.yml:24 in job build step 2 (lint)",
		},
		{
			name: "no file",
			loc:  findings.Location{},
			want: "(no file)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.loc.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The zero value of StepNumber must mean "not a step". With a 0-based index the
// first step of a job would share a value with a job-level finding, and the two
// would be indistinguishable in output and in filtering.
func TestZeroLocationIsNotStepZero(t *testing.T) {
	jobLevel := findings.At("ci.yml", 7)
	if jobLevel.StepNumber != 0 {
		t.Errorf("At() produced StepNumber = %d, want 0", jobLevel.StepNumber)
	}

	step := findings.AtStep("ci.yml", 9, "build", 1, "build")
	if step.StepNumber != 1 {
		t.Errorf("first step has StepNumber = %d, want 1", step.StepNumber)
	}
	if jobLevel.StepNumber == step.StepNumber {
		t.Error("a job-level finding is indistinguishable from the first step of a job")
	}
}

func TestJSONUsesSnakeCaseKeys(t *testing.T) {
	f := findings.New("PPE-004", findings.SeverityBlock, "bare IP literal in run", findings.AtStep("ci.yml", 24, "build", 3, "exfil"))

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(data)
	for _, key := range []string{`"rule_id"`, `"ruleset_version"`, `"severity"`, `"message"`, `"location"`, `"job_id"`, `"step_number"`, `"step_name"`} {
		if !strings.Contains(got, key) {
			t.Errorf("marshaled finding %s does not contain %s", got, key)
		}
	}
	if !strings.Contains(got, `"severity":"block"`) {
		t.Errorf("severity should marshal as the lowercase tier name, got %s", got)
	}

	// A lockfile finding has no job or step, so those keys are omitted rather
	// than serialized as empty strings that a consumer would have to special case.
	dep := findings.New("DEP-D2", findings.SeverityBlock, "install script", findings.At("package-lock.json", 42))
	data, err = json.Marshal(dep)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := string(data); strings.Contains(got, "job_id") || strings.Contains(got, "step_number") {
		t.Errorf("dependency finding should omit step keys, got %s", got)
	}
}

func TestFindings(t *testing.T) {
	fs := findings.Findings{
		findings.New("PPE-007", findings.SeverityWarn, "unfiltered push", findings.At("ci.yml", 1)),
		findings.New("PPE-004", findings.SeverityBlock, "bare IP in run", findings.At("ci.yml", 9)),
		findings.New("PPE-004", findings.SeverityBlock, "bare IP in run", findings.At("ci.yml", 12)),
	}

	if !fs.HasBlock() {
		t.Error("HasBlock() = false, want true")
	}
	if got := fs.Blocking(); len(got) != 2 {
		t.Errorf("Blocking() returned %d findings, want 2", len(got))
	}
	if got := fs.Count(findings.SeverityWarn); got != 1 {
		t.Errorf("Count(warn) = %d, want 1", got)
	}
	if got := fs.ByRule("PPE-004"); len(got) != 2 {
		t.Errorf("ByRule(PPE-004) returned %d findings, want 2", len(got))
	}
	if got := fs.ByRule("PPE-999"); len(got) != 0 {
		t.Errorf("ByRule(PPE-999) returned %d findings, want 0", len(got))
	}
	if got := fs.RuleIDs(); len(got) != 2 || got[0] != "PPE-004" || got[1] != "PPE-007" {
		t.Errorf("RuleIDs() = %v, want [PPE-004 PPE-007]", got)
	}

	warnsOnly := findings.Findings{findings.New("PPE-010", findings.SeverityWarn, "external action", findings.At("ci.yml", 3))}
	if warnsOnly.HasBlock() {
		t.Error("a warn-only set must not block: rules 7, 8, 10 and 11 fire on legitimate repositories")
	}
}

func TestSortIsStableAcrossInputOrder(t *testing.T) {
	a := findings.New("PPE-004", findings.SeverityBlock, "first", findings.At("b.yml", 5))
	b := findings.New("PPE-004", findings.SeverityBlock, "second", findings.At("a.yml", 30))
	c := findings.New("PPE-001", findings.SeverityBlock, "third", findings.At("a.yml", 10))

	forward := findings.Findings{a, b, c}
	reverse := findings.Findings{c, b, a}
	forward.Sort()
	reverse.Sort()

	if forward[0].Location.File != reverse[0].Location.File || forward[0].Location.Line != reverse[0].Location.Line {
		t.Errorf("Sort() is not order independent: %v vs %v", forward, reverse)
	}
	if forward[0].Location.File != "a.yml" || forward[0].Location.Line != 10 {
		t.Errorf("Sort() put %s:%d first, want a.yml:10", forward[0].Location.File, forward[0].Location.Line)
	}
}
