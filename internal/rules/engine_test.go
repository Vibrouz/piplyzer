package rules

import (
	"testing"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// The engine is the only place rules are combined, so its contract is tested on
// fake rules. Testing it through rule 1 would only prove it passes one rule
// through.
func TestEngineOrdersAndSorts(t *testing.T) {
	late := func(*parse.File) findings.Findings {
		return findings.Findings{
			findings.New("PPE-002", findings.SeverityBlock, "second rule, later line", findings.At("ci.yml", 30)),
		}
	}
	early := func(*parse.File) findings.Findings {
		return findings.Findings{
			findings.New("PPE-001", findings.SeverityWarn, "first rule, earlier line", findings.At("ci.yml", 10)),
			findings.New("PPE-001", findings.SeverityWarn, "first rule, same line, other rule id sorts after", findings.At("ci.yml", 10)),
		}
	}
	silent := func(*parse.File) findings.Findings { return nil }

	engine := Engine{rules: []Rule{late, early, silent}}
	got := engine.Run(&parse.File{Path: "ci.yml"})

	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3", len(got))
	}
	// Sorted by line, and within a line by rule ID, so the same repository
	// reports in the same order on every run regardless of rule registration
	// order.
	wantOrder := []struct {
		line int
		rule string
	}{
		{10, "PPE-001"},
		{10, "PPE-001"},
		{30, "PPE-002"},
	}
	for i, want := range wantOrder {
		if got[i].Location.Line != want.line || got[i].RuleID != want.rule {
			t.Errorf("finding %d = %s at line %d, want %s at line %d",
				i, got[i].RuleID, got[i].Location.Line, want.rule, want.line)
		}
	}
}

func TestEngineOnEmptyRuleList(t *testing.T) {
	if got := (Engine{}).Run(&parse.File{Path: "ci.yml"}); len(got) != 0 {
		t.Errorf("got %d findings from an engine with no rules", len(got))
	}
}

// NewEngine has to pick up every rule in the package, or a rule ships and never
// runs. This asserts the wiring rather than trusting it.
func TestNewEngineRunsEveryRegisteredRule(t *testing.T) {
	if len(checks) == 0 {
		t.Fatal("no rules registered")
	}
	if got := len(NewEngine().rules); got != len(checks) {
		t.Errorf("NewEngine runs %d rules, but %d are registered", got, len(checks))
	}
}
