// Package rules implements the PPE checks that run against a parsed workflow.
//
// Every check is a pure function from a parsed workflow to a list of findings:
// no I/O, no shared state, no rule calling another. Two things follow from
// that, and both are load bearing rather than stylistic.
//
// Fixtures can call a rule directly and assert its own finding count, so a rule
// can never quietly turn into a partial check. And no rule can be affected by
// whether another one ran, which is what lets them be built in any order.
//
// A check that needs to know about another check does not reach for it. The
// GhostAction composite is the one exception and takes the other rules' findings
// as an argument, because counting findings from rules 4 through 8 is genuinely
// its input; see decisions.md section 21.
package rules

import (
	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// Rule is one check.
type Rule func(*parse.File) findings.Findings

// checks is every rule in the order it runs. A fixed slice rather than a
// registry, so output order cannot depend on map iteration or on which rules
// happen to exist yet.
var checks = []Rule{
	Rule1,
	Rule2,
	Rule7,
	Rule8,
}

// Engine runs the rules against a workflow.
//
// It exists so that ordering and the aggregate live in one place, while each
// rule stays independently callable from a test.
type Engine struct {
	rules []Rule
}

// NewEngine returns an engine running every rule in this package.
func NewEngine() Engine { return Engine{rules: checks} }

// Run applies every rule to a file and returns the combined findings, sorted so
// that the same repository reports in the same order on every run.
//
// The GhostAction composite is appended here when it lands. It takes the
// findings below as an argument, which is the only place a rule is allowed to
// see another rule's output.
func (e Engine) Run(file *parse.File) findings.Findings {
	var all findings.Findings
	for _, rule := range e.rules {
		all = append(all, rule(file)...)
	}
	all.Sort()
	return all
}
