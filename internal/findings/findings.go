// Package findings defines the single result type that every check in ppe
// returns.
//
// The PPE rules, the npm lockfile checks, and the CLI all speak in terms of
// Finding, so this shape is the contract between them and the reason it is
// deliberately small. Which subsystem a finding came from, and which of the
// checks fired, are both encoded in the rule ID; whether a merge is blocked is
// a function of severity. Neither is stored as a field, because a field that
// can disagree with the rest of the value is a class of bug this package exists
// to rule out.
//
// Changing anything here is a change to every package that imports it.
package findings

import (
	"fmt"
	"sort"
)

// RulesetVersion identifies the set of checks that produced a finding.
//
// Every finding carries it so that a disagreement between two runs is
// diagnosable: the same version on both sides means one side has a bug,
// different versions means one side is running stale checks. Bump it whenever
// the behavior of a check changes, not on every release.
const RulesetVersion = "1.0.0"

// Severity is the triage tier of a finding.
//
// Only the two tiers this tool produces are defined. An Info tier would be a
// third case for every consumer of this package to handle, and no check emits
// one, so it is left out rather than defined and never used.
type Severity string

const (
	// SeverityBlock fails the check, which blocks the merge when ppe runs as a
	// required status check. Reserved for findings on attacker-controlled
	// external content: configuration patterns that legitimate repositories
	// use every day warn instead, because a noisy gate gets disabled and takes
	// the blocking checks down with it.
	SeverityBlock Severity = "block"
	// SeverityWarn annotates and lets the merge proceed.
	SeverityWarn Severity = "warn"
)

func (s Severity) String() string { return string(s) }

// Valid reports whether s is a severity this package defines. Used by tests to
// assert that a check did not invent a tier.
func (s Severity) Valid() bool {
	return s == SeverityBlock || s == SeverityWarn
}

// Blocking reports whether a finding at this severity fails the check.
func (s Severity) Blocking() bool { return s == SeverityBlock }

// Location is where in a repository a finding was observed.
//
// The zero value is a valid file-level location with no step. StepNumber is
// 1-based so that zero means "not a step" unambiguously: a step index would
// have to be offset by one somewhere, and an offset by one that lands on step
// 0 is a silent misreport rather than an error.
type Location struct {
	// File is the repository-relative path of the file the finding came from.
	File string `json:"file"`
	// Line is the 1-based line, or 0 when the finding is not tied to a line.
	Line int `json:"line"`
	// Column is the 1-based column, or 0 when there is not one.
	Column int `json:"column,omitempty"`
	// JobID is the job the finding is in, empty for a workflow-level finding.
	JobID string `json:"job_id,omitempty"`
	// StepNumber is the 1-based position of the step in its job, or 0 when the
	// finding is about the job or the whole workflow.
	StepNumber int `json:"step_number,omitempty"`
	// StepName is the name of the step, for output a human can act on.
	StepName string `json:"step_name,omitempty"`
}

// At returns a location for a file or a whole job, with no step.
func At(file string, line int) Location {
	return Location{File: file, Line: line}
}

// AtStep returns a location for one step of one job.
func AtStep(file string, line int, jobID string, stepNumber int, stepName string) Location {
	return Location{File: file, Line: line, JobID: jobID, StepNumber: stepNumber, StepName: stepName}
}

// String renders the location for terminal and annotation output.
func (l Location) String() string {
	if l.File == "" {
		return "(no file)"
	}
	out := l.File
	if l.Line > 0 {
		out = fmt.Sprintf("%s:%d", out, l.Line)
		if l.Column > 0 {
			out = fmt.Sprintf("%s:%d", out, l.Column)
		}
	}
	if l.JobID != "" {
		out = fmt.Sprintf("%s in job %s", out, l.JobID)
	}
	if l.StepNumber > 0 {
		out = fmt.Sprintf("%s step %d", out, l.StepNumber)
		if l.StepName != "" {
			out = fmt.Sprintf("%s (%s)", out, l.StepName)
		}
	}
	return out
}

// Finding is one thing a check noticed that a maintainer should look at.
//
// The rule ID is the stable identifier used for filtering, for suppression, and
// for naming the fixture that covers the check, so it must not change meaning
// between releases. The human-facing explanation of what to do about a finding
// belongs in Message rather than in a separate remediation field: it is the same
// paragraph, and splitting it produces two places for the advice to drift.
type Finding struct {
	// RuleID identifies the check, for example PPE-001 or DEP-D2. See
	// internal/rules for the PPE identifiers.
	RuleID string `json:"rule_id"`
	// Severity is the triage tier, Block or Warn.
	Severity Severity `json:"severity"`
	// Message is one paragraph explaining what matched, why it matters, and
	// what to do instead.
	Message string `json:"message"`
	// Location is where it matched.
	Location Location `json:"location"`
	// RulesetVersion is stamped by New. It is a field rather than something the
	// CLI adds at print time so that a finding is self describing wherever it
	// ends up, including in a serialized result the CLI did not write.
	RulesetVersion string `json:"ruleset_version"`
}

// New returns a Finding stamped with the current ruleset version.
//
// The version is applied here rather than left to each check so that no check
// can forget it: a finding with a blank version is exactly the version skew
// the field exists to expose.
func New(ruleID string, severity Severity, message string, loc Location) Finding {
	return Finding{
		RuleID:         ruleID,
		Severity:       severity,
		Message:        message,
		Location:       loc,
		RulesetVersion: RulesetVersion,
	}
}

// Findings is an ordered set of findings from one or more checks.
type Findings []Finding

// HasBlock reports whether any finding blocks the merge.
func (f Findings) HasBlock() bool {
	for _, finding := range f {
		if finding.Severity.Blocking() {
			return true
		}
	}
	return false
}

// Blocking returns only the findings that block the merge.
func (f Findings) Blocking() Findings {
	var out Findings
	for _, finding := range f {
		if finding.Severity.Blocking() {
			out = append(out, finding)
		}
	}
	return out
}

// ByRule returns the findings a single check produced.
func (f Findings) ByRule(ruleID string) Findings {
	var out Findings
	for _, finding := range f {
		if finding.RuleID == ruleID {
			out = append(out, finding)
		}
	}
	return out
}

// Count returns how many findings have the given severity.
func (f Findings) Count(severity Severity) int {
	n := 0
	for _, finding := range f {
		if finding.Severity == severity {
			n++
		}
	}
	return n
}

// RuleIDs returns the distinct rule IDs present, sorted, for summary output.
func (f Findings) RuleIDs() []string {
	seen := make(map[string]bool, len(f))
	ids := make([]string, 0, len(f))
	for _, finding := range f {
		if !seen[finding.RuleID] {
			seen[finding.RuleID] = true
			ids = append(ids, finding.RuleID)
		}
	}
	sort.Strings(ids)
	return ids
}

// Sort orders findings by file, then line, then rule ID.
//
// Checks return findings in the order they walked the workflow, which is stable
// on its own, but output that concatenates several checks needs one ordering
// rule or the same repository reports in a different order every run.
func (f Findings) Sort() {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		return a.RuleID < b.RuleID
	})
}
