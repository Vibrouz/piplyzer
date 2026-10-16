package rules

import (
	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// This file holds the things more than one rule needs, defined once so that
// rules 1 and 10 cannot drift apart on them. sensitiveJob joins it in Phase 1
// step 6.

// usesSite is one uses: reference together with the place it was written.
type usesSite struct {
	ref parse.UsesRef
	// jobID is empty for a workflow level reference.
	jobID string
	// stepNumber is 0 unless the reference is a step's, so that a job level or
	// workflow level finding cannot be confused with the first step.
	stepNumber int
	stepName   string
}

// allUses returns every uses: reference in the workflow, in document order.
//
// There are three locations and all three matter. Steps are the obvious one.
// jobs.<id>.uses is a reusable workflow call, which is the more dangerous case
// because the jobs that run live in a repository we never see. The workflow
// level uses: is not part of GitHub's workflow schema, but walking it too means
// a shape we do not recognize cannot be the one place a mutable reference
// hides.
//
// A pass that only looks at steps compiles, passes a step-only fixture, and
// misses every reusable workflow call.
func allUses(file *parse.File) []usesSite {
	var sites []usesSite

	for _, uses := range file.Uses {
		sites = append(sites, usesSite{ref: uses})
	}
	for _, job := range file.Jobs {
		if job.Uses != nil {
			sites = append(sites, usesSite{ref: *job.Uses, jobID: job.ID})
		}
		for _, step := range job.Steps {
			if step.Uses != nil {
				sites = append(sites, usesSite{
					ref:        *step.Uses,
					jobID:      job.ID,
					stepNumber: step.Number,
					stepName:   step.Name,
				})
			}
		}
	}
	return sites
}

// location is where a finding about this reference belongs: the step it is in,
// the job it is in, or the workflow itself.
func (u usesSite) location(file *parse.File) findings.Location {
	if u.stepNumber > 0 {
		return findings.AtStep(file.Path, u.ref.Line, u.jobID, u.stepNumber, u.stepName)
	}
	loc := findings.At(file.Path, u.ref.Line)
	loc.JobID = u.jobID
	return loc
}
