package rules

import (
	"strings"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// This file holds the things more than one rule needs, defined once so that
// rules cannot drift apart on them.

// prEvents are the events that can bring contributor-influenced content into a
// workflow. decisions.md section 18 fixes this set: dropping pull_request misses
// the common fork case, dropping pull_request_target misses the deliberate one,
// and workflow_run runs a second workflow's job graph with a write token.
var prEvents = []string{"pull_request", "pull_request_target", "workflow_run"}

// isPREvent reports whether the workflow can be triggered by a pull request.
func isPREvent(file *parse.File) bool {
	for _, event := range prEvents {
		if file.Triggers.Has(event) {
			return true
		}
	}
	return false
}

// sensitiveJob reports whether a job can reach credentials.
//
// Rules 8 and 11 both need this and would drift if each defined it. A job is
// sensitive when it references a repository secret, declares id-token: write,
// receives secrets through its own secrets: block, or checks out code on a pull
// request event.
//
// The workflow token is deliberately not part of this. github.token and
// secrets.GITHUB_TOKEN are the same credential and are available in every job,
// so a reference to it does not make a job sensitive in the sense these rules
// mean: the harm they target is a credential the attacker would not otherwise
// have. The workflow token is owned by rule 11, which has the permissions
// context to say whether it is over-privileged.
//
// The reasons are returned as a string so the finding can say which one applied.
// A job that trips three of them should not produce a message implying it
// tripped none.
func sensitiveJob(file *parse.File, job parse.Job) (bool, string) {
	if job.Secrets.Declared {
		return true, "it receives secrets through its secrets: block"
	}
	if jobReferencesRealSecret(job) {
		return true, "it references a repository secret"
	}
	if permissions, ok := file.PermissionsFor(job.ID); ok && permissions.Grants("id-token") {
		return true, "id-token: write lets it mint a cloud credential"
	}
	if isPREvent(file) && jobChecksOutCode(job) {
		return true, "it checks out code on a pull request event"
	}
	return false, ""
}

// jobReferencesRealSecret reports whether any part of the job mentions a
// repository secret. The workflow token is excluded on purpose: it is the same
// credential in every job and is owned by rule 11.
//
// Every place a job can carry an expression is checked: its own env, with, if
// and secrets, and the same on each step. A workflow that hides the reference
// in one place we do not look is a workflow that gets skipped.
func jobReferencesRealSecret(job parse.Job) bool {
	if valuesMentionRealSecret(job.Env) || valuesMentionRealSecret(job.With) ||
		valuesMentionRealSecret(job.Secrets.Values) || mentionsRealSecret(job.If) {
		return true
	}
	for _, step := range job.Steps {
		if mentionsRealSecret(step.Run) || mentionsRealSecret(step.If) ||
			valuesMentionRealSecret(step.With) || valuesMentionRealSecret(step.Env) {
			return true
		}
	}
	return false
}

func valuesMentionRealSecret(values parse.Values) bool {
	for _, entry := range values {
		if mentionsRealSecret(entry.Text) {
			return true
		}
	}
	return false
}

// mentionsRealSecret reports whether the text references a repository secret.
// secrets.GITHUB_TOKEN is the workflow token and does not count.
func mentionsRealSecret(text string) bool {
	for _, marker := range []string{"secrets."} {
		idx := 0
		for {
			pos := findSubstring(text, marker, idx)
			if pos < 0 {
				break
			}
			if !strings.HasPrefix(text[pos+len(marker):], "GITHUB_TOKEN") {
				return true
			}
			idx = pos + len(marker)
		}
	}
	return false
}

// findSubstring is strings.Index from an offset, kept here so the secret check
// can keep scanning past a GITHUB_TOKEN reference.
func findSubstring(s, sub string, from int) int {
	if from >= len(s) {
		return -1
	}
	i := strings.Index(s[from:], sub)
	if i < 0 {
		return -1
	}
	return from + i
}

// checkoutActions are the actions that put pull request code in the workspace.
var checkoutActions = map[string]bool{
	"actions/checkout": true,
}

// jobChecksOutCode reports whether any step checks code out.
//
// actions/checkout now refuses fork pull request checkouts on
// pull_request_target and workflow_run unless the job opts out, so this is the
// documented safe shape rather than the finding. It is here because a job that
// checks out code on a pull request event holds a token and runs whatever came
// back.
func jobChecksOutCode(job parse.Job) bool {
	for _, step := range job.Steps {
		if step.Uses == nil {
			continue
		}
		repo, _, _ := step.Uses.Parts()
		if checkoutActions[repo] {
			return true
		}
	}
	return false
}

// jobLocation is where a finding about a whole job belongs.
func jobLocation(file *parse.File, job parse.Job) findings.Location {
	loc := findings.At(file.Path, job.Line)
	loc.JobID = job.ID
	return loc
}

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
