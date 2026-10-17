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
			idx = pos + len(marker) + len("GITHUB_TOKEN")
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

// runSite is one run: block in a workflow, with the place it was written.
type runSite struct {
	// script is the run value with block scalars already joined.
	script string
	// runLine is the first line of the script inside the file.
	runLine int
	jobID   string
	step    parse.Step
}

// stripShellComment removes a trailing comment from one line of a script.
//
// A rule that matches a command by its text will otherwise match a line that only
// documents it, and `# do not forget to git fetch origin main` is an ordinary
// thing for someone to write. For a Warn rule that is untidy; for a Block rule it
// blocks a repository on a line nobody runs.
//
// The scan is quote aware, and that is not a refinement. An earlier version just
// looked for a # after whitespace, which meant `echo 'release #42' && git fetch
// origin pull/1/head` lost everything after the quoted hash and the real command
// went unseen. A Block rule whose bypass is one apostrophe is worse than the
// false positive it was written to remove, so quoting has to be understood rather
// than approximated.
//
// Inside single quotes a backslash is an ordinary character, which is POSIX
// behaviour and is what `bash -c 'echo '\”hi'\”'` depends on. Inside double
// quotes a backslash escapes. Outside quotes a backslash escapes too, so a
// trailing backslash continues the line rather than ending it.
func stripShellComment(line string) string {
	var quote byte
	var out strings.Builder

	for i := 0; i < len(line); i++ {
		c := line[i]

		if quote != 0 {
			out.WriteByte(c)
			// Escapes apply inside double quotes only. In single quotes POSIX
			// gives a backslash no special meaning at all.
			if c == '\\' && quote == '"' && i+1 < len(line) {
				out.WriteByte(line[i+1])
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}

		switch {
		case c == '\'' || c == '"':
			quote = c
			out.WriteByte(c)
		case c == '\\' && i+1 < len(line):
			// An escaped character outside quotes cannot open a comment, so it
			// and whatever it escapes are both kept.
			out.WriteByte(c)
			out.WriteByte(line[i+1])
			i++
		case c == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			// An unquoted # after whitespace starts a comment and ends the line.
			return out.String()
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

// uncommentedScript removes the comments from a whole script, keeping the line
// structure so that an offset in the result still maps to the right line.
func uncommentedScript(script string) string {
	lines := strings.Split(script, "\n")
	for i, line := range lines {
		lines[i] = stripShellComment(line)
	}
	return strings.Join(lines, "\n")
}

// allRunScripts returns every run: block in the workflow, in document order.
//
// Rules 2, 3, 4, and 5 all match against the resolved script text rather than
// the raw YAML lines, so they share this walk. Each rule owns what it matches;
// this only hands them the script, the line to blame, and the step it belongs to.
func allRunScripts(file *parse.File) []runSite {
	var sites []runSite
	for _, job := range file.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}
			sites = append(sites, runSite{
				script:  step.Run,
				runLine: step.RunLine,
				jobID:   job.ID,
				step:    step,
			})
		}
	}
	return sites
}

// location is where a finding about this script belongs.
func (r runSite) location(file *parse.File) findings.Location {
	return findings.AtStep(file.Path, r.runLine, r.jobID, r.step.Number, r.step.Name)
}

// lineAt maps a byte offset within the script back to a line in the file, so a
// match partway through a block scalar points at the line the match is on.
func (r runSite) lineAt(offset int) int {
	if r.runLine == 0 || offset < 0 || offset > len(r.script) {
		return r.runLine
	}
	return r.runLine + strings.Count(r.script[:offset], "\n")
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
