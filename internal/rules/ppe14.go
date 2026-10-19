package rules

import (
	"strings"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// ---------------------------------------------------------------- rule 14

// Rule 14: a secret used as a structured value is not redacted.

// Rule14ID is the rule identifier for rule 14.
const Rule14ID = "PPE-014"

// Rule14 reports a secret that reaches the log unredacted.
//
// The runner redacts a secret from the log by matching the exact string value
// it holds. That works when the workflow refers to the secret as a whole:
//
//	env:
//	  PASSWORD: ${{ secrets.MY_SECRET }}
//
// It stops working the moment the secret is treated as a structured value. If
// the secret holds a JSON document and the workflow takes one field out of it:
//
//	env:
//	  PASSWORD: ${{ fromJSON(secrets.MY_SECRET).password }}
//
// then the value in the log is a substring of the secret, not the secret, and
// there is nothing for the runner to match. The password is printed in full.
//
// This is Block, and it is the most straightforwardly exploitable finding in
// this ruleset. It needs no attacker at all: the value is in the job log, and
// anyone who can read the log can read the secret. On a public repository the
// logs are public.
//
// The whole secrets context has the same problem, since toJSON(secrets) puts
// every secret in the log at once, and that is reported by the same rule.
func Rule14(file *parse.File) findings.Findings {
	var out findings.Findings

	for _, job := range file.Jobs {
		for _, site := range secretSites(job) {
			if !usesSecretAsStructuredValue(site.text) {
				continue
			}
			out = append(out, findings.New(
				Rule14ID,
				findings.SeverityBlock,
				rule14Message(site.text),
				site.location(file, job),
			))
		}
	}

	return out
}

// secretSite is one place a job can carry a secret reference.
type secretSite struct {
	// text is the value as written, which is what has to be searched.
	text string
	// line is where the value is, and jobID is the job it belongs to.
	line  int
	jobID string
	// step is the step number and stepName its name, 0 for a job level value.
	step     int
	stepName string
}

// location points at the value that caused the finding.
func (s secretSite) location(file *parse.File, job parse.Job) findings.Location {
	loc := findings.At(file.Path, s.line)
	loc.JobID = s.jobID
	if s.step > 0 {
		loc.StepNumber = s.step
		loc.StepName = s.stepName
	}
	return loc
}

// secretSites returns every place a job can carry a value that might name a
// secret.
//
// The same set of places that jobReferencesRealSecret checks, because the two
// questions are about the same references: one asks whether a real secret is
// mentioned, the other asks whether a secret is mentioned in a way that stops
// it being redacted.
//
// The filter looks for the secrets context rather than for a dotted member of
// it, because the whole context is one of the two shapes that leaks. A
// reference to the context is written "secrets", with no dot, and a filter that
// looked for "secrets." would miss exactly the case that hands over
// everything.
func secretSites(job parse.Job) []secretSite {
	var out []secretSite

	add := func(values parse.Values, step int, stepName string) {
		for _, entry := range values {
			if !mentionsSecretsContext(entry.Text) {
				continue
			}
			out = append(out, secretSite{
				text:     entry.Text,
				line:     entry.Line,
				jobID:    job.ID,
				step:     step,
				stepName: stepName,
			})
		}
	}

	add(job.Env, 0, "")
	add(job.With, 0, "")
	for _, step := range job.Steps {
		add(step.Env, step.Number, step.Name)
		add(step.With, step.Number, step.Name)
	}

	return out
}

// mentionsSecretsContext reports whether the text refers to the secrets
// context, either as the whole context or as one of its members.
//
// The context on its own is "secrets" and a member of it is "secrets.NAME", so
// both shapes have to be caught. A word boundary is used on the bare form so
// that an unrelated word ending in secrets does not match.
func mentionsSecretsContext(text string) bool {
	if strings.Contains(text, "secrets.") {
		return true
	}
	from := 0
	for {
		at := strings.Index(text[from:], "secrets")
		if at < 0 {
			return false
		}
		at += from
		before := at == 0 || !isWordByte(text[at-1])
		after := at+len("secrets") >= len(text) || !isWordByte(text[at+len("secrets")])
		if before && after {
			return true
		}
		from = at + len("secrets")
	}
}

// isWordByte reports whether the byte is part of a word.
//
// Only the ASCII word characters count, because that is what a context name
// can be made of and anything else in a workflow expression is punctuation.
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// usesSecretAsStructuredValue reports whether a value reads a secret as
// something other than a whole value.
//
// The two shapes are the whole secrets context and a field taken out of one.
// Both end up in the log as text the runner cannot match:
//
//	toJSON(secrets)
//	fromJSON(secrets.MY_SECRET).password
//
// The check is on the function applied to the secret rather than on the
// presence of a secret, so a workflow that refers to a secret the ordinary way
// is not a finding.
func usesSecretAsStructuredValue(text string) bool {
	for _, fn := range []string{"fromJSON", "fromYaml", "toJSON", "toYaml"} {
		if !strings.Contains(text, fn+"(") {
			continue
		}
		// The function has to be applied to the secret, not to something else
		// in the same expression. toJSON of a non-secret is harmless.
		if secretInsideCall(text, fn) {
			return true
		}
	}
	return false
}

// secretInsideCall reports whether the named function is applied to the
// secrets context.
//
// The call is found by its opening parenthesis and the argument is read to the
// matching close, so a function applied to something else in the same
// expression is not mistaken for one applied to the secret.
func secretInsideCall(text, fn string) bool {
	from := 0
	for {
		at := strings.Index(text[from:], fn+"(")
		if at < 0 {
			return false
		}
		at += from
		open := at + len(fn)

		// Walk to the matching close parenthesis.
		depth := 0
		end := -1
		for i := open; i < len(text); i++ {
			switch text[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			// Unbalanced, which the parser would have rejected. Nothing to say.
			return false
		}

		argument := text[open+1 : end]
		if mentionsSecretsContext(argument) {
			return true
		}
		from = end + 1
	}
}

// rule14Message explains the finding.
//
// The remedy is not obvious from the finding alone, because the natural
// instinct is that a secret in an env block is a secret in an env block. The
// message says what the runner does and does not redact, and what to do
// instead.
func rule14Message(text string) string {
	return "this reads a secret as a structured value, so the runner cannot redact it. The runner hides a " +
		"secret from the log by matching its exact value, and a field taken out of a secret, or the whole " +
		"secrets context, is a different string, so it is printed in full. Anyone who can read this job's log " +
		"can read the secret. Store each field as its own secret and refer to it directly: " +
		"${{ secrets.MY_SECRET_PASSWORD }} rather than a field of a larger one."
}
