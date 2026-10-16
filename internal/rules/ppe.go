package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// This file holds the PPE rules, in rule number order, which is the order
// plan.md lists them in. One file rather than one per rule: the rules are
// independent by design and a reader looking for one wants to see it next to
// its neighbours, not hunt through a directory of small files. What earns a
// separate file is not "a rule" but "something that is not a pure function over
// one parsed workflow", and none of these are.
//
// Every rule is func(*parse.File) findings.Findings. None of them call each
// other, none of them touch I/O, and none of them keep state.

// ---------------------------------------------------------------- rule 1

// Rule 1: uses: pinned to something mutable instead of a commit SHA.

// Rule1ID is the rule identifier for rule 1.
const Rule1ID = "PPE-001"

const (
	lockfilesDocURL = "https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles"
	tjActionsCVEURL = "https://nvd.nist.gov/vuln/detail/cve-2025-30066"
)

var (
	// commitSHA is a full git object name, which is what pinning means.
	commitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	// abbreviatedSHA is enough to resolve today and can be extended to a
	// different commit tomorrow, so it is not a pin.
	abbreviatedSHA = regexp.MustCompile(`^[0-9a-fA-F]{7,39}$`)
	// versionTag is v4, v4.1.2, 4.1.2, 1.0.0-rc1.
	versionTag = regexp.MustCompile(`^v?\d+(\.\d+)*(-[0-9A-Za-z.-]+)?$`)
)

// Rule1 reports uses: references pinned to something mutable rather than to a
// commit SHA.
//
// Block. Most repositories still pin by tag, so this fires on a large share of
// real workflows, and the temptation is to demote it. The reason not to: the
// reference is the only thing standing between an approved change and
// attacker-controlled code at run time, which is the entire job of this gate. A
// tag that moves is indistinguishable, at run time, from a tag the maintainer
// approved.
func Rule1(file *parse.File) findings.Findings {
	var out findings.Findings
	for _, site := range allUses(file) {
		if !rule1Applies(site.ref) {
			continue
		}
		repo, _, ref := site.ref.Parts()
		out = append(out, findings.New(Rule1ID, findings.SeverityBlock, rule1Message(site.ref, repo, ref), site.location(file)))
	}
	return out
}

// rule1Applies decides whether a reference is this rule's business, and the
// test is whether there is a ref that could move.
//
// A reference with no ref is not this rule's problem: it is a workflow that does
// not run, which is a different thing from one that runs unreviewed code. That
// single case is also what excludes the two shapes that have no remote ref to
// pin, since parse reports no ref for either. A local action cannot be
// repointed without changing this repository, and a container reference is a
// different supply chain with different controls, so flagging docker:// would
// fire on a very common pattern for a risk this rule does not cover.
func rule1Applies(uses parse.UsesRef) bool {
	_, _, ref := uses.Parts()
	return ref != "" && !commitSHA.MatchString(ref)
}

// rule1Message leads with workflow dependency lockfiles, because GitHub
// documents them as the strongest control here and as superseding SHA pinning.
// SHA pinning is the fallback for a repository that cannot adopt one, and
// saying it the other way round would be recommending the weaker control.
func rule1Message(uses parse.UsesRef, repo, ref string) string {
	return fmt.Sprintf(
		"%s is pinned to %s. A tag or a branch can be repointed at different code after this change is "+
			"approved, so what runs is not necessarily what was reviewed. GitHub documents workflow "+
			"dependency lockfiles as the strongest control here, and as superseding SHA pinning: a lockfile "+
			"records the exact commit for every action a workflow uses and verifies it at run time (%s). "+
			"Without one, pinning %s to a full 40 character commit SHA is the documented fallback. This is "+
			"what tj-actions/changed-files did in practice: CVE-2025-30066 affected more than 23,000 "+
			"repositories (%s).",
		uses.Target, refKind(ref), lockfilesDocURL, repo, tjActionsCVEURL,
	)
}

// refKind names what sort of mutable reference this is, so the finding says
// what to change rather than only that something is wrong.
func refKind(ref string) string {
	switch {
	case abbreviatedSHA.MatchString(ref):
		return "an abbreviated commit SHA, which can be extended into a different commit"
	case versionTag.MatchString(ref):
		return "a version tag, which can be moved to point at new code"
	default:
		return "a branch or other mutable reference"
	}
}

// ---------------------------------------------------------------- rule 2

// Rule 2: untrusted context interpolated into a run: block.

// Rule2ID is the rule identifier for rule 2.
const Rule2ID = "PPE-002"

// untrustedSuffixes is GitHub's published list of context properties an attacker
// can put content into, verified verbatim against the script injection docs.
//
// Matching the suffix shape rather than enumerating full paths is deliberate: an
// enumeration misses fields, and GitHub adds more events over time. The set is a
// suffix set, not a path set, because `body` is untrusted whether it is reached
// as github.event.issue.body or github.event.pull_request.body, and a rule that
// knew only one of those would miss the other.
var untrustedSuffixes = map[string]bool{
	"body":           true,
	"default_branch": true,
	"email":          true,
	"head_ref":       true,
	"label":          true,
	"message":        true,
	"name":           true,
	"page_name":      true,
	"ref":            true,
	"title":          true,
}

// blockTierSuffixes are the suffixes a fork pull request can reach with no
// privileges at all, which is what makes them Block.
var blockTierSuffixes = map[string]bool{
	"title":   true,
	"body":    true,
	"message": true,
	"email":   true,
}

// heldAtWarnSuffixes are Block tier in plan.md but ship as Warn until P2
// measures their false positive rate against real repositories.
//
// `name` belongs in this tier. It is the widest of the ten suffixes, and
// blocking on an unmeasured suffix is the one way this rule could cost us the
// gate. It is named explicitly here rather than left to the Warn fallback, so
// that deleting the entry visibly promotes it to Block and the change is caught
// rather than silent. decisions.md section 22 records it and how to reverse it.
var heldAtWarnSuffixes = map[string]bool{
	"name": true,
}

// writeGatedContexts end in a Block tier suffix but cannot be reached by a fork
// pull request, because creating a release, a milestone or a project already
// requires write access. Reporting them as Block would be a false positive on
// every repository that publishes releases. decisions.md section 22.
var writeGatedContexts = map[string]bool{
	"github.event.release.name":               true,
	"github.event.milestone.title":            true,
	"github.event.project.name":               true,
	"github.event.workflow_run.display_title": true,
}

// githubContext matches a reference to the github context inside an expression,
// capturing the dotted path that follows it.
//
// The path handles both shapes GitHub uses: github.head_ref, where the property
// follows the context directly, and github.event.issue.title, where several
// segments come first. plan.md writes this as
// `github\.(event\.)?\w+[.\w]*\.(suffix)`, which requires a dot before the
// suffix and so never matches github.head_ref or github.ref, the most common
// ref-suffix references there are. The path is captured and its final segment
// compared instead. The [n] alternation is for list contexts such as
// github.event.commits[0].message and github.event.pages[0].page_name.
// decisions.md section 22 records the regex bug.
var githubContext = regexp.MustCompile(`github((?:\.[A-Za-z0-9_-]+|\[[0-9]+\])+)`)

// Rule2 reports untrusted context interpolated into a run: block.
//
// GitHub substitutes expressions into the script before the shell sees it, so a
// pull request title containing a quote and a semicolon becomes commands rather
// than text. A fork pull request is enough to try it, which is why the freetext
// suffixes block.
//
// Rule 2 reads run: blocks only, on purpose. A value in a step with: or in an
// env: block is not shell text, and GitHub documents passing it through an
// environment variable as the mitigation for this attack. Scanning env: would
// flag the recommended fix.
func Rule2(file *parse.File) findings.Findings {
	var out findings.Findings
	for _, site := range allRunScripts(file) {
		for _, ref := range untrustedReferences(site.script) {
			// The location is the line the match is on, not the line the run:
			// key is on. In a block scalar those differ by however deep into
			// the script the match sits, and a finding that always points at
			// the top of the script is not actionable.
			loc := site.location(file)
			loc.Line = site.lineAt(ref.offset)
			out = append(out, findings.New(Rule2ID, ref.severity, rule2Message(ref), loc))
		}
	}
	return out
}

// untrustedReference is one untrusted context reference found in a script.
type untrustedReference struct {
	// expression is the full text as written, for the message.
	expression string
	// suffix is the final path segment, which is what the tier is decided by.
	suffix string
	// severity is resolved from the context and the suffix.
	severity findings.Severity
	// offset is where the expression starts in the script, so the finding can
	// be placed on the line the match is actually on.
	offset int
}

// untrustedReferences finds every untrusted context reference in a script.
//
// The suffix has to be the whole final segment. That is what keeps
// github.event.pull_request.number from matching, and what keeps a path ending
// in full_name from matching on `name`, so the segment is compared rather than
// substring searched.
func untrustedReferences(script string) []untrustedReference {
	var out []untrustedReference
	for _, loc := range githubContext.FindAllStringSubmatchIndex(script, -1) {
		path := script[loc[2]:loc[3]]
		suffix := path[strings.LastIndex(path, ".")+1:]
		if !untrustedSuffixes[suffix] {
			continue
		}
		expression := script[loc[0]:loc[1]]
		out = append(out, untrustedReference{
			expression: expression,
			suffix:     suffix,
			severity:   rule2Severity(expression, suffix),
			offset:     loc[0],
		})
	}
	return out
}

// rule2Severity decides the tier for one reference.
//
// The split is privilege, not safety. Both tiers are injectable; the difference
// is who can reach the input. A pull request title needs nothing but the ability
// to open a fork pull request. A ref needs push access to create the branch,
// which is a higher bar but not a safe one, since GitHub documents branch names
// as an injection vector in their own right.
func rule2Severity(expression, suffix string) findings.Severity {
	// Write gated first: it can demote a suffix that would otherwise block.
	if writeGatedContexts[expression] {
		return findings.SeverityWarn
	}
	if heldAtWarnSuffixes[suffix] {
		return findings.SeverityWarn
	}
	if blockTierSuffixes[suffix] {
		return findings.SeverityBlock
	}
	return findings.SeverityWarn
}

func rule2Message(ref untrustedReference) string {
	why := "Anyone who can open a pull request on this repository controls this value, so the script below runs as them."
	if ref.severity != findings.SeverityBlock {
		why = "Creating the input for this needs push access, which is a higher bar than a fork pull request but is not " +
			"safe: branch names and similar values can contain quotes and shell metacharacters."
	}
	return fmt.Sprintf(
		"%s is untrusted input interpolated into a shell script. GitHub substitutes expressions into the script "+
			"before the shell runs it, so a value containing a quote and a semicolon becomes commands rather than "+
			"text. %s Pass the value through an environment variable instead: set it under env: and use the "+
			"variable with quotes in the script, which keeps it out of the generated script.",
		ref.expression, why,
	)
}

// ---------------------------------------------------------------- rule 7

// Rule 7: on: push with no ref or path filter.

// Rule7ID is the rule identifier for rule 7.
const Rule7ID = "PPE-007"

// Rule7 reports a workflow that runs on every push to any branch.
//
// Warn, because an unfiltered push is extremely common and legitimate: many
// repositories deliberately build every branch. Blocking it would be noise, and
// a noisy gate gets disabled, which costs us the rules that matter.
//
// It is one of the five components of the GhostAction fingerprint composite
// (rules 4 through 8). It cannot trigger that composite on its own, because it
// fires on far too many real workflows to mean anything by itself.
func Rule7(file *parse.File) findings.Findings {
	push, ok := file.Triggers.Spec("push")
	if !ok || !push.Unfiltered() {
		return nil
	}
	return findings.Findings{
		findings.New(Rule7ID, findings.SeverityWarn, rule7Message(), findings.At(file.Path, push.Line)),
	}
}

func rule7Message() string {
	// No incident figure is quoted here on purpose. plan.md still has the
	// GhostAction counts marked vendor-sourced pending confirmation, and
	// decisions.md requires a source for any figure that reaches a user. The
	// mechanism is what matters here and it is not in doubt: a stolen maintainer
	// token pushes to the default branch and the workflow runs.
	return "on: push has no branches, tags or paths filter, so this workflow runs for every commit that " +
		"lands on any branch in the repository. That is the entry point for a compromised maintainer " +
		"account: the attacker pushes a malicious workflow straight to the default branch, there is no " +
		"pull request and no review, and it runs with the repository's secrets. Restrict it to the " +
		"branches you build from, and put anything that should be deliberate behind workflow_dispatch."
}

// ---------------------------------------------------------------- rule 8

// Rule 8: workflow_dispatch on a job that can reach credentials.

// Rule8ID is the rule identifier for rule 8.
const Rule8ID = "PPE-008"

// Rule8 reports a dormant privileged job: a workflow that someone can trigger
// by hand, running a job that holds secrets.
//
// Warn, not Block. A workflow_dispatch trigger on a privileged job is a
// reasonable thing for a maintainer to want, and it is what deploy buttons are
// built out of. It is a risk worth naming, not a mistake.
//
// It is also one of the five components of the GhostAction composite, and like
// rule 7 it cannot trigger that composite alone.
func Rule8(file *parse.File) findings.Findings {
	if !file.Triggers.Has("workflow_dispatch") {
		return nil
	}

	var out findings.Findings
	for _, job := range file.Jobs {
		sensitive, why := sensitiveJob(file, job)
		if !sensitive {
			continue
		}
		out = append(out, findings.New(Rule8ID, findings.SeverityWarn, rule8Message(why), jobLocation(file, job)))
	}
	return out
}

func rule8Message(why string) string {
	return "workflow_dispatch lets someone with write access run this workflow on demand, and " + why +
		". That is a dormant privileged job: nothing in the workflow looks wrong until it is triggered, " +
		"and then it runs with credentials it should not be reachable with. A stolen maintainer token can " +
		"use it to run code in a job that is allowed to deploy or publish, with no pull request to review. " +
		"Keep workflow_dispatch on the jobs that need it, and put anything privileged behind an " +
		"environment with required reviewers."
}
