package rules

import (
	"fmt"
	"regexp"

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
