package rules

import (
	"fmt"
	"regexp"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

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
