package rules

import (
	"strings"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// ---------------------------------------------------------------- rule 13

// Rule 13: secrets handed to a workflow in another repository.

// Rule13ID is the rule identifier for rule 13.
const Rule13ID = "PPE-013"

// Rule13 reports a reusable workflow call that hands over every secret.
//
// A job that calls a reusable workflow can pass secrets to it two ways. The
// explicit form names each one:
//
//	secrets:
//	  DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
//
// The inherit form passes all of them:
//
//	secrets: inherit
//
// The difference is the whole of the security question. The explicit form says
// what leaves the repository and the reader can check that the callee needs
// it. The inherit form says "everything", and what everything is depends on
// the repository's secret store, which is not in the file and can change
// without the workflow changing at all.
//
// This is Block rather than Warn, and the difference from the other rules that
// mention secrets is that this one is not about a credential being exposed to
// code that might misuse it. It is about a credential being handed to a
// repository this tool cannot read, which is the one case where the reader
// cannot check the answer themselves. A Warn is something a reader can look at
// and decide; here there is nothing to look at, because the receiving
// repository is a different repository.
//
// A call to a workflow in this repository is not a finding. It is the same
// code, it is readable, and inherit is a reasonable way to pass secrets
// between two workflows one team owns.
func Rule13(file *parse.File) findings.Findings {
	var out findings.Findings

	for _, job := range file.Jobs {
		// Only a reusable workflow call can take a secrets: block. A job with
		// steps cannot, and a job with a uses: has no steps.
		if job.Uses == nil || !job.Secrets.Inherit {
			continue
		}

		repo, _, _ := job.Uses.Parts()
		// A local reference is a workflow in this repository, which is the code
		// the reader can already see.
		if repo == "" {
			continue
		}
		// A container is not a repository reference at all.
		if strings.HasPrefix(repo, "docker://") {
			continue
		}

		out = append(out, findings.New(
			Rule13ID,
			findings.SeverityBlock,
			rule13Message(repo),
			jobLocation(file, job),
		))
	}

	return out
}

// rule13Message explains the finding.
//
// The remedy is named because the finding is otherwise just an observation,
// and an observation about a secret leaving the repository is one a reader can
// dismiss. The fix is a one line change to a secrets block.
func rule13Message(repo string) string {
	return "secrets: inherit hands every secret in this repository to " + repo + ", which is a different " +
		"repository and code this tool cannot read. The explicit form says what leaves and can be checked " +
		"against what the called workflow uses: replace secrets: inherit with a secrets: block naming each " +
		"secret the workflow actually needs."
}
