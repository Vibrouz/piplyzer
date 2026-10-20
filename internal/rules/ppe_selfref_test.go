package rules

import (
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// A reference to this repository is not a hop.
//
// It is the code in this repository, which the reader is already looking at,
// and a workflow that calls its own reusable workflow is ordinary. Reporting it
// as unreadable third-party code is exactly backwards, and it is the shape
// every repository that adopts an action from its own organisation has in it.
func TestRule10IgnoresAReferenceToThisRepository(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n" +
		"    steps:\n      - uses: our-org/whoa/.github/workflows/inner.yml@main\n"
	file, err := parse.ParseWorkflow(".github/workflows/ci.yml", parse.Repository{Owner: "our-org", Name: "whoa"}, []byte(src))
	if err != nil {
		t.Fatalf("ParseWorkflow: %v", err)
	}

	if got := Rule10(file); len(got) != 0 {
		t.Errorf("got %d findings, want 0: a reference to this repository is not a hop: %+v", len(got), got)
	}
}

// The comparison is on the whole repository and not on the owner alone.
//
// A reference to a different repository in the same organisation is still a
// reference to code this run is not scanning, and the same-org message is the
// right one for it.
func TestRule10StillReportsAnotherRepositoryInTheSameOrganisation(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n" +
		"    steps:\n      - uses: our-org/other-repo/.github/workflows/inner.yml@main\n"
	file, err := parse.ParseWorkflow(".github/workflows/ci.yml", parse.Repository{Owner: "our-org", Name: "whoa"}, []byte(src))
	if err != nil {
		t.Fatalf("ParseWorkflow: %v", err)
	}

	got := Rule10(file)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Message, "your own organisation") {
		t.Errorf("the message does not say it is the same organisation: %s", got[0].Message)
	}
}

// The owner comparison is case insensitive, because a host is.
func TestRule10ThisRepositoryIsCaseInsensitive(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n" +
		"    steps:\n      - uses: Our-Org/Whoa/.github/workflows/inner.yml@main\n"
	file, err := parse.ParseWorkflow(".github/workflows/ci.yml", parse.Repository{Owner: "our-org", Name: "whoa"}, []byte(src))
	if err != nil {
		t.Fatalf("ParseWorkflow: %v", err)
	}

	if got := Rule10(file); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}
}

// Without a known repository the rule cannot tell a reference to this
// repository from one to a third party, so it reports it and says the owner is
// unknown. The message must not claim it is third party.
func TestRule10ThisRepositoryWithoutAKnownRepositoryIsStillReported(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n" +
		"    steps:\n      - uses: our-org/whoa/.github/workflows/inner.yml@main\n"
	file, err := parse.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	got := Rule10(file)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if strings.Contains(got[0].Message, "third-party") {
		t.Errorf("the message claims third party without knowing the owner: %s", got[0].Message)
	}
}

// The finding is still a Warn, not something stronger, because a reference to
// another repository in the same organisation is a matter of reading rather than
// of trusting blind.
func TestRule10ThisRepositoryFindingSeverity(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n" +
		"    steps:\n      - uses: our-org/other-repo/.github/workflows/inner.yml@main\n"
	file, err := parse.ParseWorkflow(".github/workflows/ci.yml", parse.Repository{Owner: "our-org", Name: "whoa"}, []byte(src))
	if err != nil {
		t.Fatalf("ParseWorkflow: %v", err)
	}

	got := Rule10(file)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if got[0].Severity != findings.SeverityWarn {
		t.Errorf("severity = %q, want Warn", got[0].Severity)
	}
}
