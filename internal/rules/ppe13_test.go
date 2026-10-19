package rules

import (
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// ---------------------------------------------------------------- rule 13

// A reusable workflow call that hands over every secret.
//
// The explicit form names what leaves and can be checked. The inherit form
// says everything, and what everything is depends on the secret store, which
// is not in the file.
func TestRule13SecretsInherit(t *testing.T) {
	file, data := parseFixture(t, "ppe-013/secrets_inherit.yml")

	assertFindings(t, Rule13(file), []want{
		{Rule13ID, findings.SeverityBlock, lineOf(t, data, "  third-party:")},
		{Rule13ID, findings.SeverityBlock, lineOf(t, data, "  same-org:")},
	})
}

// A workflow in this repository is not a finding.
//
// It is the same code, it is readable, and inherit is a reasonable way to pass
// secrets between two workflows one team owns.
func TestRule13LocalCallIsNotAFinding(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n" +
		"    uses: ./.github/workflows/inner.yml\n    secrets: inherit\n"
	file, err := parse.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := Rule13(file); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}
}

// The explicit form names what leaves, and that is the shape the finding asks
// for. It is not a finding.
func TestRule13ExplicitSecretsAreNotAFinding(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n" +
		"    uses: some-org/their-workflow/.github/workflows/build.yml@main\n" +
		"    secrets:\n      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n"
	file, err := parse.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := Rule13(file); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}
}

// A job with no uses: cannot take a secrets: block at all, and a job with a
// secrets: block but no inherit is the explicit form.
func TestRule13OnlyInheritCounts(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "a job with steps and a secrets block",
			src: "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n" +
				"    secrets:\n      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n" +
				"    steps:\n      - run: echo hi\n",
			want: 0,
		},
		{
			name: "a call with no secrets block",
			src: "on:\n  push:\n    branches: [main]\njobs:\n  j:\n" +
				"    uses: some-org/their-workflow/.github/workflows/build.yml@main\n",
			want: 0,
		},
		{
			name: "a call with inherit",
			src: "on:\n  push:\n    branches: [main]\njobs:\n  j:\n" +
				"    uses: some-org/their-workflow/.github/workflows/build.yml@main\n    secrets: inherit\n",
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parse.Parse([]byte(tt.src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := len(Rule13(file)); got != tt.want {
				t.Errorf("got %d findings, want %d", got, tt.want)
			}
		})
	}
}

// A container is not a repository reference at all, so it cannot be the other
// side of a secrets: inherit.
func TestRule13ContainerIsNotAFinding(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n" +
		"    uses: docker://alpine:3.20\n    secrets: inherit\n"
	file, err := parse.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := Rule13(file); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}
}

// An unbalanced parenthesis cannot be parsed, so the guard is unreachable from
// a parsed workflow. It is here because the search walks a string by finding
// matching brackets, and a string that does not balance would otherwise read
// past the end of the value.
func TestRule14UnbalancedCallIsNotAFinding(t *testing.T) {
	for _, text := range []string{
		"${{ fromJSON(secrets.MY_SECRET",
		"${{ toJSON(secrets",
	} {
		if usesSecretAsStructuredValue(text) {
			t.Errorf("usesSecretAsStructuredValue(%q) = true, want false", text)
		}
	}
}

// The message names the repository the secrets are going to and says what to
// do about it, because a finding that does not say what to do is an
// observation rather than a result.
func TestRule13MessageNamesTheRepository(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n" +
		"    uses: some-org/their-workflow/.github/workflows/build.yml@main\n    secrets: inherit\n"
	file, err := parse.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	got := Rule13(file)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if !strings.Contains(got[0].Message, "some-org/their-workflow") {
		t.Errorf("the message does not name the repository: %s", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "secrets: block") {
		t.Errorf("the message does not say what to do: %s", got[0].Message)
	}
}
