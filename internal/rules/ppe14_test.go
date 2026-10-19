package rules

import (
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// ---------------------------------------------------------------- rule 14

// A secret read as a structured value is not redacted from the log.
func TestRule14UnredactedSecrets(t *testing.T) {
	file, data := parseFixture(t, "ppe-014/unredacted.yml")

	assertFindings(t, Rule14(file), []want{
		{Rule14ID, findings.SeverityBlock, lineOf(t, data, "USERNAME:")},
		{Rule14ID, findings.SeverityBlock, lineOf(t, data, "PASSWORD: ${{ fromJSON")},
		{Rule14ID, findings.SeverityBlock, lineOf(t, data, "ALL:")},
	})
}

// A secret referred to as a whole is redacted, and is not a finding.
func TestRule14WholeSecretIsNotAFinding(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n" +
		"    steps:\n      - run: ./deploy.sh\n        env:\n          PASSWORD: ${{ secrets.MY_SECRET }}\n"
	file, err := parse.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := Rule14(file); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}
}

// Every way of reading a secret as something other than a whole value leaks,
// and every way of reading it as a whole value does not.
func TestRule14WhichShapesLeak(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{"a field of a JSON secret", "${{ fromJSON(secrets.MY_SECRET).password }}", true},
		{"a field of a YAML secret", "${{ fromYaml(secrets.MY_SECRET).password }}", true},
		{"the whole context as JSON", "${{ toJSON(secrets) }}", true},
		{"the whole context as YAML", "${{ toYaml(secrets) }}", true},
		{"a whole secret", "${{ secrets.MY_SECRET }}", false},
		{"a whole secret by another name", "${{ secrets.MY_SECRET_PASSWORD }}", false},
		{"a function applied to something else", "${{ toJSON(github.event) }}", false},
		{"a word that ends in secrets", "${{ github.event.secretsauce }}", false},
		{"a word that starts with secrets", "${{ github.event.secretscount }}", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := usesSecretAsStructuredValue(tt.text); got != tt.want {
				t.Errorf("usesSecretAsStructuredValue(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

// The whole secrets context has no dot in it, and a check that looked for a
// dotted member would miss exactly the case that hands over everything.
func TestRule14FindsTheWholeContext(t *testing.T) {
	if !mentionsSecretsContext("${{ toJSON(secrets) }}") {
		t.Error("the whole context was not found")
	}
	if !mentionsSecretsContext("${{ secrets.NAME }}") {
		t.Error("a member of the context was not found")
	}
	for _, text := range []string{
		"${{ github.event.secretsauce }}",
		"${{ github.event.secretscount }}",
		"${{ toJSON(github.event) }}",
	} {
		if mentionsSecretsContext(text) {
			t.Errorf("%q was taken for the secrets context", text)
		}
	}
}

// The finding points at the value that caused it, so the reader does not have
// to search the job for it.
func TestRule14Location(t *testing.T) {
	file, data := parseFixture(t, "ppe-014/unredacted.yml")

	got := Rule14(file)
	if len(got) == 0 {
		t.Fatal("no findings")
	}
	found := got[0]
	if found.Location.JobID != "deploy" {
		t.Errorf("job = %q, want deploy", found.Location.JobID)
	}
	if found.Location.StepNumber != 1 {
		t.Errorf("step = %d, want 1", found.Location.StepNumber)
	}
	if found.Location.Line != lineOf(t, data, "USERNAME:") {
		t.Errorf("line = %d, want %d", found.Location.Line, lineOf(t, data, "USERNAME:"))
	}
}

// The message explains the mechanism, because the finding is otherwise
// surprising: a secret in an env block looks like a secret in an env block.
func TestRule14MessageExplainsTheMechanism(t *testing.T) {
	src := "on:\n  push:\n    branches: [main]\njobs:\n  j:\n    runs-on: ubuntu-latest\n" +
		"    steps:\n      - run: ./deploy.sh\n        env:\n          P: ${{ fromJSON(secrets.S).p }}\n"
	file, err := parse.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	got := Rule14(file)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if !strings.Contains(got[0].Message, "redact") {
		t.Errorf("the message does not explain redaction: %s", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "log") {
		t.Errorf("the message does not say where the value ends up: %s", got[0].Message)
	}
}
