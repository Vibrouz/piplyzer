package main

import (
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/parse"
)

// The repository is read from the environment, so a scan in CI knows which
// repository it is looking at.
func TestCurrentRepository(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  parse.Repository
	}{
		{
			name:  "an owner and a name",
			value: "our-org/whoa",
			want:  parse.Repository{Owner: "our-org", Name: "whoa"},
		},
		{
			name:  "not set",
			value: "",
			want:  parse.Repository{},
		},
		{
			name:  "not an owner and a name",
			value: "nonsense",
			want:  parse.Repository{},
		},
		{
			name:  "no owner",
			value: "/whoa",
			want:  parse.Repository{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := func(string) string { return tt.value }
			got := currentRepository(env)
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A scan in CI knows the repository, and a reference to this repository is not
// third-party code.
//
// Without the repository, a workflow that uses this repository's own action is
// reported as code from a stranger, which is exactly backwards.
func TestScanKnowsItsOwnRepository(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".github/workflows/ci.yml": "on:\n  pull_request:\n    branches: [main]\njobs:\n  j:\n" +
			"    runs-on: ubuntu-latest\n    steps:\n" +
			"      - uses: our-org/whoa/.github/workflows/inner.yml@main\n",
	})

	t.Setenv("GITHUB_REPOSITORY", "our-org/whoa")

	stdout, _, _ := scanArgs(t, "", "scan", dir)

	if strings.Contains(stdout, "PPE-010") {
		t.Errorf("a reference to this repository was reported:\n%s", stdout)
	}
}

// A reference to another repository is still reported, whether or not the
// scan knows which repository it is in.
func TestScanStillReportsAnotherRepository(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".github/workflows/ci.yml": "on:\n  pull_request:\n    branches: [main]\njobs:\n  j:\n" +
			"    runs-on: ubuntu-latest\n    steps:\n" +
			"      - uses: other-org/their-action@0123456789abcdef0123456789abcdef01234567\n",
	})

	t.Setenv("GITHUB_REPOSITORY", "our-org/whoa")

	stdout, _, _ := scanArgs(t, "", "scan", dir)

	if !strings.Contains(stdout, "PPE-010") {
		t.Errorf("a reference to another repository was not reported:\n%s", stdout)
	}
}
