package parse_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/parse"
)

// A workflow that does not parse has to be a scan failure, not a clean result.
// A scanner that skips the files it cannot read is one an attacker can hide
// behind by making a file unreadable, so every case here has to return an error
// rather than a half populated File.
func TestParseFailures(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMsg string
	}{
		{
			name:    "empty file",
			src:     "",
			wantMsg: "no YAML document",
		},
		{
			name:    "comments only",
			src:     "# nothing here\n",
			wantMsg: "no YAML document",
		},
		{
			name:    "root is a list",
			src:     "- on: push\n",
			wantMsg: "must be a mapping",
		},
		{
			name:    "root is a scalar",
			src:     "just a string\n",
			wantMsg: "must be a mapping",
		},
		{
			name:    "second document is ignored by a naive decode",
			src:     "---\non: push\n---\non: pull_request\n",
			wantMsg: "multiple YAML documents",
		},
		{
			name:    "duplicate key, the reader that disagrees about which wins is the gate",
			src:     "on: push\non: pull_request\njobs:\n  build:\n    steps: []\n",
			wantMsg: `duplicate key "on"`,
		},
		{
			name:    "duplicate job key",
			src:     "jobs:\n  build:\n    steps: []\n  build:\n    steps: []\n",
			wantMsg: `duplicate key "build"`,
		},
		{
			name:    "tab indentation",
			src:     "jobs:\n\tbuild:\n\t\tsteps: []\n",
			wantMsg: "",
		},
		{
			name:    "anchor referring back to itself",
			src:     "steps: &loop\n  - *loop\njobs:\n  build:\n    steps: []\n",
			wantMsg: "anchor refers back to itself",
		},
		{
			name:    "job is a list",
			src:     "jobs:\n  build:\n    - run: echo hi\n",
			wantMsg: "must be a mapping",
		},
		{
			name:    "steps is a mapping",
			src:     "jobs:\n  build:\n    steps:\n      first:\n        run: echo hi\n",
			wantMsg: "steps must be a list",
		},
		{
			name:    "step is empty",
			src:     "jobs:\n  build:\n    steps:\n      -\n",
			wantMsg: "is empty",
		},
		{
			name:    "step is a scalar",
			src:     "jobs:\n  build:\n    steps:\n      - echo hi\n",
			wantMsg: "must be a mapping",
		},
		{
			name:    "permissions is a number",
			src:     "permissions: 4\njobs:\n  build:\n    steps: []\n",
			wantMsg: "permissions must be a mapping",
		},
		{
			name:    "permissions is an unknown keyword",
			src:     "permissions: everything\njobs:\n  build:\n    steps: []\n",
			wantMsg: "permissions must be a mapping",
		},
		{
			name:    "with: value is a mapping",
			src:     "jobs:\n  build:\n    steps:\n      - uses: a/b@v1\n        with:\n          nested:\n            a: b\n",
			wantMsg: "must be a single value",
		},
		{
			name:    "uses is a list",
			src:     "jobs:\n  build:\n    steps:\n      - uses:\n          - a/b@v1\n",
			wantMsg: "uses must be a single value",
		},
		{
			name:    "uses is empty",
			src:     "jobs:\n  build:\n    steps:\n      - uses: ''\n",
			wantMsg: "uses is empty",
		},
		{
			name:    "branches is a mapping",
			src:     "on:\n  push:\n    branches:\n      main: true\n",
			wantMsg: "must be a value or a list",
		},
		{
			name:    "unterminated quote",
			src:     "name: \"ci\n",
			wantMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parse.ParseFile(".github/workflows/ci.yml", []byte(tt.src))
			if err == nil {
				t.Fatalf("ParseFile succeeded on an unparseable workflow, returning %+v: a file that cannot be read must fail the scan rather than count as clean", file)
			}
			if file != nil {
				t.Error("ParseFile returned both a File and an error: a partially parsed workflow would let a rule skip what it could not read")
			}

			var perr *parse.Error
			if !errors.As(err, &perr) {
				t.Fatalf("error type = %T, want *parse.Error", err)
			}
			if perr.Path != ".github/workflows/ci.yml" {
				t.Errorf("error path = %q, want the file the caller passed in", perr.Path)
			}
			if !strings.Contains(perr.Msg, tt.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", perr.Msg, tt.wantMsg)
			}
			if !strings.Contains(err.Error(), ".github/workflows/ci.yml") {
				t.Errorf("error string %q does not name the file", err.Error())
			}
		})
	}
}

func TestParseErrorCarriesLine(t *testing.T) {
	_, err := parse.ParseFile("ci.yml", []byte("on: push\n\njobs:\n  build:\n    steps:\n      - echo hi\n"))

	var perr *parse.Error
	if !errors.As(err, &perr) {
		t.Fatalf("error type = %T, want *parse.Error", err)
	}
	if perr.Line != 6 {
		t.Errorf("error line = %d, want 6: a parse failure has to point at the line a maintainer has to fix", perr.Line)
	}
	if got := err.Error(); got != "ci.yml:6: step 1 of job build must be a mapping, got a single value" {
		t.Errorf("error = %q", got)
	}
}

func TestParseErrorWithoutPath(t *testing.T) {
	_, err := parse.Parse([]byte("- not a workflow\n"))
	var perr *parse.Error
	if !errors.As(err, &perr) {
		t.Fatalf("error type = %T, want *parse.Error", err)
	}
	if got := err.Error(); !strings.Contains(got, "workflow:") {
		t.Errorf("error = %q, want it to name the location even with no path", got)
	}
}
