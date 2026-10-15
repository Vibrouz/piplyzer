package parse_test

import (
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/parse"
)

// Actions resolves YAML anchors and aliases as of September 18, 2025, so a
// workflow using them runs. Rejecting them would fail the scan on a valid
// workflow, which is the one kind of false positive a gate cannot afford.
func TestAliasesResolveToTheirContent(t *testing.T) {
	file, data := parseFixture(t, "anchors.yml")

	t.Run("mapping behind an alias", func(t *testing.T) {
		test, ok := file.Job("test")
		if !ok {
			t.Fatal("job test not found")
		}
		if test.Env.Len() != 2 {
			t.Fatalf("env has %d entries, want 2: the alias was not expanded", test.Env.Len())
		}
		if env, ok := test.Env.Get("NODE_ENV"); !ok || env.Text != "production" {
			t.Errorf("env NODE_ENV = %+v, want production", env)
		}
		if env, ok := test.Env.Get("AWS_ACCESS_KEY_ID"); !ok || env.Text != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("env AWS_ACCESS_KEY_ID = %+v, want the credential pattern the rules match on", env)
		}
	})

	t.Run("aliased content keeps the anchor's line", func(t *testing.T) {
		test, _ := file.Job("test")
		env, _ := test.Env.Get("AWS_ACCESS_KEY_ID")
		if want := lineOf(t, data, "AWS_ACCESS_KEY_ID"); env.Line != want {
			t.Errorf("aliased env line = %d, want %d: the text is written on the anchor line", env.Line, want)
		}
	})

	t.Run("block scalar behind an alias", func(t *testing.T) {
		deploy, ok := file.Job("deploy")
		if !ok {
			t.Fatal("job deploy not found")
		}
		if len(deploy.Steps) != 2 {
			t.Fatalf("deploy has %d steps, want 2", len(deploy.Steps))
		}
		for _, step := range deploy.Steps {
			if !strings.Contains(step.Run, "curl https://example.invalid/install.sh | bash") {
				t.Errorf("step %d run = %q: an aliased block scalar has to come through whole, lines joined", step.Number, step.Run)
			}
			idx := strings.Index(step.Run, "curl https")
			if got, want := step.RunLineAt(idx), lineOf(t, data, "curl https"); got != want {
				t.Errorf("step %d RunLineAt = %d, want %d", step.Number, got, want)
			}
		}
	})
}

// A merge key is not merged. Actions does not support `<<:`, so the keys behind
// one never reach the runner, and merging them here would put content in front
// of the rules that the workflow does not actually run.
func TestMergeKeysAreNotMerged(t *testing.T) {
	file, err := parse.Parse([]byte(`env: &base
  SHARED: yes-shared
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      <<: *base
      OWN: yes-own
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	job, ok := file.Job("build")
	if !ok {
		t.Fatal("job build not found")
	}
	if job.Env.Has("SHARED") {
		t.Error("SHARED came through a merge key: Actions does not merge, so the runner never sees it")
	}
	if env, ok := job.Env.Get("OWN"); !ok || env.Text != "yes-own" {
		t.Errorf("env OWN = %+v, want yes-own", env)
	}
	if job.Env.Len() != 1 {
		t.Errorf("env has %d entries, want 1", job.Env.Len())
	}
}

// The YAML reader accepts a cyclic anchor and hands back a tree that never
// bottoms out, so expansion has to be bounded or one workflow hangs the scan.
func TestCyclicAliasIsRejected(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMsg string
	}{
		{
			name:    "mapping referring to itself",
			src:     "env: &loop\n  SELF: *loop\njobs:\n  build:\n    steps: []\n",
			wantMsg: "anchor refers back to itself",
		},
		{
			name:    "sequence referring to itself",
			src:     "steps: &loop\n  - *loop\njobs:\n  build:\n    steps: []\n",
			wantMsg: "anchor refers back to itself",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parse.ParseFile(".github/workflows/ci.yml", []byte(tt.src))
			if err == nil {
				t.Fatalf("ParseFile accepted a cyclic anchor, returning %+v", file)
			}
			if file != nil {
				t.Error("ParseFile returned both a File and an error")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

// An anchor is a way of reusing content, and the reused content has to stay
// reachable through every path a rule walks.
func TestAnchoredJobContentIsStillWalked(t *testing.T) {
	file, _ := parseFixture(t, "anchors.yml")

	release, ok := file.Job("release")
	if !ok {
		t.Fatal("job release not found")
	}
	if len(release.Steps) != 2 {
		t.Fatalf("release has %d steps, want 2", len(release.Steps))
	}
	if !strings.Contains(release.Steps[0].Run, "git log -p") {
		t.Errorf("release step 1 run = %q", release.Steps[0].Run)
	}
}
