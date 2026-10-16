package rules

import (
	"testing"

	"github.com/Vibrouz/whoa/internal/parse"
)

// refKind decides what the finding says to change, so it is tested directly
// rather than only through a message that happens to contain it.
func TestRefKind(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		{"v4", "a version tag, which can be moved to point at new code"},
		{"v4.1.2", "a version tag, which can be moved to point at new code"},
		{"4.1.2", "a version tag, which can be moved to point at new code"},
		{"1.0.0-rc1", "a version tag, which can be moved to point at new code"},
		{"main", "a branch or other mutable reference"},
		{"master", "a branch or other mutable reference"},
		{"release/v1", "a branch or other mutable reference"},
		{"5f3b1c0", "an abbreviated commit SHA, which can be extended into a different commit"},
		{"a1b2c3d4e5f6", "an abbreviated commit SHA, which can be extended into a different commit"},
		{"deadbeef", "an abbreviated commit SHA, which can be extended into a different commit"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			if got := refKind(tt.ref); got != tt.want {
				t.Errorf("refKind(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestCommitSHA(t *testing.T) {
	tests := []struct {
		ref     string
		pinned  bool
		comment string
	}{
		{"1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", true, "40 hex characters"},
		{"5f3b1c0d4e8a9b2c7d6e5f4a3b2c1d0e9f8a7b6c", true, "40 hex characters"},
		{"1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D", true, "uppercase hex is still 40 characters, and GitHub does not emit it but it is not a real ambiguity"},
		{"a1b2c3d4e5f6", false, "12 characters"},
		{"5f3b1c0", false, "7 characters"},
		{"1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4", false, "39 characters"},
		{"1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4dd", false, "41 characters"},
		{"z1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", false, "not hex"},
		{"sha256:0123456789abcdef0123456789abcdef", false, "a digest, not a git object name"},
		{"v4", false, "a version tag"},
		{"main", false, "a branch"},
	}

	for _, tt := range tests {
		t.Run(tt.comment, func(t *testing.T) {
			if got := commitSHA.MatchString(tt.ref); got != tt.pinned {
				t.Errorf("commitSHA.MatchString(%q) = %v, want %v", tt.ref, got, tt.pinned)
			}
		})
	}
}

// The three exclusions in rule 1 are decisions. Each one is a way a naive
// implementation over-fires or under-fires.
func TestRule1Exclusions(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		flagged bool
		reason  string
	}{
		{"local action", "./.github/actions/build", false, "cannot be repointed without changing this repository"},
		{"local action, parent", "../shared/action", false, "same"},
		{"local action written with a ref", "./.github/actions/build@v4", false, "no ref is reported for a local action, so nothing to repoint"},
		{"container action", "docker://alpine:3.19", false, "different supply chain with different controls"},
		{"container action, digest", "docker://alpine@sha256:abc", false, "same"},
		{"no ref at all", "actions/checkout", false, "a workflow that does not run, not one that runs unreviewed code"},
		{"full sha", "actions/checkout@1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", false, "pinned"},
		{"full sha in a subdirectory", "actions/aws/ec2@1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", false, "pinned, and subdirectory is part of the path not the ref"},
		{"version tag", "actions/checkout@v4", true, "the shape most repositories have"},
		{"branch", "actions/setup-node@main", true, "a branch"},
		{"branch with a slash", "actions/setup-node@release/v1", true, "the ref, not the subpath"},
		{"sha as a tag", "actions/checkout@5f3b1c0", true, "abbreviated, so not a pin"},
		{"digest prefix", "actions/checkout@sha256:0123456789abcdef", true, "not a 40 character git object name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parse.Parse([]byte("uses: " + tt.target + "\n"))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := len(Rule1(file)) > 0
			if got != tt.flagged {
				t.Errorf("flagged = %v, want %v (%s)", got, tt.flagged, tt.reason)
			}
		})
	}
}
