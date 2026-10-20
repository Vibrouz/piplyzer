package parse_test

import (
	"testing"

	"github.com/Vibrouz/whoa/internal/parse"
)

// A repository string is an owner and a name.
func TestParseRepository(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		owner string
		repo  string
		ok    bool
	}{
		{name: "owner and name", in: "our-org/whoa", owner: "our-org", repo: "whoa", ok: true},
		{name: "surrounding space", in: "  our-org/whoa  ", owner: "our-org", repo: "whoa", ok: true},
		{name: "no name", in: "our-org/", ok: false},
		{name: "no owner", in: "/whoa", ok: false},
		{name: "no slash", in: "our-org", ok: false},
		{name: "two slashes", in: "our-org/whoa/extra", ok: false},
		{name: "empty", in: "", ok: false},
		{name: "only a slash", in: "/", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parse.ParseRepository(tt.in)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				if !got.IsZero() {
					t.Errorf("a rejected string gave %+v, want the zero value", got)
				}
				return
			}
			if got.Owner != tt.owner || got.Name != tt.repo {
				t.Errorf("got %+v, want owner %q name %q", got, tt.owner, tt.repo)
			}
		})
	}
}

// A repository with an empty owner would make every comparison against an
// owner match, so a rejected string has to give the zero value rather than a
// half-filled one.
func TestParseRepositoryRejectionGivesTheZeroValue(t *testing.T) {
	got, ok := parse.ParseRepository("/whoa")
	if ok {
		t.Fatal("ParseRepository accepted a string with no owner")
	}
	if !got.IsZero() {
		t.Errorf("got %+v, want the zero value", got)
	}
	if got.String() != "" {
		t.Errorf("String = %q, want the empty string", got.String())
	}
}
