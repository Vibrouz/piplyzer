package deps_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/deps"
	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/lockfile"
)

// lockFixture reads and parses a lockfile fixture.
func lockFixture(t *testing.T, name string) *lockfile.Lockfile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "lockfile", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	lock, err := lockfile.Parse(data)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return lock
}

// The diff between two lockfiles, over the fixture pair.
//
// The pair has one of every case:
//
//	existing               unchanged, silent
//	upgraded               a version bump, silent
//	gained-a-script        gained an install script, a D2
//	always-had-a-script    had one before and has one now, silent
//	brand-new              new, a D1
//	brand-new-with-a-script new and runs a script, a D1D2
func TestDiffOverTheFixture(t *testing.T) {
	base := lockFixture(t, "diff-base.json")
	head := lockFixture(t, "diff-head.json")

	got := deps.Diff(base, head, "package-lock.json")

	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(got), got)
	}

	// The one that runs an install script comes first, because it is the one
	// that executes code at install time.
	byID := map[string]findings.Finding{}
	for _, f := range got {
		byID[f.RuleID] = f
	}

	d1d2, ok := byID[deps.D1D2ID]
	if !ok {
		t.Fatalf("there is no %s finding: %+v", deps.D1D2ID, got)
	}
	if d1d2.Severity != findings.SeverityBlock {
		t.Errorf("the %s severity = %q, want Block", deps.D1D2ID, d1d2.Severity)
	}
	if !strings.Contains(d1d2.Message, "brand-new-with-a-script") {
		t.Errorf("the %s finding names the wrong package: %s", deps.D1D2ID, d1d2.Message)
	}

	d1, ok := byID[deps.D1ID]
	if !ok {
		t.Fatalf("there is no %s finding: %+v", deps.D1ID, got)
	}
	if d1.Severity != findings.SeverityWarn {
		t.Errorf("the %s severity = %q, want Warn", deps.D1ID, d1.Severity)
	}
	if !strings.Contains(d1.Message, "brand-new") {
		t.Errorf("the %s finding names the wrong package: %s", deps.D1ID, d1.Message)
	}

	d2, ok := byID[deps.D2ID]
	if !ok {
		t.Fatalf("there is no %s finding: %+v", deps.D2ID, got)
	}
	if d2.Severity != findings.SeverityBlock {
		t.Errorf("the %s severity = %q, want Block", deps.D2ID, d2.Severity)
	}
	if !strings.Contains(d2.Message, "gained-a-script") {
		t.Errorf("the %s finding names the wrong package: %s", deps.D2ID, d2.Message)
	}
}

// A version bump is not a new package.
//
// This is the case that decides whether the check is usable. A dependency
// update is the most ordinary thing in a lockfile, and if a version bump read
// as a new package then every dependency bump in every pull request would be a
// finding, and the check would be switched off.
func TestDiffAVersionBumpIsNotANewPackage(t *testing.T) {
	base := lockFixture(t, "diff-base.json")
	head := lockFixture(t, "diff-head.json")

	for _, f := range deps.Diff(base, head, "package-lock.json") {
		if strings.Contains(f.Message, "upgraded") {
			t.Errorf("a version bump was reported: %s", f.Message)
		}
	}
}

// A package that already had an install script did not gain one.
//
// A package that always had a script is a known quantity. It was in the base
// lockfile, and anyone who looked at the dependency saw it.
func TestDiffAPackageThatAlwaysHadAScriptIsSilent(t *testing.T) {
	base := lockFixture(t, "diff-base.json")
	head := lockFixture(t, "diff-head.json")

	for _, f := range deps.Diff(base, head, "package-lock.json") {
		if strings.Contains(f.Message, "always-had-a-script") {
			t.Errorf("a package that already had a script was reported: %s", f.Message)
		}
	}
}

// A package that was already there and is unchanged is silent.
func TestDiffAnUnchangedPackageIsSilent(t *testing.T) {
	base := lockFixture(t, "diff-base.json")
	head := lockFixture(t, "diff-head.json")

	for _, f := range deps.Diff(base, head, "package-lock.json") {
		if strings.Contains(f.Message, "existing") {
			t.Errorf("an unchanged package was reported: %s", f.Message)
		}
	}
}

// A new package that also runs an install script is one finding, not two.
//
// It reports under its own identifier so that filtering by D1 does not miss
// the case worth looking at, and so that one package does not produce two
// findings for one condition.
func TestDiffANewPackageWithAScriptIsOneFinding(t *testing.T) {
	base := lockFixture(t, "diff-base.json")
	head := lockFixture(t, "diff-head.json")

	count := 0
	for _, f := range deps.Diff(base, head, "package-lock.json") {
		if strings.Contains(f.Message, "brand-new-with-a-script") {
			count++
			if f.RuleID != deps.D1D2ID {
				t.Errorf("the rule ID is %q, want %q", f.RuleID, deps.D1D2ID)
			}
			// The message says it supersedes both, so a reader who expects a
			// D1 and a D2 for it does not go looking for them.
			if !strings.Contains(f.Message, "rather than two") {
				t.Errorf("the message does not say it supersedes both: %s", f.Message)
			}
		}
	}
	if count != 1 {
		t.Errorf("got %d findings for the package, want 1", count)
	}
}

// With no base lockfile there is nothing to compare against, and every package
// would read as new.
//
// A pull request that adds a lockfile has this, and reporting every package in
// it would be noise rather than signal.
func TestDiffWithNoBaseIsNothing(t *testing.T) {
	head := lockFixture(t, "diff-head.json")

	if got := deps.Diff(nil, head, "package-lock.json"); len(got) != 0 {
		t.Errorf("got %d findings with no base, want 0: %+v", len(got), got)
	}
}

// A version 1 base cannot say whether a package had an install script, so it
// cannot say whether one appeared.
//
// The field does not exist before npm 7, and reading the absent field as false
// would be a silent false negative on the check that blocks install-time
// malware.
//
// The base here holds the same packages as the head, so the two lockfiles are
// comparable and the only reason there is no D2 is the version floor. A base
// with no packages in common would pass this test without testing anything.
func TestDiffV1BaseSkipsD2(t *testing.T) {
	base := lockFixture(t, "diff-base-v1.json")
	head := lockFixture(t, "diff-head.json")

	// The base and the head do share packages, so a D2 would be reported if
	// the version floor were not there.
	baseNames := map[string]bool{}
	for _, p := range base.Packages {
		baseNames[p.Path] = true
	}
	shared := false
	for _, p := range head.Packages {
		if baseNames[p.Path] {
			shared = true
		}
	}
	if !shared {
		t.Fatal("the base and the head share no packages, so the test proves nothing")
	}

	for _, f := range deps.Diff(base, head, "package-lock.json") {
		if f.RuleID == deps.D2ID {
			t.Errorf("a D2 was reported against a version 1 base: %s", f.Message)
		}
	}
}

// A version 1 base still reports a new package.
//
// The version floor is about D2 only. A package that is not in the base is new
// whatever the base's version is, and the base cannot say whether it had a
// script because there is no base version of it at all.
func TestDiffV1BaseStillReportsANewPackage(t *testing.T) {
	base := lockFixture(t, "diff-base-v1.json")
	head := lockFixture(t, "diff-head.json")

	found := false
	for _, f := range deps.Diff(base, head, "package-lock.json") {
		if f.RuleID == deps.D1ID || f.RuleID == deps.D1D2ID {
			found = true
		}
	}
	if !found {
		t.Error("no new package was reported against a version 1 base")
	}
}

// A version 2 base can say, so D2 fires.
//
// This is the other half of the version floor: it is not that D2 never works,
// it is that it works once the lockfile is new enough to record the field.
func TestDiffV2BaseReportsD2(t *testing.T) {
	base := lockFixture(t, "npm-v2.json")
	head := lockFixture(t, "diff-head.json")

	// The real version 2 fixture has lodash, which is not in the head fixture,
	// so the head's new packages are all new. There is nothing to compare, so
	// this is a D1 and not a D2, and the point of the test is that the base
	// was read at all.
	got := deps.Diff(base, head, "package-lock.json")
	for _, f := range got {
		if f.RuleID == deps.D2ID {
			t.Errorf("a D2 was reported for a package that is not in the base: %s", f.Message)
		}
	}
}

// The findings come out with the install script one first.
//
// A reader scanning the output should meet the case that executes code at
// install time before the case that is only worth a look.
func TestDiffPutsTheScriptedPackageFirst(t *testing.T) {
	base := lockFixture(t, "diff-base.json")
	head := lockFixture(t, "diff-head.json")

	got := deps.Diff(base, head, "package-lock.json")
	if len(got) == 0 {
		t.Fatal("no findings")
	}
	if got[0].RuleID != deps.D1D2ID {
		t.Errorf("the first finding is %q, want %q", got[0].RuleID, deps.D1D2ID)
	}
}

// The findings name the file they came from.
func TestDiffLocation(t *testing.T) {
	base := lockFixture(t, "diff-base.json")
	head := lockFixture(t, "diff-head.json")

	got := deps.Diff(base, head, "package-lock.json")
	if len(got) == 0 {
		t.Fatal("no findings")
	}
	if got[0].Location.File != "package-lock.json" {
		t.Errorf("the file is %q, want package-lock.json", got[0].Location.File)
	}
}
