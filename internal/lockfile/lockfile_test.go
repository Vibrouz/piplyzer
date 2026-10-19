package lockfile_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/lockfile"
)

// fixture reads a lockfile fixture.
func fixture(t *testing.T, name string) *lockfile.Lockfile {
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

// A lockfile that npm actually wrote is read the way npm wrote it.
//
// The fixture is a real package-lock.json produced by npm install, so the shape
// of it is the shape of the thing this has to read. A hand-written fixture
// would have the shape the author expected, which is not the same thing.
func TestParseRealNpmLockfile(t *testing.T) {
	lock := fixture(t, "npm-v3.json")

	if lock.Version != 3 {
		t.Errorf("Version = %d, want 3", lock.Version)
	}
	if lock.Name != "gen" {
		t.Errorf("Name = %q, want gen", lock.Name)
	}
	// The root entry, keyed by the empty string, is the project and not a
	// dependency of it.
	if len(lock.Packages) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(lock.Packages), lock.Packages)
	}

	p := lock.Packages[0]
	if p.Name != "lodash" {
		t.Errorf("Name = %q, want lodash", p.Name)
	}
	if p.Version != "4.18.1" {
		t.Errorf("Version = %q, want 4.18.1", p.Version)
	}
	if p.Resolved != "https://registry.npmjs.org/lodash/-/lodash-4.18.1.tgz" {
		t.Errorf("Resolved = %q", p.Resolved)
	}
	// The field is absent, and on a version 3 lockfile absent means false.
	if value, known := p.HasInstallScript.Bool(); !known || value {
		t.Errorf("HasInstallScript = %v (known %v), want false and known", value, known)
	}
}

// Every field the checks need is read from a version 3 lockfile.
func TestParseV3Fields(t *testing.T) {
	lock := fixture(t, "v3.json")

	byPath := map[string]lockfile.Package{}
	for _, p := range lock.Packages {
		byPath[p.Path] = p
	}

	// A package with no install script.
	plain, ok := byPath["node_modules/plain"]
	if !ok {
		t.Fatal("node_modules/plain is missing")
	}
	if value, known := plain.HasInstallScript.Bool(); !known || value {
		t.Errorf("plain HasInstallScript = %v (known %v), want false and known", value, known)
	}

	// A package with one.
	script, ok := byPath["node_modules/with-install-script"]
	if !ok {
		t.Fatal("node_modules/with-install-script is missing")
	}
	if value, known := script.HasInstallScript.Bool(); !known || !value {
		t.Errorf("script HasInstallScript = %v (known %v), want true and known", value, known)
	}

	// A nested package. The name is what comes after the last node_modules/,
	// which is what npm calls it.
	nested, ok := byPath["node_modules/parent/node_modules/nested"]
	if !ok {
		t.Fatal("the nested package is missing")
	}
	if nested.Name != "nested" {
		t.Errorf("nested Name = %q, want nested", nested.Name)
	}
	if !nested.Dev {
		t.Error("nested Dev = false, want true")
	}
}

// The packages are sorted by path, so two runs produce the same order.
//
// A map would not, and a diff that reorders itself between runs is a diff
// nobody reads.
func TestParseIsDeterministic(t *testing.T) {
	first := fixture(t, "v3.json")
	for i := 0; i < 5; i++ {
		got := fixture(t, "v3.json")
		if len(got.Packages) != len(first.Packages) {
			t.Fatalf("run %d had %d packages, run 0 had %d", i, len(got.Packages), len(first.Packages))
		}
		for j := range got.Packages {
			if got.Packages[j].Path != first.Packages[j].Path {
				t.Fatalf("run %d order differs at %d: %q vs %q", i, j, got.Packages[j].Path, first.Packages[j].Path)
			}
		}
	}
}

// A version 1 lockfile has a nested dependencies tree and no packages map.
//
// The tree is a hierarchy, so the path has to be built as it descends, and the
// same package can appear at more than one path when npm had to install more
// than one version of it.
func TestParseV1Tree(t *testing.T) {
	lock := fixture(t, "v1.json")

	if lock.Version != 1 {
		t.Errorf("Version = %d, want 1", lock.Version)
	}
	if len(lock.Packages) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(lock.Packages), lock.Packages)
	}

	byPath := map[string]lockfile.Package{}
	for _, p := range lock.Packages {
		byPath[p.Path] = p
	}

	alpha, ok := byPath["node_modules/alpha"]
	if !ok {
		t.Fatal("node_modules/alpha is missing")
	}
	if alpha.Name != "alpha" || alpha.Version != "1.0.0" {
		t.Errorf("alpha = %+v", alpha)
	}

	beta, ok := byPath["node_modules/alpha/node_modules/beta"]
	if !ok {
		t.Fatal("the nested beta is missing")
	}
	if beta.Name != "beta" || beta.Version != "2.0.0" {
		t.Errorf("beta = %+v", beta)
	}
}

// A version 1 lockfile does not record hasInstallScript at all.
//
// Reading the absent field as false would be a silent false negative on the
// check that blocks install-time malware, so it has to read as unknown.
func TestV1CannotSayAboutInstallScripts(t *testing.T) {
	lock := fixture(t, "v1.json")

	for _, p := range lock.Packages {
		if value, known := p.HasInstallScript.Bool(); known {
			t.Errorf("%s HasInstallScript = %v and known, want unknown", p.Path, value)
		}
	}
}

// A version 2 lockfile has both a packages map and a legacy dependencies tree.
//
// The packages map is the one to read. It is flat, so a nested package is one
// entry rather than a subtree, and it carries the hasInstallScript field that
// the legacy tree does not have.
func TestParseV2PrefersThePackagesMap(t *testing.T) {
	lock := fixture(t, "npm-v2.json")

	if lock.Version != 2 {
		t.Errorf("Version = %d, want 2", lock.Version)
	}
	if len(lock.Packages) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(lock.Packages), lock.Packages)
	}
	if lock.Packages[0].Name != "lodash" {
		t.Errorf("Name = %q, want lodash", lock.Packages[0].Name)
	}
	// The field is absent and the lockfile is version 2, so absent means false.
	if value, known := lock.Packages[0].HasInstallScript.Bool(); !known || value {
		t.Errorf("HasInstallScript = %v (known %v), want false and known", value, known)
	}
}

// The tri-state is the whole point, so it is tested directly.
func TestTriState(t *testing.T) {
	if value, known := lockfile.Present.Bool(); !known || !value {
		t.Errorf("Present = %v (known %v), want true and known", value, known)
	}
	if value, known := lockfile.Absent.Bool(); !known || value {
		t.Errorf("Absent = %v (known %v), want false and known", value, known)
	}
	if value, known := lockfile.Unknown.Bool(); known || value {
		t.Errorf("Unknown = %v (known %v), want false and not known", value, known)
	}
	if lockfile.Present.String() != "yes" || lockfile.Absent.String() != "no" || lockfile.Unknown.String() != "unknown" {
		t.Error("the string forms are wrong")
	}
}

// A file that is not a lockfile is an error, not an empty lockfile.
//
// An empty lockfile is indistinguishable from a clean one, and a dependency
// check that silently checks nothing is worse than no check at all.
func TestParseRejectsNonLockfiles(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"not json", "this is not json\n"},
		{"json but not a lockfile", `{"hello":"world"}`},
		{"a truncated file", `{"name":"x","lockfileVersion":3,"packages":{`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := lockfile.Parse([]byte(tt.data)); err == nil {
				t.Error("Parse succeeded, want an error")
			}
		})
	}
}

// A lockfile with no packages is an empty project, which is a real answer.
//
// This is the one case where the lockfile has a lockfileVersion and no
// dependencies at all, which is what npm writes for a project with no
// dependencies.
func TestParseEmptyLockfile(t *testing.T) {
	lock, err := lockfile.Parse([]byte(`{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"}}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(lock.Packages) != 0 {
		t.Errorf("got %d packages, want 0", len(lock.Packages))
	}
}

// A lockfile with neither a packages map nor a dependencies tree is empty.
//
// The root entry alone is a lockfile with no dependencies, so this is the same
// answer reached a different way.
func TestParseLockfileWithNeitherSection(t *testing.T) {
	lock, err := lockfile.Parse([]byte(`{"name":"x","version":"1.0.0","lockfileVersion":3}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(lock.Packages) != 0 {
		t.Errorf("got %d packages, want 0", len(lock.Packages))
	}
}

// A package is found by its path, and a path that is not there is not found.
func TestGet(t *testing.T) {
	lock := fixture(t, "v3.json")

	p, ok := lock.Get("node_modules/plain")
	if !ok {
		t.Fatal("Get did not find the package")
	}
	if p.Name != "plain" {
		t.Errorf("Name = %q, want plain", p.Name)
	}
	if _, ok := lock.Get("node_modules/nope"); ok {
		t.Error("Get found a package that is not there")
	}
}

// A package entry that is not shaped like one is an error.
func TestParseRejectsAMalformedEntry(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "a modern entry that is not an object",
			data: `{"lockfileVersion":3,"packages":{"node_modules/x":"not an object"}}`,
		},
		{
			name: "a legacy entry that is not an object",
			data: `{"lockfileVersion":1,"dependencies":{"x":"not an object"}}`,
		},
		{
			name: "a legacy entry whose nested tree is not an object",
			data: `{"lockfileVersion":1,"dependencies":{"x":{"version":"1.0.0","dependencies":"not an object"}}}`,
		},
		{
			// A nested entry is only checked when the recursion reaches it, so
			// the error surfaces from there rather than from the outer unmarshal.
			name: "a legacy entry with a malformed nested entry",
			data: `{"lockfileVersion":1,"dependencies":{"x":{"version":"1.0.0","dependencies":{"y":"not an object"}}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := lockfile.Parse([]byte(tt.data)); err == nil {
				t.Error("Parse succeeded, want an error")
			}
		})
	}
}

// The name is derived from the path, and a path with no node_modules in it
// keeps the whole path rather than becoming an empty name.
func TestNameFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"node_modules/lodash", "lodash"},
		{"node_modules/parent/node_modules/nested", "nested"},
		{"node_modules/@scope/pkg", "@scope/pkg"},
		{"", ""},
		// A path with no node_modules in it is not a package path. npm does not
		// write one, but the parser has to have an answer for it, and the
		// answer is not an empty name, which would sort and display as nothing.
		{"weird/path", "weird/path"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			// The derivation is exercised through Parse, since it is not
			// exported.
			data := `{"lockfileVersion":3,"packages":{"` + tt.path + `":{"version":"1.0.0"}}}`
			lock, err := lockfile.Parse([]byte(data))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(lock.Packages) == 0 {
				if tt.want != "" {
					t.Errorf("got no packages, want one named %q", tt.want)
				}
				return
			}
			if got := lock.Packages[0].Name; got != tt.want {
				t.Errorf("Name = %q, want %q", got, tt.want)
			}
		})
	}
}

// The resolved URL is kept exactly as the lockfile wrote it.
//
// It is not a URL in every case, and normalising it here would lose the
// information that tells the two cases apart. The check that reads it needs to
// see the raw value.
func TestResolvedIsKeptVerbatim(t *testing.T) {
	for _, resolved := range []string{
		"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
		"https://npm.pkg.github.com/@scope/pkg/-/pkg-1.0.0.tgz",
		"git+https://github.com/org/repo.git#abc123",
		"file:../local",
		"lodash/-/lodash-4.17.21.tgz",
	} {
		data := `{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0","resolved":"` + resolved + `"}}}`
		lock, err := lockfile.Parse([]byte(data))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(lock.Packages) != 1 {
			t.Fatalf("got %d packages, want 1", len(lock.Packages))
		}
		if lock.Packages[0].Resolved != resolved {
			t.Errorf("Resolved = %q, want %q", lock.Packages[0].Resolved, resolved)
		}
	}
}

// The name of a scoped package keeps its scope, because the scope is part of
// the name and dropping it would merge two different packages.
func TestScopedPackageKeepsItsScope(t *testing.T) {
	data := `{"lockfileVersion":3,"packages":{"node_modules/@scope/pkg":{"version":"1.0.0"}}}`
	parsed, err := lockfile.Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	name := parsed.Packages[0].Name
	if !strings.HasPrefix(name, "@") {
		t.Errorf("Name = %q, want it to keep the scope", name)
	}
}
