package deps_test

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/deps"
	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/lockfile"
)

// registry builds a Registry with one default registry.
func registry(t *testing.T, raw string) deps.Registry {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return deps.Registry{Default: u, Scopes: map[string]*url.URL{}, Found: true}
}

// scopedRegistry builds a Registry with a default and one scoped registry.
func scopedRegistry(t *testing.T, defaultURL, scope, scopeURL string) deps.Registry {
	t.Helper()
	reg := registry(t, defaultURL)
	u, err := url.Parse(scopeURL)
	if err != nil {
		t.Fatalf("parse %q: %v", scopeURL, err)
	}
	reg.Scopes = map[string]*url.URL{scope: u}
	return reg
}

// lockWith builds a lockfile with one package, from a lockfile JSON body.
func lockWith(t *testing.T, path, resolved string) *lockfile.Lockfile {
	t.Helper()
	body := `{"name":"p","version":"1.0.0","lockfileVersion":3,"packages":{"":{},` +
		`"node_modules/` + path + `":{"version":"1.0.0"` +
		map[bool]string{true: `,"resolved":"` + resolved + `"`}[resolved != ""] + `}}}`
	lock, err := lockfile.Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return lock
}

// The whole fixture, which has every shape of resolved URL in one lockfile.
//
// The unit tests above each cover one shape. This one covers them together,
// because the shapes are the point of the check and a lockfile has all of them
// at once.
func TestD3OverTheFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "lockfile", "registry-mismatch.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	lock, err := lockfile.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// The default registry is npmjs.org and the @myorg scope is served by a
	// private one.
	reg := scopedRegistry(t, "https://registry.npmjs.org/", "@myorg", "https://npm.pkg.github.com/")

	got := deps.D3(lock, reg, "package-lock.json")

	// Only the package from the third host is a finding.
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Message, "from-another-registry") {
		t.Errorf("the wrong package was reported: %s", got[0].Message)
	}
}

// A package resolved from a registry other than the one serving it is a
// finding.
//
// This is dependency confusion. The project fetches from one place and the
// lockfile says the package came from another, so the code that runs at install
// time is code somebody else published.
func TestD3ReportsAPackageFromAnotherRegistry(t *testing.T) {
	lock := lockWith(t, "lodash", "https://evil.example.com/lodash/-/lodash-4.17.21.tgz")
	reg := registry(t, "https://npm.pkg.github.com/")

	got := deps.D3(lock, reg, "package-lock.json")

	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if got[0].RuleID != deps.D3ID {
		t.Errorf("RuleID = %q, want %q", got[0].RuleID, deps.D3ID)
	}
	if got[0].Severity != findings.SeverityBlock {
		t.Errorf("Severity = %q, want Block", got[0].Severity)
	}
	// The message names the package and both hosts, because "this package came
	// from somewhere else" is not actionable.
	if !strings.Contains(got[0].Message, "lodash") {
		t.Errorf("the message does not name the package: %s", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "evil.example.com") {
		t.Errorf("the message does not name where it came from: %s", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "npm.pkg.github.com") {
		t.Errorf("the message does not name the registry it should have come from: %s", got[0].Message)
	}
}

// A package resolved from the registry serving it is not a finding.
func TestD3AcceptsTheConfiguredRegistry(t *testing.T) {
	lock := lockWith(t, "lodash", "https://npm.pkg.github.com/lodash/-/lodash-4.17.21.tgz")
	reg := registry(t, "https://npm.pkg.github.com/")

	if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}
}

// The npmjs.org magic value means the currently configured registry, so it is
// not a finding.
//
// This is the case that a string comparison gets wrong, and it is not a rare
// shape: it is what npm writes for every package when the lockfile is created
// against the public registry, which is what most lockfiles are. A check that
// compared hosts would report every package in every repository.
func TestD3AcceptsTheNpmjsMagicValue(t *testing.T) {
	lock := lockWith(t, "lodash", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
	reg := registry(t, "https://npm.pkg.github.com/")

	if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 0 {
		t.Errorf("got %d findings, want 0: the magic value means the configured registry: %+v", len(got), got)
	}
}

// A relative path is resolved against the registry serving the package, so it
// is not a finding.
//
// This is the other case a string comparison gets wrong, and it is the shape a
// lockfile written against a registry with a path prefix has.
func TestD3AcceptsARelativeResolvedPath(t *testing.T) {
	lock := lockWith(t, "lodash", "lodash/-/lodash-4.17.21.tgz")
	reg := registry(t, "https://npm.pkg.github.com/")

	if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 0 {
		t.Errorf("got %d findings, want 0: a relative path resolves against the configured registry: %+v", len(got), got)
	}
}

// A git dependency, a local tarball, and a file path are not registry fetches,
// so they are not this check's business.
func TestD3IgnoresNonRegistryReferences(t *testing.T) {
	for _, resolved := range []string{
		"git+https://github.com/org/repo.git#abc123",
		"file:../local-package",
	} {
		t.Run(resolved, func(t *testing.T) {
			lock := lockWith(t, "pkg", resolved)
			reg := registry(t, "https://npm.pkg.github.com/")

			if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(got), got)
			}
		})
	}
}

// A package with no resolved URL is not fetched from a registry.
func TestD3IgnoresAPackageWithNoResolvedURL(t *testing.T) {
	lock := lockWith(t, "pkg", "")
	reg := registry(t, "https://npm.pkg.github.com/")

	if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}
}

// A scoped package is served by its scope's registry, so a package resolved
// from there is not a finding even when the default registry is different.
//
// A project that serves one scope from a private registry and everything else
// from the default is an ordinary setup. A check that only knew about the
// default would report every package in the private scope.
func TestD3UsesTheScopeRegistry(t *testing.T) {
	reg := scopedRegistry(t, "https://registry.npmjs.org/", "@myorg", "https://npm.pkg.github.com/")

	// The scoped package comes from the scope's registry, which is where it
	// belongs.
	lock := lockWith(t, "@myorg/pkg", "https://npm.pkg.github.com/@myorg/pkg/-/pkg-1.0.0.tgz")
	if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 0 {
		t.Errorf("got %d findings, want 0 for the scope's own registry: %+v", len(got), got)
	}

	// The same package from a third host is a finding.
	lock = lockWith(t, "@myorg/pkg", "https://evil.example.com/pkg/-/pkg-1.0.0.tgz")
	if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 1 {
		t.Errorf("got %d findings, want 1: %+v", len(got), got)
	}
}

// An unscoped package is served by the default registry, even when a scope
// registry is configured.
func TestD3UnscopedPackageUsesTheDefaultRegistry(t *testing.T) {
	reg := scopedRegistry(t, "https://npm.pkg.github.com/", "@myorg", "https://other.example.com/")

	lock := lockWith(t, "lodash", "https://npm.pkg.github.com/lodash/-/lodash-4.17.21.tgz")
	if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(got), got)
	}

	lock = lockWith(t, "lodash", "https://other.example.com/lodash/-/lodash-4.17.21.tgz")
	if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 1 {
		t.Errorf("got %d findings, want 1: %+v", len(got), got)
	}
}

// When no registry configuration was found, the finding is a Warn rather than
// a Block.
//
// The project may be using a registry that was not in any of the places we
// read, and a finding that depends on a registry we did not find is not a fact.
// A repo with no .npmrc is not a dependency-confusion incident, it is an
// unconfigured project.
func TestD3DowngradesWhenNoRegistryWasFound(t *testing.T) {
	lock := lockWith(t, "lodash", "https://some-mirror.example.com/lodash/-/lodash-4.17.21.tgz")

	got := deps.D3(lock, deps.Registry{}, "package-lock.json")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if got[0].Severity != findings.SeverityWarn {
		t.Errorf("Severity = %q, want Warn", got[0].Severity)
	}
}

// The source of the registry is recorded, so that a finding can say where the
// registry it compared against came from.
//
// The sources are not equivalent and a reader cannot tell them apart from the
// finding. The environment variable silently outranks the repository's own
// .npmrc, so a project whose .npmrc says one registry and whose CI sets
// another is checked against the CI one, with nothing in the output to say so.
func TestDiscoverRegistryRecordsItsSource(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	tests := []struct {
		name  string
		npmrc string
		flag  string
		env   map[string]string
		wf    string
		want  string
	}{
		{
			name: "the flag",
			flag: "https://from-flag.example/",
			want: "--registry flag",
		},
		{
			name:  "the npmrc",
			npmrc: "registry=https://from-npmrc.example/\n",
			want:  ".npmrc in the repository",
		},
		{
			name: "the environment",
			env:  map[string]string{"NPM_CONFIG_REGISTRY": "https://from-env.example/"},
			want: "NPM_CONFIG_REGISTRY",
		},
		{
			name: "the workflow",
			wf:   "https://from-workflow.example/",
			want: "setup-node",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A directory of its own for each case, because the sources are
			// tried in order and an .npmrc left over from another case would
			// win over the one under test.
			dir := t.TempDir()
			if tt.npmrc != "" {
				if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(tt.npmrc), 0o644); err != nil {
					t.Fatalf("write npmrc: %v", err)
				}
			}

			got, found := deps.DiscoverRegistry(tt.flag, dir, env(tt.env), tt.wf)
			if !found {
				t.Fatal("no registry was found")
			}
			if !strings.Contains(got.Source, tt.want) {
				t.Errorf("Source = %q, want it to mention %q", got.Source, tt.want)
			}
		})
	}
}

// A finding says where the registry it compared against came from.
//
// Without it, a project whose CI sets a registry that contradicts the
// repository's own .npmrc gets a finding that gives no way to tell which
// registry was used.
func TestD3MessageNamesTheRegistrySource(t *testing.T) {
	body := `{"name":"p","version":"1.0.0","lockfileVersion":3,"packages":{
		"": {"name":"p","version":"1.0.0"},
		"node_modules/evil": {"version":"1.0.0","resolved":"https://evil.example.com/evil/-/evil-1.0.0.tgz","integrity":"sha512-x"}
	}}`
	file, err := lockfile.Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	registry, found := deps.DiscoverRegistry("https://npm.pkg.github.com/", "", func(string) string { return "" }, "")
	if !found {
		t.Fatal("no registry was found")
	}

	got := deps.D3(file, registry, "package-lock.json")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Message, "--registry flag") {
		t.Errorf("the message does not name the source: %s", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "npm.pkg.github.com") {
		t.Errorf("the message does not name the registry: %s", got[0].Message)
	}
}

// The registry is discovered from the four sources, in the order the plan sets
// out, and the first one that has something wins.
func TestDiscoverRegistryOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("registry=https://from-npmrc.example/\n"), 0o644); err != nil {
		t.Fatalf("write npmrc: %v", err)
	}

	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	tests := []struct {
		name  string
		flag  string
		dir   string
		env   map[string]string
		wf    string
		want  string
		found bool
	}{
		{
			name:  "the flag wins over everything",
			flag:  "https://from-flag.example/",
			dir:   dir,
			env:   map[string]string{"NPM_CONFIG_REGISTRY": "https://from-env.example/"},
			wf:    "https://from-workflow.example/",
			want:  "from-flag.example",
			found: true,
		},
		{
			name:  "the npmrc wins over the environment and the workflow",
			dir:   dir,
			env:   map[string]string{"NPM_CONFIG_REGISTRY": "https://from-env.example/"},
			wf:    "https://from-workflow.example/",
			want:  "from-npmrc.example",
			found: true,
		},
		{
			name:  "the environment wins over the workflow",
			env:   map[string]string{"NPM_CONFIG_REGISTRY": "https://from-env.example/"},
			wf:    "https://from-workflow.example/",
			want:  "from-env.example",
			found: true,
		},
		{
			name:  "the workflow is the last one",
			wf:    "https://from-workflow.example/",
			want:  "from-workflow.example",
			found: true,
		},
		{
			name:  "nothing configured",
			want:  "",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := deps.DiscoverRegistry(tt.flag, tt.dir, env(tt.env), tt.wf)
			if found != tt.found {
				t.Fatalf("found = %v, want %v", found, tt.found)
			}
			if !found {
				return
			}
			if got.Default == nil {
				t.Fatal("the default registry is not set")
			}
			if !strings.Contains(got.Default.Host, tt.want) {
				t.Errorf("host = %q, want it to contain %q", got.Default.Host, tt.want)
			}
		})
	}
}

// The .npmrc is read the way npm reads it, as key=value lines with comments,
// and a scoped registry is read as well as the default one.
func TestRegistryFromNpmrc(t *testing.T) {
	tests := []struct {
		name       string
		npmrc      string
		want       string
		wantScope  string
		wantScope2 string
		found      bool
	}{
		{name: "plain", npmrc: "registry=https://a.example/\n", want: "a.example", found: true},
		{name: "with comments", npmrc: "# a comment\n; another\nregistry=https://b.example/\n", want: "b.example", found: true},
		{name: "with spaces", npmrc: "  registry = https://c.example/  \n", want: "c.example", found: true},
		{
			name:      "a scoped registry as well",
			npmrc:     "registry=https://d.example/\n@myorg:registry=https://e.example/\n",
			want:      "d.example",
			wantScope: "@myorg",
			found:     true,
		},
		{
			name:      "only a scoped registry",
			npmrc:     "@myorg:registry=https://f.example/\n",
			wantScope: "@myorg",
			found:     true,
		},
		{name: "other keys are skipped", npmrc: "always-auth=true\nregistry=https://g.example/\n", want: "g.example", found: true},
		{name: "no registry key", npmrc: "always-auth=true\n", found: false},
		{name: "an empty value", npmrc: "registry=\n", found: false},
		{name: "an auth token is not a registry", npmrc: "//registry.npmjs.org/:_authToken=abc\n", found: false},
		{name: "empty file", npmrc: "", found: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(tt.npmrc), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}

			got, found := deps.DiscoverRegistry("", dir, func(string) string { return "" }, "")
			if found != tt.found {
				t.Fatalf("found = %v, want %v", found, tt.found)
			}
			if !found {
				return
			}
			// The Found field is what the check uses to decide whether a
			// finding is a Block or a Warn, so it has to agree with the return
			// value. The .npmrc path once left it unset, which made every
			// project that had configured a registry read as one that had not.
			if !got.Found {
				t.Error("Found = false for a registry that was found")
			}
			if tt.want != "" {
				if got.Default == nil {
					t.Fatal("the default registry is not set")
				}
				if !strings.Contains(got.Default.Host, tt.want) {
					t.Errorf("host = %q, want it to contain %q", got.Default.Host, tt.want)
				}
			}
			if tt.wantScope != "" {
				u, ok := got.Scopes[tt.wantScope]
				if !ok {
					t.Fatalf("the scope %q is missing: %v", tt.wantScope, got.Scopes)
				}
				if tt.wantScope2 != "" && !strings.Contains(u.Host, tt.wantScope2) {
					t.Errorf("scope host = %q, want it to contain %q", u.Host, tt.wantScope2)
				}
			}
		})
	}
}

// A registry URL that does not parse is a configuration problem, not evidence
// of anything, so it is treated the same as no registry at all.
func TestDiscoverRegistryRejectsABrokenURL(t *testing.T) {
	env := func(string) string { return "" }
	for _, raw := range []string{"not a url", "://nope", "/just/a/path"} {
		if _, ok := deps.DiscoverRegistry(raw, "", env, ""); ok {
			t.Errorf("DiscoverRegistry(%q) found a registry, want none", raw)
		}
	}
}

// A broken value in the .npmrc is skipped rather than accepted, and the rest of
// the file is still read.
//
// A .npmrc with one bad line and one good line is a .npmrc with a good
// registry, and refusing all of it because of the bad line would be a check
// that gives up on a file it can partly read.
func TestNpmrcSkipsBrokenValues(t *testing.T) {
	dir := t.TempDir()
	content := "registry=not a url\n@myorg:registry=also not a url\nregistry=https://good.example/\n"
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, found := deps.DiscoverRegistry("", dir, func(string) string { return "" }, "")
	if !found {
		t.Fatal("found = false, want true")
	}
	if got.Default == nil {
		t.Fatal("the default registry is not set")
	}
	if !strings.Contains(got.Default.Host, "good.example") {
		t.Errorf("host = %q, want it to contain good.example", got.Default.Host)
	}
}

// A .npmrc with only broken values is no registry at all.
func TestNpmrcWithOnlyBrokenValuesIsNoRegistry(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("registry=not a url\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, found := deps.DiscoverRegistry("", dir, func(string) string { return "" }, ""); found {
		t.Error("found = true, want false")
	}
}

// A broken registry in the environment or the workflow is a configuration
// problem, and it does not fall through to the next source.
//
// The sources are tried in order and the first one that parses wins. A broken
// value in an earlier source is not a reason to look at a later one, because
// that would mean the setting was ignored rather than fixed.
func TestDiscoverRegistryDoesNotFallThroughABrokenValue(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	// A broken flag with a good environment.
	if _, ok := deps.DiscoverRegistry("not a url", "", env(map[string]string{
		"NPM_CONFIG_REGISTRY": "https://good.example/",
	}), ""); ok {
		t.Error("found = true, want false for a broken flag")
	}

	// A broken environment with a good workflow.
	if _, ok := deps.DiscoverRegistry("", "", env(map[string]string{
		"NPM_CONFIG_REGISTRY": "not a url",
	}), "https://good.example/"); ok {
		t.Error("found = true, want false for a broken environment")
	}

	// A broken workflow value.
	if _, ok := deps.DiscoverRegistry("", "", env(map[string]string{}), "not a url"); ok {
		t.Error("found = true, want false for a broken workflow value")
	}
}

// A .npmrc that cannot be read is no registry, not an error.
//
// A repository with no .npmrc at all is an ordinary repository, and the file
// being unreadable is the same situation as far as this check is concerned.
func TestNpmrcThatCannotBeRead(t *testing.T) {
	if _, found := deps.DiscoverRegistry("", "/nonexistent-directory", func(string) string { return "" }, ""); found {
		t.Error("found = true, want false")
	}
}

// A .npmrc line that is not a key=value pair is skipped.
func TestNpmrcSkipsLinesThatAreNotKeyValue(t *testing.T) {
	dir := t.TempDir()
	content := "just some text\nregistry=https://good.example/\n=novalue\n"
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, found := deps.DiscoverRegistry("", dir, func(string) string { return "" }, "")
	if !found {
		t.Fatal("found = false, want true")
	}
	if !strings.Contains(got.Default.Host, "good.example") {
		t.Errorf("host = %q, want good.example", got.Default.Host)
	}
}

// A scoped key that is not a registry is not a scope.
//
// "@myorg:publishConfig" is a different key that happens to start with an @.
func TestNpmrcIgnoresOtherScopedKeys(t *testing.T) {
	dir := t.TempDir()
	content := "@myorg:publishConfig=public\n@myorg:registry=https://scope.example/\n"
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, found := deps.DiscoverRegistry("", dir, func(string) string { return "" }, "")
	if !found {
		t.Fatal("found = false, want true")
	}
	if len(got.Scopes) != 1 {
		t.Errorf("got %d scopes, want 1: %v", len(got.Scopes), got.Scopes)
	}
	if _, ok := got.Scopes["@myorg"]; !ok {
		t.Errorf("the scope is missing: %v", got.Scopes)
	}
}

// A resolved URL that does not parse is not a registry fetch.
//
// The lockfile is a file in the repository, so a malformed URL in it is
// something a pull request could contain, and it has to be ignored rather
// than crash the scan.
func TestD3IgnoresAMalformedResolvedURL(t *testing.T) {
	for _, resolved := range []string{
		"https://exa mple.com/pkg.tgz",
		"http://[::1/pkg.tgz",
	} {
		lock := lockWith(t, "pkg", resolved)
		reg := registry(t, "https://npm.pkg.github.com/")

		if got := deps.D3(lock, reg, "package-lock.json"); len(got) != 0 {
			t.Errorf("got %d findings for %q, want 0: %+v", len(got), resolved, got)
		}
	}
}

// The scope of a package name, which decides which registry serves it.
func TestScopeOf(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"lodash", ""},
		{"@myorg/pkg", "@myorg"},
		{"@myorg/pkg/sub", "@myorg"},
		{"@notascope", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The scope is exercised through the registry it selects.
			reg := scopedRegistry(t, "https://default.example/", "@myorg", "https://scope.example/")
			got := reg.For(tt.name)
			if got == nil {
				t.Fatal("For returned nothing")
			}
			want := "default.example"
			if tt.want == "@myorg" {
				want = "scope.example"
			}
			if !strings.Contains(got.Host, want) {
				t.Errorf("For(%q) = %q, want the %q registry", tt.name, got.Host, want)
			}
		})
	}
}
