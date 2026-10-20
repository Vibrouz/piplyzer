package deps

import (
	"bufio"
	"net/url"
	"os"
	"strings"
)

// DiscoverRegistry works out which registry the project is configured to use.
//
// The order is the one the plan sets out, and the order matters:
//
//  1. An explicit --registry flag.
//  2. The .npmrc in the repository.
//  3. The NPM_CONFIG_REGISTRY environment variable.
//  4. The registry-url input of an actions/setup-node step in the workflow.
//
// The first three are what npm itself would use. The fourth is not an npm
// setting at all, it is a thing a workflow does, and it is last because it is
// the one that is easiest to get wrong: a setup-node step can set a registry
// for the job, and if the repository has an .npmrc as well, which one wins
// depends on how the workflow is run.
//
// It returns Found false when no registry could be found.
//
// A project with no registry configuration is not a dependency-confusion
// incident, it is an unconfigured project, so the caller downgrades the
// finding rather than blocking on it. Hard-failing on "we could not find your
// configuration" is a false-positive machine.
func DiscoverRegistry(explicit string, repoDir string, env func(string) string, workflowRegistry string) (Registry, bool) {
	// The default registry is always known, because npm has one. A project that
	// configures nothing is using it.
	registry := Registry{Scopes: map[string]*url.URL{}}

	if raw := strings.TrimSpace(explicit); raw != "" {
		if u, ok := parseRegistry(raw); ok {
			registry.Default = u
			registry.Found = true
			return registry, true
		}
		return Registry{}, false
	}

	if repoDir != "" {
		if found, ok := registryFromNpmrc(repoDir); ok {
			return found, true
		}
	}

	if raw := strings.TrimSpace(env("NPM_CONFIG_REGISTRY")); raw != "" {
		if u, ok := parseRegistry(raw); ok {
			registry.Default = u
			registry.Found = true
			return registry, true
		}
		return Registry{}, false
	}

	if raw := strings.TrimSpace(workflowRegistry); raw != "" {
		if u, ok := parseRegistry(raw); ok {
			registry.Default = u
			registry.Found = true
			return registry, true
		}
		return Registry{}, false
	}

	return registry, false
}

// registryFromNpmrc reads the registries out of a repository's .npmrc.
//
// The file is read line by line rather than parsed as INI, because npm reads a
// .npmrc as a sequence of key=value lines with comments, and an INI parser
// would disagree with npm about the lines that matter.
//
// Two kinds of registry are read:
//
//	registry=https://npm.pkg.github.com/          the default
//	@myorg:registry=https://npm.pkg.github.com/  one scope
//
// The scoped form matters. A project that serves one scope from a private
// registry and everything else from the default is an ordinary setup, and a
// check that only knew about the default would report every package in the
// private scope.
func registryFromNpmrc(dir string) (Registry, bool) {
	file, err := os.Open(dir + "/.npmrc")
	if err != nil {
		return Registry{}, false
	}
	defer file.Close()

	registry := Registry{Scopes: map[string]*url.URL{}}
	found := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		if rest, isScoped := strings.CutPrefix(key, "@"); isScoped {
			// A scoped registry. The key is "@myorg:registry".
			//
			// The suffix is cut from the end rather than the first occurrence,
			// because the key has to end with ":registry" for it to be one.
			// Cutting on the first occurrence would accept "@myorg:registry
			// :something-else" as a scoped registry.
			name, ok := strings.CutSuffix(rest, ":registry")
			if !ok || name == "" {
				continue
			}
			u, ok := parseRegistry(value)
			if !ok {
				continue
			}
			registry.Scopes["@"+name] = u
			found = true
			continue
		}

		if key != "registry" {
			continue
		}
		u, ok := parseRegistry(value)
		if !ok {
			continue
		}
		registry.Default = u
		found = true
	}

	if !found {
		return Registry{}, false
	}
	return registry, true
}

// parseRegistry turns a registry URL into a URL.
//
// A URL that does not parse is not a registry, and the caller treats that the
// same as no registry at all: a broken setting is a configuration problem, not
// evidence of a dependency confusion incident.
func parseRegistry(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, false
	}
	return u, true
}
