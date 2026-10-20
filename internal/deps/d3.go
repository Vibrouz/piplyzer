// Package deps holds the checks that read an npm lockfile.
//
// The checks are pure functions over a lockfile and whatever else the caller
// provides. Nothing here touches the network, reads the git history, or reads
// the environment. That is the same discipline the workflow rules follow, and
// for the same reason: a check that cannot be run over a crafted input is a
// check that cannot be tested.
package deps

import (
	"net/url"
	"strings"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/lockfile"
)

// ---------------------------------------------------------------- D3

// D3ID is the rule identifier for the registry check.
const D3ID = "DEP-D3"

// npmjsHost is the host of the public npm registry.
//
// It has a special meaning in a lockfile. The npm documentation is explicit
// about it:
//
//	"When the default registry is used in a package-lock or shrinkwrap it has
//	 the special meaning of 'the currently configured registry'."
//
// So a package whose resolved URL points here was fetched from whichever
// registry applies to it, and where it was fetched from is not something the
// lockfile records. A lockfile written against a mirror says registry.npmjs.org
// and means the mirror.
const npmjsHost = "registry.npmjs.org"

// Registry is the registry configuration a project has.
//
// It is more than one URL because npm's registry configuration is per scope: a
// scope can point at a private registry while everything else comes from the
// default. A project that has a private scope registry and does not use it
// for anything else is an ordinary setup, and a check that ignored the scope
// would report every package in it.
type Registry struct {
	// Default is the registry for unscoped packages, and for scopes with no
	// registry of their own.
	Default *url.URL

	// Scopes maps a scope, with its @, to the registry that serves it.
	Scopes map[string]*url.URL

	// Found is whether any registry configuration was found at all.
	//
	// It is not the same as Default being set. The default registry is always
	// known, because npm has one, and a project that configures nothing is
	// using it. What is not known is what a project that configures a registry
	// somewhere we did not read is using, and a finding that depends on that
	// unknown is not a Block.
	Found bool
}

// For returns the registry that serves a package.
//
// A scoped package goes to its scope's registry if it has one, and everything
// else goes to the default.
func (r Registry) For(name string) *url.URL {
	if scope := scopeOf(name); scope != "" {
		if u, ok := r.Scopes[scope]; ok {
			return u
		}
	}
	return r.Default
}

// scopeOf returns the scope of a package name, with its @, or the empty string
// for an unscoped one.
func scopeOf(name string) string {
	if !strings.HasPrefix(name, "@") {
		return ""
	}
	if at := strings.Index(name[1:], "/"); at >= 0 {
		return name[:at+1]
	}
	// A name that starts with @ but has no slash is not a scoped package, it is
	// a malformed one, and it has no scope.
	return ""
}

// D3 reports a package that was resolved from a registry other than the one
// that serves it.
//
// This is dependency confusion. A project that depends on a package by a name
// somebody else can also publish can be attacked by whoever publishes that name
// first. The lockfile records where each package came from, and a package that
// came from somewhere other than the registry that serves it is a package
// whose author is not the one the project chose.
//
// It is Block when the registry configuration is known, because then the
// comparison is against a fact rather than a guess. It is Warn when no
// configuration was found, because the project may be using a registry that
// was not in any of the places we read, and a finding that depends on a
// registry we did not find is not a fact.
//
// ## The shapes a resolved URL can take
//
// The npm documentation is explicit that the field is not always a URL:
//
//	"For registry sources this is path of the tarball relative to the registry
//	 URL. If the tarball URL isn't on the same server as the registry URL then
//	 this is a complete URL. registry.npmjs.org is a magic value meaning 'the
//	 currently configured registry'."
//
// So there are three cases and only one of them is a finding:
//
//   - A complete URL on a host that is not the registry serving this package.
//     That is the finding.
//   - A complete URL on the registry serving this package. That is the package
//     coming from where the project fetches from.
//   - A relative path, or the npmjs.org magic value. npm resolves both against
//     the registry serving the package, so the package comes from where the
//     project fetches from.
//
// A check that compared strings would get all three wrong. It would report the
// relative path and the magic value as findings, and the magic value is what
// every package in a lockfile written against the public registry says, so
// that check would report every package in every repository.
func D3(lock *lockfile.Lockfile, registry Registry, path string) findings.Findings {
	var out findings.Findings

	for _, p := range lock.Packages {
		if p.Resolved == "" {
			// A package with no resolved URL is a local link, a workspace, or
			// something else that is not fetched from a registry at all.
			continue
		}

		host, ok := resolvedHost(p.Resolved)
		if !ok {
			// Not a registry fetch. A git dependency, a local tarball, a file
			// path.
			continue
		}

		// The magic value. npm rewrites this to the registry serving the
		// package, so the lockfile does not say where it came from and there is
		// nothing to compare.
		if isNpmjs(host) {
			continue
		}

		serving := registry.For(p.Name)
		if serving != nil && sameHost(host, serving.Host) {
			continue
		}

		severity := findings.SeverityBlock
		if !registry.Found {
			// The registry this project uses was not in any of the places we
			// looked, so this comparison is against a guess.
			severity = findings.SeverityWarn
		}

		out = append(out, findings.New(
			D3ID,
			severity,
			d3Message(p, host, serving),
			findings.At(path, 0),
		))
	}

	return out
}

// resolvedHost works out which host a resolved URL points at.
//
// It returns false when the value is not a registry fetch at all.
//
// A relative path is not a URL and does not say where anything came from, so
// there is nothing to compare. npm resolves it against the registry serving
// the package.
func resolvedHost(resolved string) (string, bool) {
	if !strings.Contains(resolved, "://") {
		return "", false
	}

	u, err := url.Parse(resolved)
	if err != nil {
		return "", false
	}
	// A scheme that is not http or https is a git, file, or ssh reference,
	// which is not fetched from a registry.
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	return u.Host, true
}

// isNpmjs reports whether a host is the public npm registry.
//
// The registry is a constant, so the URL is parsed once here rather than on
// every call, and the error is impossible: a constant that does not parse
// would be a bug in this file and not a condition to handle.
// isNpmjs reports whether a host is the public npm registry.
func isNpmjs(host string) bool {
	return host == npmjsHost
}

// sameHost reports whether two hosts are the same.
//
// The comparison is on the host and not the whole URL, because the npm registry
// is written with a trailing slash in the documentation and without one in a
// lockfile, and because a registry can have a path that the tarball URL
// repeats.
func sameHost(a, b string) bool {
	return a == b
}

// d3Message explains the finding.
//
// It names the package and both hosts, because "this package came from
// somewhere else" is not actionable and "lodash came from registry.npmjs.org
// rather than npm.pkg.github.com" is.
func d3Message(p lockfile.Package, from string, serving *url.URL) string {
	against := "the registry this project is configured to use"
	if serving != nil {
		against = serving.Host
	}
	return p.Name + " " + p.Version + " was resolved from " + from + ", which is not " + against + ". A " +
		"package fetched from a registry you did not choose is a package you did not review: whoever published " +
		"that name there chose the code that runs, and it runs at install time with this repository's " +
		"credentials in scope. If this package is supposed to come from your own registry, check that the " +
		"registry is configured for this scope, and that the lockfile was written against it."
}
