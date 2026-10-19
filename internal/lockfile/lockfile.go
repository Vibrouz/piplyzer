// Package lockfile reads an npm lockfile into a normalised form.
//
// The normalised form is the security control, not tidiness. A package-lock.json
// in a real repository is thousands of lines, and a single line in it changing
// from "hasInstallScript": false to true is invisible in a raw diff: the diff
// is enormous and the one line that matters is somewhere in the middle of it.
// Normalised to one entry per package, the same change is a line in a list of
// packages, next to every other package, and a reviewer sees it.
//
// This package reads and normalises. It does not judge: what counts as a new
// package, and what a resolved URL means, are decisions that belong to the
// checks in internal/deps.
package lockfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Package is one dependency, as the lockfile describes it.
//
// The fields are the ones the checks need. Everything else in a lockfile entry
// is either a checksum, a licence, or metadata about the platform, and none of
// it changes what the checks decide.
type Package struct {
	// Name is the package name, without a version.
	//
	// A lockfile does not store it for most entries, so it is derived from the
	// path. The derivation is the part after the last "node_modules/", which is
	// the name npm itself uses, and it is why a package nested under another
	// ("node_modules/a/node_modules/b") is named "b" and not "a".
	Name string

	// Version is the version that was resolved.
	Version string

	// Resolved is where the tarball came from, as the lockfile wrote it.
	//
	// It is not always a URL, and it is not always a URL on the registry that
	// is configured. See Resolved for the shapes it takes.
	Resolved string

	// HasInstallScript is whether the package runs a program at install time.
	//
	// The three states are not decoration. A lockfile that does not record the
	// field at all cannot say the package has no install script, and treating
	// that as "no" would be a silent false negative on the check that blocks
	// malware.
	HasInstallScript TriState

	// Dev is whether the package is only in the development dependency tree.
	//
	// It is recorded rather than acted on. A dev dependency is still installed
	// and still runs its install script, so it is not less dangerous, but a
	// reader is allowed to know which tree it came from.
	Dev bool

	// Path is the lockfile key the entry was under, which is the full
	// installation path. Two entries can have the same name at different paths,
	// which is how npm expresses a version conflict.
	Path string
}

// TriState is a value that can be true, false, or unknown.
//
// It exists for one field. hasInstallScript is absent from a lockfile that
// predates npm 7, and absent there means "this lockfile does not say", not
// "this package has no install script". A two-value bool cannot hold that
// distinction, and the distinction is the difference between a check that works
// and a check that silently passes.
type TriState int

const (
	// Unknown means the lockfile does not record the value.
	Unknown TriState = iota
	// Absent means the lockfile records the value and it is false.
	Absent
	// Present means the lockfile records the value and it is true.
	Present
)

// Bool returns the value, and whether it was known.
func (t TriState) Bool() (value bool, known bool) {
	switch t {
	case Present:
		return true, true
	case Absent:
		return false, true
	default:
		return false, false
	}
}

// String renders the state for output.
func (t TriState) String() string {
	switch t {
	case Present:
		return "yes"
	case Absent:
		return "no"
	default:
		return "unknown"
	}
}

// Lockfile is a parsed package-lock.json.
//
// The packages are sorted by path, so two runs over the same lockfile produce
// the same output in the same order. A map would not, and a diff that
// reorders itself between runs is a diff nobody reads.
type Lockfile struct {
	// Version is the lockfileVersion field.
	//
	// It decides what the lockfile can answer. Version 1 has a nested
	// dependencies tree and does not record hasInstallScript at all. Version 2
	// and later have a flat packages map and do.
	Version int

	// Packages are the dependencies, sorted by path.
	Packages []Package

	// Name is the project's own name, from the lockfile.
	Name string
}

// Get returns the package at the given path.
func (l *Lockfile) Get(path string) (Package, bool) {
	for _, p := range l.Packages {
		if p.Path == path {
			return p, true
		}
	}
	return Package{}, false
}

// Parse reads a package-lock.json.
//
// It reads the format npm writes and nothing else. A file that is not JSON, or
// that is JSON but not a lockfile, is an error rather than an empty lockfile,
// because an empty lockfile is indistinguishable from a clean one and a
// dependency check that silently checks nothing is worse than no check.
func Parse(data []byte) (*Lockfile, error) {
	var raw struct {
		Name            string                     `json:"name"`
		Version         string                     `json:"version"`
		LockfileVersion int                        `json:"lockfileVersion"`
		Packages        map[string]json.RawMessage `json:"packages"`
		Dependencies    map[string]json.RawMessage `json:"dependencies"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("not a JSON file: %w", err)
	}

	// A file with no lockfileVersion is not a lockfile.
	//
	// This is the check that separates a lockfile from any other JSON file, and
	// it matters more than it looks. Without it, a JSON file that happens to
	// have no packages in it parses as a lockfile with no dependencies, and a
	// dependency check over an empty lockfile reports nothing and looks like a
	// clean result. Every real lockfile has the field, including the one npm
	// writes for a project with no dependencies at all.
	if raw.LockfileVersion == 0 {
		return nil, errors.New("not a package-lock.json: it has no lockfileVersion")
	}

	lock := &Lockfile{
		Version: raw.LockfileVersion,
		Name:    raw.Name,
	}

	// The packages map is the modern form and the dependencies tree is the
	// legacy one. A version 2 or 3 lockfile has both, and the packages map is
	// the one to read, because it is flat and carries the fields the checks
	// need. A version 1 lockfile has only the tree.
	switch {
	case len(raw.Packages) > 0:
		if err := lock.readPackages(raw.Packages); err != nil {
			return nil, err
		}
	case len(raw.Dependencies) > 0:
		if err := lock.readDependencies(raw.Dependencies, ""); err != nil {
			return nil, err
		}
	default:
		// A lockfile with no packages at all. An empty project has one, and it
		// is a real answer, so this is not an error.
		return lock, nil
	}

	sort.Slice(lock.Packages, func(i, j int) bool {
		return lock.Packages[i].Path < lock.Packages[j].Path
	})
	return lock, nil
}

// readPackages reads the flat packages map of a version 2 or 3 lockfile.
func (l *Lockfile) readPackages(entries map[string]json.RawMessage) error {
	for path, entry := range entries {
		// The root entry, keyed by the empty string, is the project itself and
		// not a dependency of it.
		if path == "" {
			continue
		}

		var e struct {
			Version          string `json:"version"`
			Resolved         string `json:"resolved"`
			HasInstallScript *bool  `json:"hasInstallScript"`
			Dev              bool   `json:"dev"`
		}
		if err := json.Unmarshal(entry, &e); err != nil {
			return fmt.Errorf("package %q: %w", path, err)
		}

		p := Package{
			Name:     nameFromPath(path),
			Version:  e.Version,
			Resolved: e.Resolved,
			Dev:      e.Dev,
			Path:     path,
		}
		p.HasInstallScript = l.installScriptState(e.HasInstallScript)
		l.Packages = append(l.Packages, p)
	}
	return nil
}

// installScriptState turns an absent or present hasInstallScript field into a
// tri-state.
//
// On a version 2 or later lockfile the field is authoritative, so absent means
// false. On a version 1 lockfile the field does not exist at all, so absent
// means unknown, and reading it as false would be a silent false negative on
// the check that blocks install-time malware.
func (l *Lockfile) installScriptState(field *bool) TriState {
	if l.Version < 2 {
		return Unknown
	}
	if field == nil || !*field {
		return Absent
	}
	return Present
}

// readDependencies reads the nested dependencies tree of a version 1 lockfile.
//
// The tree is a hierarchy rather than a flat list, so the path has to be built
// as it descends. The same package can appear at several paths, once per
// version of it that npm had to install.
func (l *Lockfile) readDependencies(entries map[string]json.RawMessage, prefix string) error {
	for name, entry := range entries {
		var e struct {
			Version          string                     `json:"version"`
			Resolved         string                     `json:"resolved"`
			HasInstallScript *bool                      `json:"hasInstallScript"`
			Dev              bool                       `json:"dev"`
			Dependencies     map[string]json.RawMessage `json:"dependencies"`
		}
		if err := json.Unmarshal(entry, &e); err != nil {
			return fmt.Errorf("package %q: %w", name, err)
		}

		path := prefix + "node_modules/" + name
		p := Package{
			Name:     name,
			Version:  e.Version,
			Resolved: e.Resolved,
			Dev:      e.Dev,
			Path:     path,
		}
		p.HasInstallScript = l.installScriptState(e.HasInstallScript)
		l.Packages = append(l.Packages, p)

		// The recursion can fail. A nested entry that is not an object is only
		// detected when it is unmarshalled, which happens here.
		if err := l.readDependencies(e.Dependencies, path+"/"); err != nil {
			return err
		}
	}
	return nil
}

// nameFromPath derives a package name from a lockfile path.
//
// The name is what comes after the last "node_modules/". A path with no
// "node_modules/" in it is not a package path at all, and the whole path is
// returned rather than an empty name, because an empty name would sort and
// display as nothing.
func nameFromPath(path string) string {
	if at := strings.LastIndex(path, "node_modules/"); at >= 0 {
		return path[at+len("node_modules/"):]
	}
	return path
}
