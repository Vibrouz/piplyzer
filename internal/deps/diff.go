package deps

import (
	"sort"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/lockfile"
)

// ---------------------------------------------------------------- D1 and D2

// D1ID is the rule identifier for a new package.
const D1ID = "DEP-D1"

// D2ID is the rule identifier for an install script that appeared.
const D2ID = "DEP-D2"

// D1D2ID is the rule identifier for a new package that also runs an install
// script.
//
// It is its own identifier rather than D2's because filtering by a rule ID has
// to mean something. If a new package with an install script reported as D2,
// then asking for D1 alone would miss the case worth looking at, and one
// package would produce two findings for one condition.
const D1D2ID = "DEP-D1D2"

// Diff compares a base lockfile with the one in the working tree.
//
// The base is the lockfile at the commit the pull request is based on, and the
// head is the one in the tree. A package is judged by the difference between
// them, because a package that was already there has already been reviewed and
// a package that is new has not.
//
// It returns the findings for D1 and D2. A nil base means there is nothing to
// compare against, which is a skip rather than a finding: a pull request that
// adds a lockfile has every package reading as new, and reporting all of them
// would be noise rather than signal.
//
// ## What counts as a new package
//
// A package is new when its path is not in the base lockfile.
//
// The path, not the name and version, because a version bump is the most
// ordinary thing in a lockfile and it must not read as a new package. Lodash
// going from 4.17.20 to 4.17.21 is a dependency update, and if that were a new
// package then every dependency bump in every pull request would be a finding
// and the check would be switched off.
//
// A new path is a new package. A typosquat is a new name and therefore a new
// path. A transitive dependency that arrived through a dependency's own
// dependency tree is a new path. Both are what D1 is for.
//
// The one thing this counts as new that is not: a package that moved. If a
// dependency was nested and is now hoisted, its path changed and it reads as
// new. That is rare, it is a Warn, and the message names the package so a
// reader can see that it is the same one.
//
// ## What counts as an install script appearing
//
// The same path in both lockfiles, with no install script in the base and one
// in the head.
//
// The same path is the same install location, so the comparison is between the
// two versions of one package. A package that went from no script to a script
// between versions is doing something new at install time, and that is the
// shape the finding is about.
//
// A new package is not a flip. There is no base version of it to have gained
// anything, so it is D1, or D1D2 when it also runs a script.
//
// ## The version floor
//
// hasInstallScript is only recorded from lockfileVersion 2, which is npm 7.
// On a version 1 lockfile the field does not exist, so the base cannot say
// whether a package had a script, and D2 cannot say whether one appeared.
//
// A version 1 base skips D2 entirely. Reading the absent field as false would
// be a silent false negative on the check that blocks install-time malware,
// which is the worst kind of wrong this tool can be.
func Diff(base *lockfile.Lockfile, head *lockfile.Lockfile, headPath string) findings.Findings {
	var out findings.Findings

	if base == nil {
		return nil
	}

	basePaths := map[string]bool{}
	for _, p := range base.Packages {
		basePaths[p.Path] = true
	}

	// The findings are collected and sorted, because the packages come out of
	// the lockfile in path order but a reader wants the most serious first.
	type pending struct {
		pkg      lockfile.Package
		isNew    bool
		scripted bool
	}
	var items []pending

	for _, p := range head.Packages {
		isNew := !basePaths[p.Path]
		hasScript, known := p.HasInstallScript.Bool()
		if !isNew {
			// The same path in the base. The question is whether the script
			// appeared, and that needs the base to be able to say.
			if !known || !hasScript {
				continue
			}
			// The path is in the base, because it is not new, so this cannot
			// fail.
			basePkg, _ := base.Get(p.Path)
			baseScript, baseKnown := basePkg.HasInstallScript.Bool()
			if !baseKnown || baseScript {
				// Either the base cannot say, which is the version floor, or
				// the base already had a script, so nothing appeared.
				continue
			}
		}
		items = append(items, pending{pkg: p, isNew: isNew, scripted: hasScript && known})
	}

	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		// A package that runs an install script comes first, because it is the
		// one that executes code at install time.
		if a.scripted != b.scripted {
			return a.scripted
		}
		return a.pkg.Path < b.pkg.Path
	})

	for _, item := range items {
		switch {
		case item.isNew && item.scripted:
			out = append(out, findings.New(
				D1D2ID,
				findings.SeverityBlock,
				d1d2Message(item.pkg),
				findings.At(headPath, 0),
			))
		case item.isNew:
			out = append(out, findings.New(
				D1ID,
				findings.SeverityWarn,
				d1Message(item.pkg),
				findings.At(headPath, 0),
			))
		case item.scripted:
			out = append(out, findings.New(
				D2ID,
				findings.SeverityBlock,
				d2Message(item.pkg),
				findings.At(headPath, 0),
			))
		}
	}

	return out
}

// d1Message explains a new package.
//
// It says the package is new and names it, and it says what a new package is
// worth looking at, because a new package is not a finding on its own. It is a
// finding because a name that looks like another name is how a dependency
// chain delivers code nobody chose.
func d1Message(p lockfile.Package) string {
	return p.Name + " " + p.Version + " is new in this change, and it was not in the base lockfile. A new " +
		"package is how a typosquat arrives: a name that looks like a package you already depend on, " +
		"published to the registry so that a dependency of a dependency resolves to it. The package is " +
		"installed and its code runs during the install, before anything in this repository has had a " +
		"chance to be reviewed."
}

// d2Message explains an install script that appeared.
//
// The distinction that matters is between a package that always had a script
// and one that gained one. The first is a known quantity, because it was in
// the base lockfile and anyone who looked at the dependency saw it. The second
// is new code that will run during the install.
func d2Message(p lockfile.Package) string {
	return p.Name + " " + p.Version + " now runs an install script, and the version in the base lockfile did " +
		"not. An install script is a program that runs during npm install, with the repository's " +
		"credentials in scope, before any of this repository's own code has run. A package that gained one " +
		"between versions is doing something new at install time, and the diff is the only place that is " +
		"visible."
}

// d1d2Message explains a new package that also runs an install script.
//
// It supersedes both D1 and D2 for this package, and the message says so, so
// a reader who expects a D1 and a D2 for it does not go looking for them.
func d1d2Message(p lockfile.Package) string {
	return p.Name + " " + p.Version + " is new in this change and it runs an install script. This is the " +
		"highest-signal shape a lockfile change can have, and it reports as one finding rather than two: " +
		"it is a package nobody has reviewed, and it is a package whose code runs during the install, " +
		"with the repository's credentials in scope, before any of this repository's own code has run. A " +
		"typosquat published to the registry, reached through a dependency of a dependency, does exactly " +
		"this."
}
