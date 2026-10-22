package main

import (
	"fmt"
	"io"

	"github.com/Vibrouz/whoa/internal/engine"
	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/lockfile"
)

// deps is the entry point for "ppe deps".
//
// It is a separate command from "ppe scan" rather than a flag on it, because
// the two read different things and can fail in different ways. A scan reads
// workflow files and needs a directory that holds them. A dependency check
// reads a lockfile and needs a repository, because the checks that matter most
// compare the lockfile against the one at the base commit, and a lockfile on
// its own says nothing about what changed.
//
// The work itself is in the engine, so that the webhook server can run the same
// checks on a tarball. What stays here is the part that is about the command
// line: choosing a directory, printing, and turning a result into an exit code.
//
// The exit codes are the same as the scan's, for the same reason. Zero means
// the check finished and nothing blocks. One means something blocks. Two means
// the check did not finish, and its result says nothing either way.
func depsCommand(cmd command, stdout, stderr io.Writer, env func(string) string) int {
	dir := "."
	if len(cmd.paths) > 0 {
		dir = cmd.paths[0]
	}

	rep, err := engine.CheckDeps(dir, engine.DepsOptions{
		Registry: cmd.registry,
		NoDiff:   cmd.noDiff,
		Env:      env,
	})
	if err != nil {
		fmt.Fprintf(stderr, "ppe: %v\n", err)
		return exitIncomplete
	}

	// The reason is printed, because a check that could not run must not look
	// like a check that passed. A silent skip here would be a clean result for
	// a scan that did not happen.
	for _, reason := range rep.Skips {
		fmt.Fprintf(stderr, "ppe: %s\n", reason)
	}

	reportDeps(stdout, rep.Findings, rep.Lockfile, dir)
	return depsExit(rep.Findings)
}

// reportDeps writes the result.
//
// It is the same shape as the workflow report, so a reader who has seen one
// knows the other.
func reportDeps(w io.Writer, found findings.Findings, lock *lockfile.Lockfile, dir string) {
	var warns int
	for _, f := range found {
		if !f.Severity.Blocking() {
			warns++
		}
	}
	blocks := 0
	for _, f := range found {
		if f.Severity.Blocking() {
			blocks++
		}
	}

	fmt.Fprintf(w, "checked %d dependenc%s, %d block%s, %d warning%s",
		len(lock.Packages), plural(len(lock.Packages), "y", "ies"),
		blocks, plural(blocks, "", "s"),
		warns, plural(warns, "", "s"))
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	if len(found) == 0 {
		fmt.Fprintln(w, "nothing to report.")
		return
	}

	for _, f := range found {
		tier := "warn"
		if f.Severity.Blocking() {
			tier = "BLOCK"
		}
		fmt.Fprintf(w, "  %-6s %s  %s\n", tier, f.RuleID, f.Location)
		fmt.Fprintf(w, "         %s\n", summarise(f.Message))
	}
}

// depsExit is the exit code for a dependency check.
//
// A Block outranks an incomplete scan, for the same reason the workflow scan
// does it: a confirmed problem is the more actionable news, and reporting
// "could not complete" there would understate it.
func depsExit(found findings.Findings) int {
	for _, f := range found {
		if f.Severity.Blocking() {
			return exitBlocked
		}
	}
	return exitOK
}
