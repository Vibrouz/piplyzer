// Command ppe scans GitHub Actions workflows for supply chain attack patterns,
// and exits non-zero when it finds something that should block a merge.
//
// The scan is a pure function over the text of a workflow. Nothing here runs a
// workflow, resolves an action, or calls the GitHub API, because a tool that
// fetches the thing it is inspecting cannot be reasoned about from its output.
// Every claim it makes is a claim about text that is in the repository.
//
// main is thin on purpose. Everything that can be tested without a process sits in
// run, which takes its arguments and its streams as values, so the whole command
// is exercisable from a test with no filesystem and no subprocess.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is overridden at build time with
// -ldflags "-X main.version=$(git describe --tags)".
var version = "dev"

// Exit codes.
//
// Zero is the important one: a scanner that exits non-zero for a Warn teaches
// everyone to ignore its output, and then the Block results stop being read too.
// A Warn is information. A Block is a decision.
const (
	// exitOK means nothing blocked. Warn findings may still have been printed.
	exitOK = 0
	// exitBlocked means at least one finding is Block tier.
	exitBlocked = 1
	// exitIncomplete means the scan did not finish: either the command line was
	// wrong, or a workflow could not be parsed and was therefore never checked.
	//
	// One code for both, because the two have the same consequence and the same
	// remedy: the scan needs to be run again before its result means anything.
	// They are told apart by the message rather than the code, so a reader who
	// mistook one for the other is corrected immediately instead of spending an
	// afternoon looking for a command line problem that is not there.
	//
	// Distinct from exitBlocked so a scan that found a problem is never reported
	// as one that merely failed to run.
	exitIncomplete = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is main, with its inputs as parameters.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "ppe: %v\n\n", err)
		usage(stderr)
		return exitIncomplete
	}

	switch cmd.kind {
	case kindHelp:
		usage(stdout)
		return exitOK
	case kindVersion:
		fmt.Fprintf(stdout, "ppe %s\n", version)
		return exitOK
	case kindScan:
		return scan(cmd, stdin, stdout, stderr)
	case kindDeps:
		return depsCommand(cmd, stdout, stderr)
	}

	// parseArgs only returns the kinds above, so reaching here means the parser
	// and this switch have drifted, which is a bug rather than a user error.
	fmt.Fprintf(stderr, "ppe: internal error, unhandled command kind %d\n", cmd.kind)
	return exitIncomplete
}

func usage(w io.Writer) {
	fmt.Fprint(w, `ppe scans GitHub Actions workflows for supply chain attack patterns,
and the npm dependencies they pull in.

usage:
  ppe scan [flags] [path...]
  ppe deps [flags] [path...]
  ppe --help
  ppe --version

commands:
  scan      scan workflows and exit non-zero if anything blocks
  deps      check the npm lockfile and exit non-zero if anything blocks

Running ppe with no command is an error rather than a scan of the current
directory, so that a mistyped command line cannot be read as a clean result.

flags:
      --no-color              never colour the output
      --no-diff               deps only: skip the checks that need a base commit
      --registry <url>        deps only: the registry this project is configured
                               to use, instead of discovering it
      --version               print the version
  -h, --help                  print this help

arguments:
  path    a file, or a directory to search for workflows. Repeatable.
          Defaults to the current directory. A path of - reads one workflow
          from standard input, which is how this runs against a workflow that
          has not been written to disk yet.

  For deps, the path is the repository to check, and it needs a
  package-lock.json in it.

exit codes:
  0  the check finished and nothing blocks. Warn findings may still be printed.
  1  at least one Block finding. This is the merge gate.
  2  the check did not finish: the command line was wrong, a file could not
     be read, or nothing was found to check. The result is not trustworthy
     either way.
`)
}
