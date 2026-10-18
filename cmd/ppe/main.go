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
	// exitUsage means the command line was wrong. Distinct from exitBlocked so a
	// broken CI invocation is not mistaken for a clean scan that found a problem.
	exitUsage = 2
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
		return exitUsage
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
	}

	// parseArgs only returns the kinds above, so reaching here means the parser
	// and this switch have drifted, which is a bug rather than a user error.
	fmt.Fprintf(stderr, "ppe: internal error, unhandled command kind %d\n", cmd.kind)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprint(w, `ppe scans GitHub Actions workflows for supply chain attack patterns.

usage:
  ppe scan [flags] [path...]
  ppe --help
  ppe --version

commands:
  scan      scan workflows and exit non-zero if anything blocks

flags:
  -f, --format <human|json>   output format (default human)
      --no-color              never colour the output
      --version               print the version
  -h, --help                  print this help

arguments:
  path    a file, or a directory to search for workflows. Repeatable.
          Defaults to the current directory. A path of - reads one workflow
          from standard input, which is how this runs against a workflow that
          has not been written to disk yet.

exit codes:
  0  nothing blocks. Warn findings may still have been printed.
  1  at least one Block finding. This is the merge gate.
  2  the command line was wrong.
`)
}
