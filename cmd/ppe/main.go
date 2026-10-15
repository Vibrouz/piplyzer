// Command ppe scans GitHub Actions workflows and npm lockfiles for supply chain
// attack patterns, and exits non-zero when it finds something that should block
// a merge.
//
// The scan command itself lands in the CLI phase. This main exists now so the
// module has the layout the plan calls for: cmd/ is glue, internal/ holds
// everything that can be tested without a GitHub runner.
package main

import (
	"fmt"
	"os"
)

// version is overridden at build time with
// -ldflags "-X main.version=$(git describe --tags)".
var version = "dev"

func main() {
	fmt.Fprintf(os.Stderr, "ppe %s: no command implemented yet\n", version)
	fmt.Fprintln(os.Stderr, "usage: ppe scan")
	os.Exit(2)
}