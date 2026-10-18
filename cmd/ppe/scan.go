package main

import (
	"fmt"
	"io"
)

// scan is the entry point for "ppe scan".
//
// This is the seam the rest of the CLI builds on: it has parsed arguments and the
// streams, and nothing else. The collection, execution and reporting layers all
// land behind it one at a time.
func scan(cmd command, stdin io.Reader, stdout, stderr io.Writer) int {
	fmt.Fprintf(stderr, "ppe scan: %v\n", errNotImplemented)
	fmt.Fprintf(stderr, "  format:  %s\n", cmd.format)
	fmt.Fprintf(stderr, "  paths:   %v\n", cmd.paths)
	if cmd.stdin {
		fmt.Fprintf(stderr, "  stdin:   yes\n")
	}
	if cmd.noColor {
		fmt.Fprintf(stderr, "  colour:  off\n")
	}
	return exitUsage
}
