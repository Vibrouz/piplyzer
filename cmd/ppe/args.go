package main

import (
	"errors"
	"fmt"
	"strings"
)

// commandKind is which subcommand was asked for.
type commandKind int

const (
	kindScan commandKind = iota
	kindHelp
	kindVersion
)

// command is a fully parsed command line.
//
// Parsed and validated up front rather than at the point of use, so that an
// unknown flag fails before any file is read. Half a scan's output followed by
// "unknown flag" is a bad way to learn that a flag was misspelled.
type command struct {
	kind commandKind

	noColor bool

	// paths are the targets. An empty slice means the current directory, which
	// is resolved later by the caller rather than here so that this stays a pure
	// function of the arguments.
	paths []string
	// stdin is true when a path of "-" appeared, meaning read one workflow from
	// standard input.
	stdin bool
}

// scanDefaults is the current directory, spelled as "." rather than resolved, so
// that the flag handling never touches the filesystem and stays testable.
const scanDefaults = "."

// parseArgs turns an argument vector into a command.
//
// It is a hand written parser rather than flag.NewFlagSet because the argument
// grammar is mixed: paths are positional and repeatable, and flags may appear
// anywhere. The standard FlagSet handles the first two awkwardly and refuses
// flags after the first positional, which is the shape people actually type.
//
// There is deliberately no --format flag. One output format does not need a
// selector, and a flag that accepts a single value is a flag whose only other
// behaviour is to be typed wrong.
func parseArgs(args []string) (command, error) {
	// A bare "ppe" with no arguments is not one of the three forms the usage
	// documents, and guessing that it means "scan the current directory" is
	// how a mistyped command line turns into a clean result.
	//
	// The exit code matters more than the message here. Exit 0 means the scan
	// finished and nothing blocks, and a CI step that runs "ppe" where it meant
	// to run "ppe scan ." would read that as a clean repository. So this is an
	// error, and it exits 2 like every other invocation that did not perform a
	// scan.
	if len(args) == 0 {
		return command{}, errors.New("no command given. The only command is scan.")
	}

	cmd := command{kind: kindScan}
	sawCommand := false

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// A bare "-" is the stdin convention, not a flag.
		if arg == "-" {
			cmd.stdin = true
			continue
		}

		if !strings.HasPrefix(arg, "-") || arg == "-" {
			if !sawCommand {
				switch arg {
				case "scan":
					sawCommand = true
				case "help":
					cmd.kind = kindHelp
					return cmd, nil
				case "version":
					cmd.kind = kindVersion
					return cmd, nil
				default:
					return cmd, fmt.Errorf("unknown command %q. The only command is scan.", arg)
				}
				continue
			}
			cmd.paths = append(cmd.paths, arg)
			continue
		}

		// Split --flag=value once so both spellings work from here on.
		name, _, _ := strings.Cut(arg, "=")

		switch name {
		case "-h", "--help":
			cmd.kind = kindHelp
			return cmd, nil
		case "--version":
			cmd.kind = kindVersion
			return cmd, nil
		case "--no-color":
			cmd.noColor = true
		default:
			return cmd, fmt.Errorf("unknown flag %q", name)
		}
	}

	// No paths means the current directory, resolved by the caller.
	if len(cmd.paths) == 0 && !cmd.stdin {
		cmd.paths = []string{scanDefaults}
	}

	return cmd, nil
}
