package main

import (
	"errors"
	"fmt"
	"strings"
)

// format selects how findings are rendered.
type format string

const (
	formatHuman format = "human"
	formatJSON  format = "json"
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

	format  format
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
// grammar is mixed: paths are positional and repeatable, flags may appear
// anywhere, and "--format json" and "--format=json" both have to work. The
// standard FlagSet handles the first two awkwardly and refuses flags after the
// first positional, which is the shape people actually type.
func parseArgs(args []string) (command, error) {
	cmd := command{kind: kindScan, format: formatHuman}
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
		name, value, hasValue := strings.Cut(arg, "=")

		// needsValue reads the flag's argument from either the same token or the
		// next one, and refuses to run off the end of the command line.
		needsValue := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", name)
			}
			i++
			return args[i], nil
		}

		switch name {
		case "-h", "--help":
			cmd.kind = kindHelp
			return cmd, nil
		case "--version":
			cmd.kind = kindVersion
			return cmd, nil
		case "--no-color":
			cmd.noColor = true
		case "-f", "--format":
			v, err := needsValue()
			if err != nil {
				return cmd, err
			}
			switch format(v) {
			case formatHuman, formatJSON:
				cmd.format = format(v)
			default:
				return cmd, fmt.Errorf("unknown format %q. Use human or json.", v)
			}
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

// errNotImplemented exists so the scan entry point compiles before the collection
// and reporting layers land. It is removed by the next commit rather than
// lingering, because a stub that survives is a stub that ships.
var errNotImplemented = errors.New("scan not implemented yet")
