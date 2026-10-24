package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// commandKind is which subcommand was asked for.
type commandKind int

const (
	kindScan commandKind = iota
	kindDeps
	kindServe
	kindSetup
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

	// registry is the registry the project is configured to use, from the
	// --registry flag. An empty string means none was given, and the registry
	// is discovered from the .npmrc, the environment, and the workflow instead.
	registry string
	// noDiff is set by --no-diff, which skips the checks that need a base
	// commit and runs only the ones that do not.
	noDiff bool

	// serve settings. They are only meaningful for kindServe, and the parser
	// rejects values that cannot work rather than leaving them to fail later.
	addr    string
	workers int
	timeout time.Duration

	// configDir is where setup writes the App key and environment file. It is
	// empty when the caller did not choose one, so setup can fall back to
	// PPE_CONFIG_DIR or the user config directory.
	configDir string
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
	// A bare "ppe" with no arguments is not one of the forms the usage
	// documents, and guessing that it means "scan the current directory" is
	// how a mistyped command line turns into a clean result.
	//
	// The exit code matters more than the message here. Exit 0 means the scan
	// finished and nothing blocks, and a CI step that runs "ppe" where it meant
	// to run "ppe scan ." would read that as a clean repository. So this is an
	// error, and it exits 2 like every other invocation that did not perform a
	// scan.
	if len(args) == 0 {
		return command{}, errors.New("no command given. The commands are scan, deps, serve and setup.")
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
				case "deps":
					cmd.kind = kindDeps
					sawCommand = true
				case "serve":
					cmd.kind = kindServe
					cmd.addr = ":8080"
					cmd.workers = 4
					cmd.timeout = 60 * time.Second
					sawCommand = true
				case "setup":
					cmd.kind = kindSetup
					cmd.addr = "127.0.0.1:8081"
					sawCommand = true
				case "help":
					cmd.kind = kindHelp
					return cmd, nil
				case "version":
					cmd.kind = kindVersion
					return cmd, nil
				default:
					return cmd, fmt.Errorf("unknown command %q. The commands are scan, deps, serve and setup.", arg)
				}
				continue
			}
			cmd.paths = append(cmd.paths, arg)
			continue
		}

		// Split --flag=value once so both spellings work from here on.
		name, value, hasValue := strings.Cut(arg, "=")

		switch name {
		case "-h", "--help":
			cmd.kind = kindHelp
			return cmd, nil
		case "--version":
			cmd.kind = kindVersion
			return cmd, nil
		case "--no-color":
			cmd.noColor = true
		case "--no-diff":
			cmd.noDiff = true
		case "--registry":
			// The registry takes a value, and it is the one flag that does, so
			// the value may be in this token or in the next one.
			if !hasValue {
				if i+1 >= len(args) {
					return cmd, errors.New("--registry needs a value")
				}
				i++
				value = args[i]
			}
			cmd.registry = value
		case "--addr":
			if !hasValue {
				if i+1 >= len(args) {
					return cmd, errors.New("--addr needs a value")
				}
				i++
				value = args[i]
			}
			if strings.TrimSpace(value) == "" {
				return cmd, errors.New("--addr needs a value")
			}
			cmd.addr = value
		case "--workers":
			if !hasValue {
				if i+1 >= len(args) {
					return cmd, errors.New("--workers needs a value")
				}
				i++
				value = args[i]
			}
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return cmd, errors.New("--workers must be a positive integer")
			}
			cmd.workers = n
		case "--timeout":
			if !hasValue {
				if i+1 >= len(args) {
					return cmd, errors.New("--timeout needs a value")
				}
				i++
				value = args[i]
			}
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				return cmd, errors.New("--timeout must be a positive duration, such as 60s")
			}
			cmd.timeout = d
		case "--config-dir":
			if !hasValue {
				if i+1 >= len(args) {
					return cmd, errors.New("--config-dir needs a value")
				}
				i++
				value = args[i]
			}
			if strings.TrimSpace(value) == "" {
				return cmd, errors.New("--config-dir needs a value")
			}
			cmd.configDir = value
		default:
			return cmd, fmt.Errorf("unknown flag %q", name)
		}
	}

	if cmd.kind == kindServe {
		if len(cmd.paths) > 0 || cmd.stdin {
			return cmd, errors.New("serve takes no paths")
		}
		return cmd, nil
	}

	if cmd.kind == kindSetup {
		if len(cmd.paths) > 0 || cmd.stdin {
			return cmd, errors.New("setup takes no paths")
		}
		return cmd, nil
	}

	// No paths means the current directory, resolved by the caller.
	if len(cmd.paths) == 0 && !cmd.stdin {
		cmd.paths = []string{scanDefaults}
	}

	return cmd, nil
}
