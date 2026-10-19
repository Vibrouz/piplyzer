package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseArgsDefaults(t *testing.T) {
	cmd, err := parseArgs([]string{"scan"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cmd.kind != kindScan {
		t.Errorf("kind = %v, want scan", cmd.kind)
	}
	if cmd.noColor {
		t.Error("colour should be on by default")
	}
	if cmd.stdin {
		t.Error("stdin should be off by default")
	}
	// No paths means the current directory, as a relative name so that parsing
	// never touches the filesystem.
	if len(cmd.paths) != 1 || cmd.paths[0] != scanDefaults {
		t.Errorf("paths = %v, want [%s]", cmd.paths, scanDefaults)
	}
}

// The argument grammar is what people actually type, so the shapes below are the
// ones worth pinning: flags before and after paths, both flag spellings, and a
// bare "-" among the paths.
//
// wantPaths is compared exactly, and the default of "." is spelled out in each
// case rather than implied, so a case that stops defaulting fails loudly instead
// of passing against an empty expectation.
func TestParseArgsGrammar(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantPath  []string
		wantStdin bool
		noColor   bool
	}{
		{
			name:     "paths before flags",
			args:     []string{"scan", "a", "b", "--no-color"},
			wantPath: []string{"a", "b"},
			noColor:  true,
		},
		{
			name:     "flags before paths",
			args:     []string{"scan", "--no-color", "a", "b"},
			wantPath: []string{"a", "b"},
			noColor:  true,
		},
		{
			name:     "equals form",
			args:     []string{"scan", "--no-color=true", "a"},
			wantPath: []string{"a"},
			noColor:  true,
		},
		{
			// --no-color takes no value, so this also covers a flag that is
			// followed by something which looks like its argument.
			name:     "flag after every path",
			args:     []string{"scan", "a", "b", "c", "--no-color"},
			wantPath: []string{"a", "b", "c"},
			noColor:  true,
		},
		{
			// An equals form on a boolean flag is accepted and ignored, since
			// there is no value to disagree with.
			name:     "boolean equals form",
			args:     []string{"scan", "--no-color=true"},
			wantPath: []string{scanDefaults},
			noColor:  true,
		},
		{
			name:      "stdin among paths",
			args:      []string{"scan", "-", "a"},
			wantPath:  []string{"a"},
			wantStdin: true,
		},
		{
			// stdin alone means no default path. Reading the workflow from a pipe
			// and scanning "." as well would be surprising, and the two would
			// produce findings the caller did not ask for.
			name:      "stdin only",
			args:      []string{"scan", "-"},
			wantPath:  nil,
			wantStdin: true,
		},
		{
			name:      "stdin with an explicit path too",
			args:      []string{"scan", "-", "a", "b"},
			wantPath:  []string{"a", "b"},
			wantStdin: true,
		},
		{
			name:     "no color",
			args:     []string{"scan", "--no-color"},
			wantPath: []string{scanDefaults},
			noColor:  true,
		},
		{
			name:     "a path that looks like a flag needs ./",
			args:     []string{"scan", "./-weird"},
			wantPath: []string{"./-weird"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parseArgs(tt.args)
			if err != nil {
				t.Fatalf("parseArgs(%v): %v", tt.args, err)
			}
			if cmd.stdin != tt.wantStdin {
				t.Errorf("stdin = %v, want %v", cmd.stdin, tt.wantStdin)
			}
			if cmd.noColor != tt.noColor {
				t.Errorf("noColor = %v, want %v", cmd.noColor, tt.noColor)
			}
			if len(cmd.paths) != len(tt.wantPath) {
				t.Fatalf("paths = %v, want %v", cmd.paths, tt.wantPath)
			}
			for i := range tt.wantPath {
				if cmd.paths[i] != tt.wantPath[i] {
					t.Errorf("path %d = %q, want %q", i, cmd.paths[i], tt.wantPath[i])
				}
			}
		})
	}
}

func TestParseArgsHelpAndVersion(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want commandKind
	}{
		{[]string{"scan", "--help"}, kindHelp},
		{[]string{"scan", "-h"}, kindHelp},
		{[]string{"--help"}, kindHelp},
		{[]string{"help"}, kindHelp},
		{[]string{"scan", "--version"}, kindVersion},
		{[]string{"--version"}, kindVersion},
		{[]string{"version"}, kindVersion},
	} {
		cmd, err := parseArgs(tt.args)
		if err != nil {
			t.Errorf("parseArgs(%v): %v", tt.args, err)
			continue
		}
		if cmd.kind != tt.want {
			t.Errorf("parseArgs(%v) kind = %v, want %v", tt.args, cmd.kind, tt.want)
		}
	}
}

// Every rejection has to name the thing that was wrong, because the person
// reading it is in a CI log and will not know which flag they mistyped.
func TestParseArgsRejects(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown command", []string{"scanx"}, "unknown command"},
		{"unknown flag", []string{"scan", "--nope"}, "unknown flag"},
		// The format flag is gone rather than reduced to one value, so passing it
		// is now an unknown flag. A caller who has a --format in a script finds
		// out immediately instead of silently getting the one format there is.
		{"the removed format flag", []string{"scan", "--format", "json"}, "unknown flag"},
		{"the removed short format flag", []string{"scan", "-f", "json"}, "unknown flag"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseArgs(tt.args)
			if err == nil {
				t.Fatalf("parseArgs(%v) succeeded, want an error", tt.args)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// run is the whole command as a function, so the dispatch and the exit codes are
// testable without a subprocess.
func TestRunDispatch(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantExit int
		wantOut  string
	}{
		{"help exits clean", []string{"--help"}, exitOK, "usage:"},
		{"version exits clean", []string{"--version"}, exitOK, "ppe "},
		{"bad flag is a usage error", []string{"scan", "--nope"}, exitIncomplete, "unknown flag"},
		{"unknown command is a usage error", []string{"nope"}, exitIncomplete, "unknown command"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(tt.args, strings.NewReader(""), &stdout, &stderr)
			if got != tt.wantExit {
				t.Errorf("exit = %d, want %d", got, tt.wantExit)
			}
			// Help and version go to stdout, errors to stderr. Mixing them means
			// `ppe --help | less` prints an error.
			combined := stdout.String() + stderr.String()
			if !strings.Contains(combined, tt.wantOut) {
				t.Errorf("output = %q, want it to contain %q", combined, tt.wantOut)
			}
		})
	}
}

// Help on stdout, errors on stderr. A CI log shows both, but a piped --help must
// not have an error line in it.
func TestRunHelpGoesToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, strings.NewReader(""), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "usage:") {
		t.Errorf("stdout = %q, want the usage text", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want nothing", stderr.String())
	}
}
