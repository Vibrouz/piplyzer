package parse

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Error is a workflow that could not be parsed, located in the file.
//
// Parse errors are reported rather than swallowed. A scanner that skips the
// files it cannot read is a scanner an attacker can hide behind by making a
// file unreadable, so an unparseable workflow has to fail the scan instead of
// counting as clean.
type Error struct {
	// Path is the file the caller passed in, empty when unknown.
	Path string
	// Line is the 1-based line the problem is on, or 0 when the underlying
	// reader did not report one.
	Line int
	Msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", e.location(), e.Line, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.location(), e.Msg)
}

func (e *Error) location() string {
	if e.Path == "" {
		return "workflow"
	}
	return e.Path
}

// yamlLocation matches the line reference in an error from the YAML reader,
// which reads either "yaml: line 3: ..." or, when it aggregates several
// problems, "yaml: unmarshal errors:\n  line 3: ...".
var yamlLocation = regexp.MustCompile(`line (\d+): (.*)`)

// wrap converts a reader error into a located parse Error, pulling the line out
// of the message so callers get the same shape whichever layer failed.
func (p *parser) wrap(err error) error {
	var typed *yaml.TypeError
	msg := err.Error()
	line := 0
	if m := yamlLocation.FindStringSubmatch(msg); m != nil {
		line, _ = strconv.Atoi(m[1])
		msg = m[2]
	}
	if errors.As(err, &typed) && len(typed.Errors) > 1 {
		msg = fmt.Sprintf("%s (and %d more problems in this file)", msg, len(typed.Errors)-1)
	}
	return &Error{Path: p.path, Line: line, Msg: msg}
}

func (p *parser) errf(line int, format string, args ...any) error {
	return &Error{Path: p.path, Line: line, Msg: fmt.Sprintf(format, args...)}
}
