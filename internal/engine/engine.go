// Package engine turns files into findings.
//
// It is deliberately separate from the command line and from GitHub. The CLI,
// the composite action and the webhook server all end up here, and none of
// them should be able to change what a finding means by how they were invoked.
package engine

import (
	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
	"github.com/Vibrouz/whoa/internal/rules"
)

// Source is one file waiting to be parsed.
type Source struct {
	// Path is how the file is named in output. Empty for standard input, which
	// has no path of its own.
	Path string
	// Data is the raw file content.
	Data []byte
}

// Name returns something printable whether or not the source has a path.
func (s Source) Name() string {
	if s.Path == "" {
		return "<stdin>"
	}
	return s.Path
}

// File is one workflow that was read, with what the rules made of it and
// anything the parser wants to say about how it read it.
type File struct {
	Path     string
	Findings findings.Findings
	Notices  []parse.Notice
}

// Unreadable is one file that could not be parsed, and why.
//
// Kept as its own type rather than an error string so that it can be grouped
// with the file it names. An ungrouped error is easy to skim past when the file
// names are similar.
type Unreadable struct {
	Path string
	Err  error
}

// Report is the result of scanning a set of sources.
type Report struct {
	Files        []File
	Unchecked    []Unreadable
	NotWorkflows int
}

// Scanned is how many files were read and checked as workflows.
func (r Report) Scanned() int { return len(r.Files) }

// Blocks counts the Block tier findings across every file.
func (r Report) Blocks() int {
	n := 0
	for _, f := range r.Files {
		n += f.Findings.Count(findings.SeverityBlock)
	}
	return n
}

// Warnings counts the findings that are not blocking.
func (r Report) Warnings() int {
	n := 0
	for _, f := range r.Files {
		n += f.Findings.Count(findings.SeverityWarn)
	}
	return n
}

// Scan parses and checks every source.
//
// A file that cannot be parsed does not stop the others. One broken workflow
// hiding every problem in the repository is the failure this shape exists to
// avoid.
//
// A file that parses but is not a workflow is neither scanned nor an error. It
// is counted as skipped, because counting it as a scanned workflow says the
// scan looked at something it did not look at.
func Scan(sources []Source, repo parse.Repository) Report {
	var out []File
	var bad []Unreadable
	notWorkflows := 0

	for _, src := range sources {
		// The name rather than the path, so a stdin finding renders as
		// "<stdin>:25" instead of "(no file)".
		//
		// The parse error is not wrapped again with the name: ParseFile already
		// puts the path at the front of its message.
		//
		// The repository is passed in when the caller knows it, so that rule 10
		// can tell a reference to this repository from a reference to a third
		// party one. It is zero for a scan of a bare directory, and the rule
		// says so in its message rather than guessing.
		var file *parse.File
		var err error
		if repo.IsZero() {
			file, err = parse.ParseFile(src.Name(), src.Data)
		} else {
			file, err = parse.ParseWorkflow(src.Name(), repo, src.Data)
		}
		if err != nil {
			bad = append(bad, Unreadable{Path: src.Name(), Err: err})
			continue
		}
		if !file.IsWorkflow() {
			notWorkflows++
			continue
		}
		out = append(out, File{
			Path:     src.Path,
			Findings: rules.NewEngine().Run(file),
			Notices:  file.Notices,
		})
	}

	return Report{Files: out, Unchecked: bad, NotWorkflows: notWorkflows}
}
