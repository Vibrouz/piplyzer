package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
	"github.com/Vibrouz/whoa/internal/rules"
)

// scan is the entry point for "ppe scan".
//
// It is the seam the rest of the CLI builds on: parsed arguments in, streams out,
// and nothing else it has to know about.
func scan(cmd command, stdin io.Reader, stdout, stderr io.Writer) int {
	found, err := collect(cmd, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "ppe: %v\n", err)
		return exitUsage
	}

	results, errs := runAll(found)

	// Plain text for now. Colour and the JSON writer land in the commits after
	// this one, and both want a single rendering function rather than formatting
	// inline here.
	//
	// Printed even when there were parse errors, because the findings from the
	// files that did parse are real and withholding them would mean one broken
	// workflow hides every problem in the repository with it.
	printPlain(stdout, results, found, len(errs))

	for _, e := range errs {
		fmt.Fprintf(stderr, "ppe: %v\n", e)
	}
	if len(errs) > 0 {
		// A workflow that could not be parsed is a workflow that was not
		// checked, and reporting that as a clean run would be the worst possible
		// answer. It is a usage level failure for now; the exit code question is
		// settled in the next commit.
		return exitUsage
	}

	// Always 0 until the exit code behaviour lands. This commit makes the scan
	// real; it does not yet make it a gate.
	return exitOK
}

// result is one file's findings, kept with the file so that a parse error and a
// finding can be reported against the same path.
type result struct {
	path     string
	findings findings.Findings
}

// name prints the path, or <stdin>.
func (r result) name() string {
	if r.path == "" {
		return "<stdin>"
	}
	return r.path
}

// runAll parses and checks every collected source.
//
// Parse failures are collected rather than returned, so one broken workflow does
// not hide the findings in every other one. They are reported separately because
// they mean something different: a finding is a problem in a file we read, a
// parse error is a file we could not read at all.
func runAll(found collection) ([]result, []error) {
	var out []result
	var errs []error

	for _, src := range found.sources {
		// The name rather than the path, so a stdin finding renders as
		// "<stdin>:25" instead of "(no file)", and a parse error names the input.
		//
		// The parse error is not wrapped again with the name: ParseFile already
		// puts the path at the front of its message, and repeating it produced
		// "broken.yml: broken.yml:5: ...".
		file, err := parse.ParseFile(src.name(), src.data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, result{path: src.path, findings: rules.NewEngine().Run(file)})
	}

	return out, errs
}

// printPlain writes the human readable form.
//
// No colour yet, and no attempt at a layout that survives narrow terminals. What
// is here is the information, grouped so it can be read: a summary, then findings
// in severity order so the ones that block are not below the fold.
func printPlain(w io.Writer, results []result, found collection, unchecked int) {
	var blocks, warns int
	for _, r := range results {
		for _, f := range r.findings {
			if f.Severity.Blocking() {
				blocks++
			} else {
				warns++
			}
		}
	}

	fmt.Fprintf(w, "scanned %d workflow%s", len(results), plural(len(results), "", "s"))
	if skipped := found.skippedTotal(); skipped > 0 {
		fmt.Fprintf(w, ", skipped %d file%s", skipped, plural(skipped, "", "s"))
	}
	// Unchecked is counted separately from skipped. Those files were not passed
	// over by choice, and folding them into the same number would understate a
	// scan that failed on a third of the repository.
	if unchecked > 0 {
		fmt.Fprintf(w, ", %d could not be checked", unchecked)
	}
	fmt.Fprintf(w, "\n%d block%s, %d warning%s", blocks, plural(blocks, "", "s"), warns, plural(warns, "", "s"))
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	if len(results) == 0 {
		fmt.Fprintln(w, "nothing to check.")
		return
	}

	// Severity first, then file, then line. A reader opening this in CI wants the
	// thing that blocks, not the thing that happens to be first in the tree.
	sorted := sortResults(results)
	for _, f := range sorted {
		tier := "warn"
		if f.finding.Severity.Blocking() {
			tier = "BLOCK"
		}
		fmt.Fprintf(w, "%-5s  %s  %s\n", tier, f.finding.RuleID, f.finding.Location)
		fmt.Fprintf(w, "       %s\n", summarise(f.finding.Message))
		fmt.Fprintln(w)
	}
}

// flatFinding is a finding with the file it came from, for sorting and printing.
type flatFinding struct {
	path    string
	finding findings.Finding
}

// sortResults flattens and orders findings by severity, then location.
func sortResults(results []result) []flatFinding {
	var flat []flatFinding
	for _, r := range results {
		for _, f := range r.findings {
			flat = append(flat, flatFinding{path: r.path, finding: f})
		}
	}

	sort.SliceStable(flat, func(i, j int) bool {
		a, b := flat[i].finding, flat[j].finding
		// Block before Warn. Severity has only two values, so this is a
		// comparison and not a rank lookup.
		if a.Severity != b.Severity {
			return a.Severity.Blocking()
		}
		if flat[i].path != flat[j].path {
			return flat[i].path < flat[j].path
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		return a.RuleID < b.RuleID
	})

	return flat
}

// summarise shortens a finding message to its first sentence.
//
// The messages are written as one paragraph, sometimes running to several
// hundred characters, and eleven of them in a row is a wall. The first sentence
// is the claim, which is what a triage reader needs to decide whether to read
// the rest, and the full text is one flag away once the formats exist.
func summarise(message string) string {
	const limit = 110

	// Prefer cutting at a sentence boundary, since a half sentence reads as a bug.
	if i := strings.Index(message, ". "); i > 0 {
		return message[:i+1]
	}
	if len(message) <= limit {
		return message
	}
	cut := strings.LastIndex(message[:limit], " ")
	if cut < limit/2 {
		// No useful space to break on, so cut hard rather than mid rune.
		return strings.TrimRight(message[:limit], " ") + "..."
	}
	return strings.TrimRight(message[:cut], " ") + "..."
}

// plural is a tiny helper so the counts read naturally without pulling in a
// formatting dependency for three call sites.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
