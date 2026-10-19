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
//
// The colour decision is made here and passed in, so that the work below does
// not have to know how the decision was reached. That split is what lets a test
// render the coloured report: the decision depends on whether stdout is a
// terminal, and a test's stdout is not one.
func scan(cmd command, stdin io.Reader, stdout, stderr io.Writer) int {
	return runWith(cmd, stdin, stdout, stderr, palette(cmd))
}

// runWith is scan, with the colour decided in advance.
func runWith(cmd command, stdin io.Reader, stdout, stderr io.Writer, c colour) int {
	found, err := collect(cmd, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "usage: %v\n", err)
		return exitIncomplete
	}

	scanned, unchecked, notWorkflows := runAll(found)

	// Files that parsed but are not workflows are counted as skipped, the same
	// as files that never had a workflow extension. The count is the one in the
	// summary line, so the reader can see that something was passed over rather
	// than having to wonder where it went.
	found.skipped[skipNotWorkflow] += notWorkflows

	// Everything on stdout, in one place.
	//
	// Parse errors used to go to stderr alone, which put them below the findings
	// with nothing separating them and made them read as another finding. Two
	// files named boom.yml and bomba.yml, one scanned and one refused, came out
	// looking like a list about one file.
	report(stdout, scanned, unchecked, found, c)

	// A Block outranks an incomplete scan.
	//
	// Both are true when they co-occur, and exit code can only carry one. A
	// confirmed problem is the more actionable news, so reporting 2 there would
	// understate it. The reverse overstates, which is why 2 is only used when
	// nothing blocks: we never hide a finding behind a "the tool was confused".
	if blocks(scanned) > 0 {
		return exitBlocked
	}
	if len(unchecked) > 0 {
		return exitIncomplete
	}
	// Finding no workflows at all is also an incomplete scan.
	//
	// This is the difference between "I looked and there is nothing wrong" and
	// "I looked at nothing". A gate that reports the second as the first is a
	// gate that passes on a mistyped path, on a repository whose workflows live
	// somewhere else, or on a checkout that did not include them. Every one of
	// those is a false clean, and a false clean in a merge gate is worse than a
	// false alarm, because nobody looks at a gate that says the repository is
	// fine.
	//
	// The remedy is the same as for a parse error: run the scan again against
	// the right path. The difference is only in what went wrong.
	if len(scanned) == 0 {
		return exitIncomplete
	}
	return exitOK
}

// blocks counts the Block tier findings across every file.
func blocks(results []checked) int {
	n := 0
	for _, r := range results {
		for _, f := range r.findings {
			if f.Severity.Blocking() {
				n++
			}
		}
	}
	return n
}

// checked is one file that was read, with what the rules made of it and anything
// the parser wants to say about how it read it.
type checked struct {
	path     string
	findings findings.Findings
	notices  []parse.Notice
}

// name prints the path, or <stdin>.
func (c checked) name() string {
	if c.path == "" {
		return "<stdin>"
	}
	return c.path
}

// unreadable is one file that could not be read, and why.
//
// Kept as its own type rather than an error string so that it can be grouped with
// the file it names. An ungrouped error is easy to skim past when the file names
// are similar.
type unreadable struct {
	path string
	// err is the parser's message.
	err error
}

// runAll parses and checks every collected source.
//
// A file that cannot be parsed does not stop the others. One broken workflow
// hiding every problem in the repository is the failure this shape exists to
// avoid.
//
// A file that parses but is not a workflow is neither scanned nor an error. It
// is counted as skipped, the same as a file that never had a workflow
// extension, because counting it as a scanned workflow says the scan looked at
// something it did not look at.
func runAll(found collection) ([]checked, []unreadable, int) {
	var out []checked
	var bad []unreadable
	notWorkflows := 0

	for _, src := range found.sources {
		// The name rather than the path, so a stdin finding renders as
		// "<stdin>:25" instead of "(no file)".
		//
		// The parse error is not wrapped again with the name: ParseFile already
		// puts the path at the front of its message.
		file, err := parse.ParseFile(src.name(), src.data)
		if err != nil {
			bad = append(bad, unreadable{path: src.name(), err: err})
			continue
		}
		if !file.IsWorkflow() {
			notWorkflows++
			continue
		}
		out = append(out, checked{
			path:     src.path,
			findings: rules.NewEngine().Run(file),
			notices:  file.Notices,
		})
	}

	return out, bad, notWorkflows
}

// report writes the whole result: a summary, then what could not be checked,
// then the findings grouped by file.
func report(w io.Writer, scanned []checked, bad []unreadable, found collection, c colour) {
	var warns int
	for _, c := range scanned {
		for _, f := range c.findings {
			if !f.Severity.Blocking() {
				warns++
			}
		}
	}

	nBlocks := blocks(scanned)
	fmt.Fprintf(w, "scanned %d workflow%s, %d block%s, %d warning%s",
		len(scanned), plural(len(scanned), "", "s"),
		nBlocks, plural(nBlocks, "", "s"),
		warns, plural(warns, "", "s"))
	// Skipped files are counted separately from unchecked ones. Those were passed
	// over by choice, usually because they are not workflows at all, and lumping
	// them in with a file we failed to read would make the second look alarming.
	if skipped := found.skippedTotal(); skipped > 0 {
		fmt.Fprintf(w, ", %d other file%s not scanned", skipped, plural(skipped, "", "s"))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	// Unchecked files are reported as their own section, before the findings, and
	// named with their reason.
	//
	// They are not folded into the counts above and not mixed into the finding
	// list, because they are neither: a file that was never read is a gap in the
	// scan, and a reader who cannot tell a gap from a clean result will trust the
	// wrong number.
	if len(bad) > 0 {
		fmt.Fprintf(w, "could not check %d file%s:\n", len(bad), plural(len(bad), "", "s"))
		for _, u := range bad {
			fmt.Fprintf(w, "  %s\n    %v\n", u.path, u.err)
		}
		fmt.Fprintln(w)
	}

	if len(scanned) == 0 {
		if len(bad) == 0 {
			// Nothing was found and nothing failed, which means the scan looked
			// at nothing at all.
			//
			// The wording is the important part. "nothing to check" reads like a
			// clean bill of health, and it is the opposite of one: the scan did
			// not find the workflows it was pointed at, so it says nothing about
			// whether they are safe. The message names that, and the exit code
			// says the same thing, so a CI step that only reads the code and a
			// person reading the output get the same news.
			fmt.Fprintln(w, "no workflows found, so nothing was checked.")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "A directory scan looks for workflows in .github/workflows. If this")
			fmt.Fprintln(w, "repository has workflows somewhere else, point the scan at them")
			fmt.Fprintln(w, "directly, or pipe one in on standard input.")
		}
		return
	}

	// Grouped by file. Block findings first within each file, and files ordered so
	// the same file is never split across the listing.
	for _, group := range groupByFile(scanned) {
		if len(group.findings) == 0 && len(group.notices) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s\n", group.title)

		for _, n := range group.notices {
			fmt.Fprintf(w, "  note    line %-4d %s\n", n.Line, n.Message)
		}
		for _, f := range group.findings {
			tier := "warn"
			if f.finding.Severity.Blocking() {
				tier = "BLOCK"
			}
			// The padding is computed on the visible width, not on the styled
			// string, so the column lines up whether or not colour is on.
			fmt.Fprintf(w, "  %s %s  %s\n",
				padTo(c.tier(tier, f.finding.Severity.Blocking()), 6),
				c.ruleID(f.finding.RuleID),
				f.finding.Location)
			fmt.Fprintf(w, "         %s\n", summarise(f.finding.Message))
		}
		fmt.Fprintln(w)
	}
}

// fileGroup is one file and everything said about it.
type fileGroup struct {
	title    string
	findings []flatFinding
	notices  []parse.Notice
}

// groupByFile collects findings and notices under the file they came from.
//
// Sorting by path rather than by severity across the whole run is deliberate. A
// single flat severity-ordered list separates two files that share a rule ID, and
// a reader cannot tell which file a line belongs to.
func groupByFile(scanned []checked) []fileGroup {
	byPath := map[string]*fileGroup{}
	var order []string

	for _, c := range scanned {
		key := c.name()
		if _, seen := byPath[key]; !seen {
			byPath[key] = &fileGroup{title: key}
			order = append(order, key)
		}
		g := byPath[key]
		g.notices = append(g.notices, c.notices...)
		for _, f := range c.findings {
			g.findings = append(g.findings, flatFinding{path: c.path, finding: f})
		}
	}

	sort.Strings(order)

	groups := make([]fileGroup, 0, len(order))
	for _, key := range order {
		g := byPath[key]
		sortFindings(g.findings)
		groups = append(groups, *g)
	}
	return groups
}

// sortFindings orders one file's findings: Block first, then line, then rule.
func sortFindings(list []flatFinding) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i].finding, list[j].finding
		if a.Severity != b.Severity {
			return a.Severity.Blocking()
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		return a.RuleID < b.RuleID
	})
}

// flatFinding is a finding with the file it came from.
type flatFinding struct {
	path    string
	finding findings.Finding
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
