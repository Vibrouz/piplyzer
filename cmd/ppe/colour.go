package main

import (
	"os"
	"strings"
)

// The colour decision, and the codes it applies.
//
// Three signals decide whether the output carries escape codes, and they are
// checked in this order:
//
//  1. --no-color on the command line, which wins over everything.
//  2. NO_COLOR in the environment, set to any non-empty value.
//  3. Whether stdout is a terminal.
//
// The third is the one that does the real work and the one that is easiest to
// leave out. A CI log and a redirected file are not terminals, and a stream of
// escape codes in either is noise that a reader has to see past, and in a
// captured log it is worse than noise because it is stored that way. A tool
// that colours a file it wrote to disk has made the file harder to read for
// whoever opens it next.
//
// NO_COLOR is treated as present-and-non-empty, which is the common reading of
// the informal standard. An empty NO_COLOR is treated as unset, so
// NO_COLOR= does not silently disable colour for a shell that exports it empty.
//
// All three inputs are passed in rather than read from the environment inside
// this file, so that every branch is reachable from a test. A decision function
// that read os.Getenv and os.Stdout itself could only be tested by mutating
// the process, which is a test that depends on what else ran first.

// ANSI escape sequences.
//
// Only the tier words and the rule ID are coloured. The message body and the
// location are not, and the reason is that the message is truncated to its first
// sentence so a reader can scan the claim rather than the prose. Colour on a
// run of truncated prose reads as noise, and the message is the one part of the
// line where a reader is expected to read words rather than scan for a shape.
//
// The sequences are the standard SGR ones: reset, bold, dim, and the foreground
// colours. There is no 256-colour or truecolour use, because a CI log renders
// on whatever the reader's terminal happens to be, and the eight basic colours
// are the ones that survive that.
const (
	ansiReset = "\x1b[0m"
	ansiDim   = "\x1b[2m"
	ansiRed   = "\x1b[31m"
	ansiBold  = "\x1b[1m"
	ansiYell  = "\x1b[33m"
)

// useColour decides whether the output should be coloured.
//
// noColorFlag is the value of the --no-color flag, env is the environment
// lookup, and isTerminal says whether stdout is a terminal.
func useColour(noColorFlag bool, env func(string) string, isTerminal bool) bool {
	if noColorFlag {
		return false
	}
	if env("NO_COLOR") != "" {
		return false
	}
	return isTerminal
}

// stdoutIsTerminal reports whether stdout is a terminal.
//
// This uses os.Stdout.Stat and the ModeCharDevice bit rather than a syscall,
// because the bit is in the standard library and a dependency that exists only
// to ask this one question is not worth the module. The check is best effort:
// when the stat fails the answer is false, and a stream we cannot identify is
// treated as a file, which is the safe direction since it means no escape codes
// in anything we cannot reason about.
func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// colour is the styling applied to the report.
//
// The zero value is usable and means no colour at all, so the report code does
// not need to know whether colour is on: it asks the palette for a style and
// gets plain text back when colour is off. That keeps the conditional out of
// the formatting code, where a missed branch would show up as a stray escape
// sequence rather than as a missing one.
type colour struct {
	on bool
}

// tier styles a severity word, which is the one thing that has to be scannable
// at a glance.
//
// BLOCK is bold as well as red, because it is the one word in the output that
// means a merge is being stopped, and a reader scanning a wall of findings
// should find it without reading. The tier words are padded to the same width
// as each other, so the column still lines up.
func (c colour) tier(word string, blocking bool) string {
	if !c.on {
		return word
	}
	if blocking {
		return ansiBold + ansiRed + word + ansiReset
	}
	return ansiYell + word + ansiReset
}

// ruleID styles a rule identifier, which is reference material rather than
// signal, so it is dimmed rather than highlighted.
func (c colour) ruleID(id string) string {
	if !c.on {
		return id
	}
	return ansiDim + id + ansiReset
}

// palette is the colour decision for one run.
func palette(cmd command) colour {
	return colour{on: useColour(cmd.noColor, os.Getenv, stdoutIsTerminal())}
}

// padTo pads a styled string to a visible width.
//
// The padding is applied to the visible text, not to the styled one, because a
// %-6s on a string that carries escape sequences pads the escape sequences too
// and the column comes out wrong. This strips the sequences to measure the
// visible width and puts the padding inside the style, so the styled result is
// still the whole field.
//
// The sequences this knows about are the ones this file emits. A more general
// implementation would strip any CSI sequence, and this one would then be wrong
// for a colour it did not add, which is the right way for it to be wrong: it
// cannot silently mismeasure output it did not produce.
func padTo(s string, width int) string {
	visible := visibleWidth(s)
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

// visibleWidth is the length of s with the ANSI escape sequences removed.
//
// A CSI sequence is ESC, then '[', then parameter bytes, then a final byte. The
// parameter bytes are 0x30 to 0x3f and the final byte is 0x40 to 0x7e, and the
// distinction matters: '[' is itself 0x5b, which is inside the final byte
// range, so a parser that ends the sequence at the first byte in that range
// stops at the bracket and counts the rest of the sequence as visible text.
//
// The sequence therefore ends only at a final byte that is reached after the
// parameter bytes, which is what this tracks.
func visibleWidth(s string) int {
	var b strings.Builder
	b.Grow(len(s))

	const (
		esc = 0x1b
		csi = 0x5b
	)

	inEscape := false
	inCSI := false
	for _, r := range s {
		switch {
		case inEscape:
			// The byte right after ESC decides the kind of sequence.
			inEscape = false
			if r == csi {
				inCSI = true
			}
		case inCSI:
			// Parameter bytes and intermediate bytes continue the sequence.
			// Anything from 0x40 up is the final byte and ends it.
			if r >= 0x40 && r <= 0x7e {
				inCSI = false
			}
		case r == esc:
			inEscape = true
		default:
			b.WriteRune(r)
		}
	}

	return len([]rune(b.String()))
}
