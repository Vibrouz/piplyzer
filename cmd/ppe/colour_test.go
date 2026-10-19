package main

import (
	"strings"
	"testing"
)

// The colour decision is the whole of the feature, so it is tested as a pure
// function over its three inputs. None of these tests need a terminal, an
// environment, or a process, which is why the decision takes them as arguments
// rather than reading them itself.

func TestUseColour(t *testing.T) {
	// env is a lookup over a fixed map, so a test says what it means.
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	tests := []struct {
		name        string
		noColor     bool
		environment map[string]string
		isTerminal  bool
		want        bool
		reason      string
	}{
		{
			name:        "terminal and nothing against it",
			environment: map[string]string{},
			isTerminal:  true,
			want:        true,
			reason:      "a terminal with no objection gets colour",
		},
		{
			name:        "not a terminal",
			environment: map[string]string{},
			isTerminal:  false,
			want:        false,
			reason:      "a file or a log gets no escape codes",
		},
		{
			name:        "the flag wins over a terminal",
			noColor:     true,
			environment: map[string]string{},
			isTerminal:  true,
			want:        false,
			reason:      "the flag is the user asking directly",
		},
		{
			name:        "the flag wins over NO_COLOR being absent",
			noColor:     true,
			environment: map[string]string{},
			isTerminal:  false,
			want:        false,
			reason:      "the flag decides regardless of the terminal",
		},
		{
			name:        "NO_COLOR set",
			environment: map[string]string{"NO_COLOR": "1"},
			isTerminal:  true,
			want:        false,
			reason:      "NO_COLOR is honoured even on a terminal",
		},
		{
			name:        "NO_COLOR set to any value",
			environment: map[string]string{"NO_COLOR": "anything"},
			isTerminal:  true,
			want:        false,
			reason:      "the value does not matter, only that it is there",
		},
		{
			name:        "NO_COLOR set but empty",
			environment: map[string]string{"NO_COLOR": ""},
			isTerminal:  true,
			want:        true,
			reason:      "an empty NO_COLOR is treated as unset",
		},
		{
			name:        "NO_COLOR does not override the flag being off",
			noColor:     true,
			environment: map[string]string{"NO_COLOR": "1"},
			isTerminal:  true,
			want:        false,
			reason:      "both signals point the same way",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := useColour(tt.noColor, env(tt.environment), tt.isTerminal)
			if got != tt.want {
				t.Errorf("useColour = %v, want %v: %s", got, tt.want, tt.reason)
			}
		})
	}
}

// The colour is off, so the styled text is the plain text. This is the property
// that lets the report code call the palette unconditionally.
func TestColourOffIsPlainText(t *testing.T) {
	c := colour{on: false}

	if got := c.tier("BLOCK", true); got != "BLOCK" {
		t.Errorf("tier = %q, want plain BLOCK", got)
	}
	if got := c.tier("warn", false); got != "warn" {
		t.Errorf("tier = %q, want plain warn", got)
	}
	if got := c.ruleID("PPE-001"); got != "PPE-001" {
		t.Errorf("ruleID = %q, want plain PPE-001", got)
	}
}

// The colour is on, so the styled text carries the escape codes and still
// contains the word it styles. A reader piping through less -R sees the word,
// and so does a test that looks for it.
func TestColourOnStylesTheTier(t *testing.T) {
	c := colour{on: true}

	block := c.tier("BLOCK", true)
	if !strings.Contains(block, "BLOCK") {
		t.Errorf("the styled block tier lost its text: %q", block)
	}
	if !strings.Contains(block, ansiRed) {
		t.Errorf("the block tier is not red: %q", block)
	}
	if !strings.Contains(block, ansiBold) {
		t.Errorf("the block tier is not bold: %q", block)
	}
	if !strings.HasSuffix(block, ansiReset) {
		t.Errorf("the styled text does not reset: %q", block)
	}

	warn := c.tier("warn", false)
	if !strings.Contains(warn, "warn") {
		t.Errorf("the styled warn tier lost its text: %q", warn)
	}
	if !strings.Contains(warn, ansiYell) {
		t.Errorf("the warn tier is not yellow: %q", warn)
	}
	if strings.Contains(warn, ansiBold) {
		t.Errorf("the warn tier is bold, which is reserved for BLOCK: %q", warn)
	}
}

// The rule ID is dimmed rather than highlighted, since it is reference material
// and not signal.
func TestColourOnDimsTheRuleID(t *testing.T) {
	c := colour{on: true}

	got := c.ruleID("PPE-001")
	if !strings.Contains(got, "PPE-001") {
		t.Errorf("the styled rule ID lost its text: %q", got)
	}
	if !strings.Contains(got, ansiDim) {
		t.Errorf("the rule ID is not dimmed: %q", got)
	}
	if strings.Contains(got, ansiRed) {
		t.Errorf("the rule ID is coloured as a tier: %q", got)
	}
}

// The padding has to be computed on the visible width. A %-6s applied to a
// styled string pads the escape sequences too, and the column comes out wrong,
// which is the bug this function exists to prevent.
func TestPadToUsesVisibleWidth(t *testing.T) {
	c := colour{on: true}

	padded := padTo(c.tier("warn", false), 6)
	if got := visibleWidth(padded); got != 6 {
		t.Errorf("visible width = %d, want 6: %q", got, padded)
	}

	// And the same word without colour pads to the same visible width, so the
	// column does not move when colour is switched on.
	plain := padTo("warn", 6)
	if got := visibleWidth(plain); got != 6 {
		t.Errorf("visible width = %d, want 6: %q", got, plain)
	}
	if visibleWidth(padded) != visibleWidth(plain) {
		t.Errorf("the column moves when colour is on: %q vs %q", padded, plain)
	}
}

// A word longer than the field is not truncated and not padded.
func TestPadToLeavesLongTextAlone(t *testing.T) {
	got := padTo("PPE-001-long", 6)
	if got != "PPE-001-long" {
		t.Errorf("padTo = %q, want the text unchanged", got)
	}
}

// visibleWidth measures the text a reader sees, which is the text without the
// escape sequences.
func TestVisibleWidth(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"plain", "warn", 4},
		{"empty", "", 0},
		{"styled", ansiYell + "warn" + ansiReset, 4},
		{"two styled", ansiBold + ansiRed + "BLOCK" + ansiReset, 5},
		{"dimmed", ansiDim + "PPE-001" + ansiReset, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := visibleWidth(tt.in); got != tt.want {
				t.Errorf("visibleWidth(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// The escape sequences this file emits must not change the width of the text
// they wrap. If they did, the report columns would move.
func TestColourDoesNotChangeTheVisibleText(t *testing.T) {
	c := colour{on: true}

	if visibleWidth(c.tier("BLOCK", true)) != visibleWidth("BLOCK") {
		t.Error("the styled block tier is a different width from the plain one")
	}
	if visibleWidth(c.ruleID("PPE-001")) != visibleWidth("PPE-001") {
		t.Error("the styled rule ID is a different width from the plain one")
	}
}
