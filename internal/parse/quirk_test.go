package parse

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// The on: key is a boolean in YAML 1.1, which is how rules 7, 8, and 9 end up
// never firing with no error anywhere. parse reads keys as node text, so the
// block parses whatever the reader resolves, and this test is where a change in
// the reader's behavior has to surface.
//
// A YAML 1.1 reader sends this block through with the key spelled true. If that
// ever happens here, parse is still correct because it never looks at the tag,
// but confirm that is still deliberate before accepting the dependency change:
// a reader that also folded the trigger body would not be.
func TestOnKeyIsReadAsText(t *testing.T) {
	var doc yaml.Node
	src := "on:\n  push:\n    branches: [main]\n"
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	root := doc.Content[0]
	key := root.Content[0]
	if key.Value != "on" {
		t.Errorf("on: key parsed as %q, want \"on\". If the YAML reader now resolves on as a boolean (YAML 1.1), parse still reads keys as text, but confirm that is still intended.", key.Value)
	}
	if key.Tag == "!!bool" {
		t.Errorf("on: key carries the boolean tag: parse reads the key as text so triggers still parse, but confirm that is still intended before accepting this dependency change")
	}

	file, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !file.Triggers.Has("push") {
		t.Error("push trigger not found: the whole block was dropped")
	}
}

func TestQuotedOnKeyParsesTheSame(t *testing.T) {
	// Some authors quote it, for exactly the reason above. Both spellings have
	// to reach the same place.
	for _, src := range []string{"on:\n  push:\n    branches: [main]\n", "\"on\":\n  push:\n    branches: [main]\n"} {
		file, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		if !file.Triggers.Has("push") {
			t.Errorf("Parse(%q) lost the push trigger", src)
		}
	}
}
