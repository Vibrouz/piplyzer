package parse

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// The on: key is a boolean in YAML 1.1, which is how rules 7, 8, and 9 end up
// never firing with no error anywhere. parse matches on the key's node text, and
// this test is where a change in the reader's behavior has to surface.
//
// The assertion has to be about the reader, not about parse. Under a YAML 1.1
// reader the key node's Value becomes "true", so parse would record the key as
// "true", never call triggers(), and drop the block without error. The original
// spelling cannot be recovered from the node, so this test is the only thing
// standing between a dependency upgrade and three silently disarmed rules.
func TestOnKeyIsReadAsText(t *testing.T) {
	var doc yaml.Node
	src := "on:\n  push:\n    branches: [main]\n"
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	root := doc.Content[0]
	key := root.Content[0]
	if key.Value != "on" {
		t.Errorf("on: key parsed as %q, want \"on\". The YAML reader now resolves on as a boolean, so parse will drop the trigger block silently. Fix the reader or the parsing, do not relax this assertion", key.Value)
	}
	if key.Tag == "!!bool" {
		t.Errorf("on: key carries the boolean tag: the reader is resolving YAML 1.1 booleans, and parse matches on the key text, so the whole on: block is about to disappear without an error. Confirm this is intended before accepting this dependency change")
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
