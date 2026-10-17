package parse

import "sort"

// TriggerSpec is one event in the workflow's on: block.
//
// GitHub writes the same event three ways, and all three have to produce the
// same TriggerSpec, because a rule that reads triggers has no business knowing
// which syntax the author chose:
//
//	on: push
//	on: [push, pull_request]
//	on:
//	  push:
//	    branches: [main]
type TriggerSpec struct {
	// Event is the event name, for example push or pull_request_target.
	Event string
	// Branches and BranchesIgnore are the ref filters for events that take
	// them. Empty means the event is not filtered, which for push is the shape
	// rule 7 looks for.
	Branches       []string
	BranchesIgnore []string
	Paths          []string
	PathsIgnore    []string
	Tags           []string
	TagsIgnore     []string
	// Types filters which activity kinds fire the event, for example
	// [opened, synchronize] on pull_request_target.
	Types []string
	// Line is where the event is written, so a finding can point at it.
	Line int
}

// Triggers is the workflow's on: block.
type Triggers struct {
	// Present is false when the workflow has no on: block at all, which GitHub
	// treats as no triggers. It is kept distinct from an empty block so that
	// "the file never declared triggers" can be reported as its own thing.
	Present bool
	// Specs is one entry per declared event, in document order.
	Specs []TriggerSpec
	Line  int
}

// Has reports whether the workflow declares the given event.
func (t Triggers) Has(event string) bool {
	_, ok := t.Spec(event)
	return ok
}

// Spec returns the declaration of one event.
func (t Triggers) Spec(event string) (TriggerSpec, bool) {
	for _, spec := range t.Specs {
		if spec.Event == event {
			return spec, true
		}
	}
	return TriggerSpec{}, false
}

// Events returns the declared event names, sorted, so that output and tests do
// not depend on the order they were written in.
func (t Triggers) Events() []string {
	events := make([]string, 0, len(t.Specs))
	for _, spec := range t.Specs {
		events = append(events, spec.Event)
	}
	sort.Strings(events)
	return events
}

// Unfiltered reports whether the event has no ref or path filter at all.
//
// An ignore list counts as a filter, and so do tags and so do paths: a push
// that runs only for v* tags, or only when something under docs/ changes, is
// restricted, and calling it an unfiltered push is a false positive. Rule 7
// exists because an unfiltered push runs the workflow for every commit that
// lands anywhere in the repository, which is what a compromised maintainer
// account needs and nothing else does.
func (s TriggerSpec) Unfiltered() bool {
	return len(s.Branches) == 0 && len(s.BranchesIgnore) == 0 &&
		len(s.Tags) == 0 && len(s.TagsIgnore) == 0 &&
		len(s.Paths) == 0 && len(s.PathsIgnore) == 0
}
