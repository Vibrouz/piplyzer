package parse

// mergeKey is the YAML merge key, `<<:`.
//
// Actions does not support merge keys: the keys behind one never reach the
// runner. They are skipped rather than merged, so a workflow that writes one
// is parsed exactly as the runner will see it. Merging them here would put
// content in front of the rules that the workflow does not actually run, which
// is a false positive on a file that is already misconfigured.
const mergeKey = "<<"

// Value is one entry of a workflow mapping whose values are plain scalars: a
// step's with: inputs, a job's env:, or the entries of a permissions: block.
type Value struct {
	Name string
	// Text is the scalar as written. It is never type converted, so
	// "fetch-depth: 0" reads back as "0" and not as the number zero cast to
	// some string form, and a step that compares an input against a literal
	// compares the thing the workflow author actually wrote.
	Text string
	Line int
}

// Values is an ordered set of scalar entries.
//
// Ordered rather than a map: Go randomizes map iteration, so a check that walks
// env: or with: and emits a finding per entry would produce findings in a
// different order on every run of the same repository.
type Values []Value

// Get returns the entry with the given name. Lookup is by exact name, which is
// how GitHub matches step inputs and job environment variables.
func (v Values) Get(name string) (Value, bool) {
	for _, entry := range v {
		if entry.Name == name {
			return entry, true
		}
	}
	return Value{}, false
}

// Has reports whether the entry exists, regardless of its value.
func (v Values) Has(name string) bool {
	_, ok := v.Get(name)
	return ok
}

// Len returns the number of entries.
func (v Values) Len() int { return len(v) }
