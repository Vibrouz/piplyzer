// Package parse turns a GitHub Actions workflow file into Go structures.
//
// Parsing only. Nothing here decides whether anything is dangerous: that is
// internal/rules, which is why this package keeps structure the rules depend on
// instead of collapsing it. Each of the following is a way a plausible looking
// parser compiles, passes a naive test, and silently misses the real thing, and
// each has a test here:
//
//   - `on:` is a YAML 1.1 boolean. Keys are read as node text and never as
//     resolved booleans, so `on: push` stays a trigger instead of becoming
//     `true: push`.
//   - `run:` is a block scalar as often as it is a single line. Run values are
//     resolved and joined, so rules match one string rather than re-reading the
//     raw source a line at a time.
//   - `uses:` appears at step level, at job level for reusable workflow calls,
//     and at workflow level. All three are walked.
//   - `permissions:` at workflow level is inherited by jobs that do not declare
//     their own. PermissionsFor resolves the chain.
//   - Steps belong to jobs. Job.Steps is the grouping that decides whether
//     fetch-depth: 0 and git log -p are in the same job.
//
// A file either parses completely or returns an error. There is no partially
// parsed workflow, because a rule that skips the part it could not read is a
// bypass, and a half populated File would make that the default rather than an
// exceptional case.
package parse

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// File is one parsed workflow file.
type File struct {
	// Path is the file the workflow was read from, as the caller passed it in.
	// Empty when the caller used Parse rather than ParseFile.
	Path string
	// Repository is the owner/name the workflow belongs to, when the caller
	// knows it. GitHub sets GITHUB_REPOSITORY on every run, so this is filled
	// in CI and empty for a scan of a bare directory.
	//
	// It lives on File rather than in a rule argument because every rule takes
	// a single workflow, and rule 10 has to tell a reference to this repository
	// from a reference to a third party one.
	Repository Repository
	Name       string
	Triggers   Triggers
	// Permissions is the workflow level block, nil when there is none. Jobs
	// inherit it.
	Permissions *Permissions
	// Env is the workflow level environment, inherited by every job.
	Env Values
	// Uses holds workflow level uses: references. GitHub's workflow schema has
	// no top level uses: key, but a file that has one is not a file to silently
	// drop a reference from: rule 1 and rule 10 walk it alongside the step and
	// job locations so that an unfamiliar shape cannot hide a mutable ref.
	Uses []UsesRef
	// Jobs are in document order. A map would lose it, and job order decides
	// output order.
	Jobs []Job
}

// Repository identifies the GitHub repository a workflow belongs to.
type Repository struct {
	Owner string
	Name  string
}

// String returns "owner/name", or the empty string when unknown.
func (r Repository) String() string {
	if r.Owner == "" && r.Name == "" {
		return ""
	}
	return r.Owner + "/" + r.Name
}

// IsZero reports whether the repository is unknown.
func (r Repository) IsZero() bool { return r.Owner == "" && r.Name == "" }

// Job returns a job by its ID.
func (f *File) Job(id string) (Job, bool) {
	for _, job := range f.Jobs {
		if job.ID == id {
			return job, true
		}
	}
	return Job{}, false
}

// PermissionsFor returns the permissions block that governs a job: the job's
// own block if it has one, otherwise the workflow level block.
//
// ok is false when neither is declared. That is the case rule 11 has to resolve
// against the repository default, and the reason a missing job block is not by
// itself an unrestricted job.
func (f *File) PermissionsFor(jobID string) (Permissions, bool) {
	if job, ok := f.Job(jobID); ok && job.Permissions != nil {
		return *job.Permissions, true
	}
	if f.Permissions != nil {
		return *f.Permissions, true
	}
	return Permissions{}, false
}

// Job is one entry of the jobs: mapping.
type Job struct {
	// ID is the key the job is written under, which is how a finding names it
	// and how needs: refers to it.
	ID   string
	Line int
	Name string
	// If is the job level condition, with the line it is on.
	If     string
	IfLine int
	// Permissions is the job level block, nil when the job inherits the
	// workflow level one.
	Permissions *Permissions
	// RunsOn is kept faithful but is not read by any v1 rule.
	RunsOn RunsOn
	Env    Values
	// Uses is set for a reusable workflow call, jobs.<id>.uses. It is a
	// different shape from a step action: it runs another workflow's jobs
	// rather than one action, and it is the more dangerous of the two because
	// the code it pulls in lives in a repository we do not scan.
	Uses *UsesRef
	// With are the inputs of a reusable workflow call, jobs.<id>.with. Same
	// idea as a step's with: and parsed the same way.
	With  Values
	Steps []Step
}

// Step is one entry of a job's steps: list.
type Step struct {
	// Index is the 0-based position in the job, for correlating facts about
	// the same step inside a rule.
	Index int
	// Number is the 1-based position, which is what findings report, so that no
	// rule has to remember which of the two it is holding.
	Number int
	// Line is where the step starts.
	Line int
	// ID is a stable identifier, jobID/step/N by position. Positional rather
	// than derived from the name because renaming a step must not change the
	// identity of a finding, and because names are not unique.
	ID string
	// Name is the step's name: for output a human can act on.
	Name     string
	NameLine int
	If       string
	IfLine   int
	// Uses is the action this step runs, nil for a run: step.
	Uses *UsesRef
	// With are the action inputs and Env the step environment, both resolved to
	// text.
	With Values
	Env  Values
	// Run is the script this step executes, with block scalars already joined.
	// Rules match this string. Matching the raw source line by line misses
	// every script written as `run: |` followed by indented lines, which is
	// how most real scripts are written.
	Run string
	// RunLine is the first line of the run value, so that a finding about
	// something inside a multi line script points at the script rather than at
	// the run: key above it.
	RunLine int
	// Shell is the shell: override, when set.
	Shell string
}

// RunLineAt maps a byte offset within Run back to a line in the source file, so
// that a match inside a multi line script points at the line the match is on.
//
// Exact for literal block scalars and for values that fit on one line. A folded
// scalar (run: >) joins its lines as it is parsed, so the mapping is approximate
// for those and returns a line near the start of the block.
func (s *Step) RunLineAt(offset int) int {
	if s.RunLine == 0 || offset < 0 || offset > len(s.Run) {
		return s.RunLine
	}
	return s.RunLine + strings.Count(s.Run[:offset], "\n")
}

// RunsOn is a job's runs-on, which GitHub accepts as a scalar, a list, or a
// matrix mapping. Only one of the three fields is ever set.
type RunsOn struct {
	Line   int
	Scalar string
	List   []string
	Matrix *Matrix
}

// Matrix is a runs-on mapping, in practice a strategy matrix. Its entries are
// ordinary workflow YAML, so a version entry can be a list and an include
// entry can be a nested mapping. No v1 rule reads a runner label, but the whole
// block still has to survive parsing: a strategy matrix is common enough that
// refusing it would mean refusing to scan a large share of real repositories.
type Matrix struct {
	Line    int
	Entries []MatrixEntry
}

// Get returns one entry of the matrix.
func (m *Matrix) Get(name string) (MatrixEntry, bool) {
	if m == nil {
		return MatrixEntry{}, false
	}
	for _, entry := range m.Entries {
		if entry.Name == name {
			return entry, true
		}
	}
	return MatrixEntry{}, false
}

// MatrixEntry is one key of a matrix block. Exactly one of Text, List, and
// Nested is set.
type MatrixEntry struct {
	Name   string
	Text   string
	List   []string
	Nested *Matrix
	Line   int
}

// Parse parses a workflow from bytes. File.Path is left empty.
func Parse(data []byte) (*File, error) { return ParseFile("", data) }

// ParseFile parses a workflow from bytes and records where it came from, so
// that findings built from it name a file.
func ParseFile(path string, data []byte) (*File, error) {
	p := &parser{path: path}
	root, err := p.root(data)
	if err != nil {
		return nil, err
	}
	file := &File{Path: path}
	if err := p.file(root, file); err != nil {
		return nil, err
	}
	return file, nil
}

// ParseWorkflow is ParseFile for callers that already have a Repository to
// attach, which is every run inside GitHub Actions.
func ParseWorkflow(path string, repo Repository, data []byte) (*File, error) {
	file, err := ParseFile(path, data)
	if err != nil {
		return nil, err
	}
	file.Repository = repo
	return file, nil
}

type parser struct {
	path string
}

// root decodes the single YAML document a workflow file is allowed to be.
func (p *parser) root(data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, p.errf(0, "no YAML document: the file is empty or only comments")
		}
		return nil, p.wrap(err)
	}

	// A second document is silently ignored by decoding only the first, which
	// would mean scanning part of a file and reporting the whole file as clean.
	var second yaml.Node
	switch err := decoder.Decode(&second); {
	case err == nil:
		return nil, p.errf(second.Line, "multiple YAML documents: a workflow file is one mapping, not a document stream")
	case errors.Is(err, io.EOF):
	default:
		return nil, p.wrap(err)
	}

	if len(doc.Content) == 0 {
		return nil, p.errf(0, "no YAML document: the file is empty")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, p.errf(root.Line, "workflow must be a mapping of keys, got %s", kindName(root.Kind))
	}
	if alias := findAlias(root); alias != nil {
		return nil, p.errf(alias.Line,
			"YAML alias: the workflow resolves through an anchor, so the parsed file would not be the file that runs")
	}
	return root, nil
}

func (p *parser) file(root *yaml.Node, file *File) error {
	pairs, err := p.pairs(root, "workflow")
	if err != nil {
		return err
	}
	for _, entry := range pairs {
		switch entry.key {
		case "name":
			if file.Name, err = p.text(entry.val, "name"); err != nil {
				return err
			}
		case "on":
			if file.Triggers, err = p.triggers(entry.val); err != nil {
				return err
			}
		case "permissions":
			if file.Permissions, err = p.permissions(entry.val, PermissionLevelWorkflow); err != nil {
				return err
			}
		case "env":
			if file.Env, err = p.values(entry.val, "env"); err != nil {
				return err
			}
		case "uses":
			uses, err := p.uses(entry.val)
			if err != nil {
				return err
			}
			file.Uses = append(file.Uses, uses)
		case "jobs":
			if file.Jobs, err = p.jobs(entry.val); err != nil {
				return err
			}
		}
		// run-name, defaults, and concurrency are valid workflow keys that no
		// v1 rule reads. Unknown keys are ignored so that a workflow using a
		// feature ppe has not heard of still parses.
	}
	return nil
}

func (p *parser) jobs(node *yaml.Node) ([]Job, error) {
	pairs, err := p.pairs(node, "jobs")
	if err != nil {
		return nil, err
	}
	jobs := make([]Job, 0, len(pairs))
	for _, entry := range pairs {
		job := Job{ID: entry.key, Line: entry.keyNode.Line}
		if !p.isNull(entry.val) {
			if err := p.job(entry.val, &job); err != nil {
				return nil, err
			}
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (p *parser) job(node *yaml.Node, job *Job) error {
	pairs, err := p.pairs(node, "job "+job.ID)
	if err != nil {
		return err
	}
	for _, entry := range pairs {
		switch entry.key {
		case "name":
			if job.Name, err = p.text(entry.val, "job "+job.ID+" name"); err != nil {
				return err
			}
		case "if":
			if job.If, err = p.text(entry.val, "job "+job.ID+" if"); err != nil {
				return err
			}
			job.IfLine = entry.val.Line
		case "permissions":
			if job.Permissions, err = p.permissions(entry.val, PermissionLevelJob); err != nil {
				return err
			}
		case "runs-on":
			if job.RunsOn, err = p.runsOn(entry.val); err != nil {
				return err
			}
		case "env":
			if job.Env, err = p.values(entry.val, "job "+job.ID+" env"); err != nil {
				return err
			}
		case "uses":
			uses, err := p.uses(entry.val)
			if err != nil {
				return err
			}
			job.Uses = &uses
		case "with":
			if job.With, err = p.values(entry.val, "job "+job.ID+" with"); err != nil {
				return err
			}
		case "steps":
			if job.Steps, err = p.steps(entry.val, job.ID); err != nil {
				return err
			}
		}
		// needs, strategy, container, services, outputs, defaults, concurrency,
		// and secrets are not read by any v1 rule.
	}
	return nil
}

func (p *parser) steps(node *yaml.Node, jobID string) ([]Step, error) {
	if p.isNull(node) {
		return nil, nil
	}
	if node.Kind != yaml.SequenceNode {
		return nil, p.errf(node.Line, "job %s steps must be a list, got %s", jobID, kindName(node.Kind))
	}

	steps := make([]Step, 0, len(node.Content))
	for i, item := range node.Content {
		step := Step{Index: i, Number: i + 1, Line: item.Line, ID: stepID(jobID, i+1)}
		if p.isNull(item) {
			return nil, p.errf(item.Line, "step %d of job %s is empty", step.Number, jobID)
		}
		pairs, err := p.pairs(item, fmt.Sprintf("step %d of job %s", step.Number, jobID))
		if err != nil {
			return nil, err
		}
		for _, entry := range pairs {
			switch entry.key {
			case "name":
				if step.Name, err = p.text(entry.val, "step name"); err != nil {
					return nil, err
				}
				step.NameLine = entry.val.Line
			case "if":
				if step.If, err = p.text(entry.val, "step if"); err != nil {
					return nil, err
				}
				step.IfLine = entry.val.Line
			case "uses":
				uses, err := p.uses(entry.val)
				if err != nil {
					return nil, err
				}
				step.Uses = &uses
			case "with":
				if step.With, err = p.values(entry.val, fmt.Sprintf("step %d of job %s with", step.Number, jobID)); err != nil {
					return nil, err
				}
			case "env":
				if step.Env, err = p.values(entry.val, fmt.Sprintf("step %d of job %s env", step.Number, jobID)); err != nil {
					return nil, err
				}
			case "shell":
				if step.Shell, err = p.text(entry.val, "shell"); err != nil {
					return nil, err
				}
			case "run":
				if step.Run, err = p.text(entry.val, "run"); err != nil {
					return nil, err
				}
				step.RunLine = runSource(entry.val)
			}
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// runSource returns the line the run script starts on. For a block scalar that
// is the line after the run: key, because the key is followed by a | and then
// the indented script, so pointing at the key would point one line above
// everything the rule matched.
func runSource(node *yaml.Node) int {
	if node.Style == yaml.LiteralStyle || node.Style == yaml.FoldedStyle {
		return node.Line + 1
	}
	return node.Line
}

func (p *parser) runsOn(node *yaml.Node) (RunsOn, error) {
	runs := RunsOn{Line: node.Line}
	switch {
	case p.isNull(node):
	case node.Kind == yaml.ScalarNode:
		runs.Scalar = node.Value
	case node.Kind == yaml.SequenceNode:
		list, err := p.list(node, "runs-on")
		if err != nil {
			return RunsOn{}, err
		}
		runs.List = list
	case node.Kind == yaml.MappingNode:
		matrix, err := p.matrix(node)
		if err != nil {
			return RunsOn{}, err
		}
		runs.Matrix = matrix
	default:
		return RunsOn{}, p.errf(node.Line, "runs-on must be a value, a list, or a matrix mapping, got %s", kindName(node.Kind))
	}
	return runs, nil
}

// matrix reads a mapping whose values may themselves be lists or mappings.
func (p *parser) matrix(node *yaml.Node) (*Matrix, error) {
	matrix := &Matrix{Line: node.Line}
	pairs, err := p.pairs(node, "runs-on matrix")
	if err != nil {
		return nil, err
	}
	for _, entry := range pairs {
		item := MatrixEntry{Name: entry.key, Line: entry.val.Line}
		switch {
		case p.isNull(entry.val):
		case entry.val.Kind == yaml.ScalarNode:
			item.Text = entry.val.Value
		case entry.val.Kind == yaml.SequenceNode:
			if item.List, err = p.list(entry.val, "runs-on."+entry.key); err != nil {
				return nil, err
			}
		case entry.val.Kind == yaml.MappingNode:
			if item.Nested, err = p.matrix(entry.val); err != nil {
				return nil, err
			}
		default:
			return nil, p.errf(entry.val.Line, "runs-on.%s must be a value, a list, or a mapping, got %s", entry.key, kindName(entry.val.Kind))
		}
		matrix.Entries = append(matrix.Entries, item)
	}
	return matrix, nil
}

func (p *parser) uses(node *yaml.Node) (UsesRef, error) {
	target, err := p.text(node, "uses")
	if err != nil {
		return UsesRef{}, err
	}
	if strings.TrimSpace(target) == "" {
		return UsesRef{}, p.errf(node.Line, "uses is empty")
	}
	return UsesRef{Target: target, Line: node.Line, Column: node.Column}, nil
}

type pair struct {
	key     string
	keyNode *yaml.Node
	val     *yaml.Node
}

// pairs returns the entries of a mapping node in document order.
//
// A duplicate key is an error rather than last-one-wins. Two YAML readers that
// disagree about which duplicate wins is a parser differential, and the loser
// of that disagreement is whichever one this gate happens to run, which is
// exactly the reader an attacker would want to disagree with.
func (p *parser) pairs(node *yaml.Node, what string) ([]pair, error) {
	if p.isNull(node) {
		return nil, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, p.errf(node.Line, "%s must be a mapping, got %s", what, kindName(node.Kind))
	}

	out := make([]pair, 0, len(node.Content)/2)
	firstSeen := make(map[string]int, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode, valNode := node.Content[i], node.Content[i+1]
		if keyNode.Kind != yaml.ScalarNode {
			return nil, p.errf(keyNode.Line, "%s has a non scalar key", what)
		}
		if first, duplicate := firstSeen[keyNode.Value]; duplicate {
			return nil, p.errf(keyNode.Line, "duplicate key %q in %s, first defined on line %d", keyNode.Value, what, first)
		}
		firstSeen[keyNode.Value] = keyNode.Line
		out = append(out, pair{key: keyNode.Value, keyNode: keyNode, val: valNode})
	}
	return out, nil
}

// text returns a scalar exactly as written, without type conversion.
func (p *parser) text(node *yaml.Node, what string) (string, error) {
	if node.Kind != yaml.ScalarNode {
		return "", p.errf(node.Line, "%s must be a single value, got %s", what, kindName(node.Kind))
	}
	return node.Value, nil
}

// list returns a scalar as a one element list, or a sequence as itself. GitHub
// accepts both forms wherever a list is allowed.
func (p *parser) list(node *yaml.Node, what string) ([]string, error) {
	switch {
	case p.isNull(node):
		return nil, nil
	case node.Kind == yaml.ScalarNode:
		return []string{node.Value}, nil
	case node.Kind == yaml.SequenceNode:
		out := make([]string, 0, len(node.Content))
		for i, item := range node.Content {
			text, err := p.text(item, fmt.Sprintf("%s[%d]", what, i))
			if err != nil {
				return nil, err
			}
			out = append(out, text)
		}
		return out, nil
	default:
		return nil, p.errf(node.Line, "%s must be a value or a list, got %s", what, kindName(node.Kind))
	}
}

// values returns a mapping of scalars as an ordered set of entries.
func (p *parser) values(node *yaml.Node, what string) (Values, error) {
	pairs, err := p.pairs(node, what)
	if err != nil {
		return nil, err
	}
	out := make(Values, 0, len(pairs))
	for _, entry := range pairs {
		text, err := p.text(entry.val, what+"."+entry.key)
		if err != nil {
			return nil, err
		}
		out = append(out, Value{Name: entry.key, Text: text, Line: entry.val.Line})
	}
	return out, nil
}

func (p *parser) isNull(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

// findAlias returns the first alias node in the tree, or nil. An alias is how
// a workflow reaches the rest of its content through an anchor.
func findAlias(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.AliasNode {
		return node
	}
	for _, child := range node.Content {
		if found := findAlias(child); found != nil {
			return found
		}
	}
	return nil
}

func stepID(jobID string, number int) string {
	return fmt.Sprintf("%s/step/%d", jobID, number)
}

func kindName(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "a document"
	case yaml.SequenceNode:
		return "a list"
	case yaml.MappingNode:
		return "a mapping"
	case yaml.ScalarNode:
		return "a single value"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "an unknown node"
	}
}
