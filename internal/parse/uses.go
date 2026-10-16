package parse

import "strings"

// UsesRef is a reference to an action, a reusable workflow, or a local action.
//
// Every uses: in a workflow is one of these whatever it appears as, so rules 1
// and 10 match a single shape instead of a step shape and a job shape.
type UsesRef struct {
	// Target is the reference exactly as written, for example
	// actions/checkout@v4, org/repo/.github/workflows/build.yml@main, or
	// ./build/action.
	Target string
	Line   int
	Column int
}

// Parts splits Target into repository, subpath, and ref.
//
// The three shapes GitHub accepts are:
//
//	actions/checkout@v4                            docker://alpine
//	org/repo/.github/workflows/build.yml@main      ./build/action
//	owner/repo/sub/path@ref
//
// The split is on the last @, because a ref may contain slashes (release/v1)
// while a subpath may not contain @. Splitting on the first @ instead would
// report a branch name as part of the path.
//
// A local action and a container action both report an empty ref, even when the
// text contains an @. That is deliberate: it lets a check about pinning skip
// both shapes without needing a case for either, because neither has a remote
// ref that could be repointed.
func (u UsesRef) Parts() (repo, subpath, ref string) {
	target := strings.TrimSpace(u.Target)

	switch {
	case target == "":
		return "", "", ""
	case strings.HasPrefix(target, "./"), strings.HasPrefix(target, "../"):
		// Local actions live in this repository and carry no ref. Reporting
		// them with an empty repo is what keeps rule 10 from calling a local
		// action third party code.
		return "", target, ""
	case strings.HasPrefix(target, "docker://"):
		// A container action, not a repository reference.
		return target, "", ""
	}

	path := target
	if at := strings.LastIndex(target, "@"); at >= 0 {
		path, ref = target[:at], target[at+1:]
	}

	segments := strings.Split(path, "/")
	if len(segments) < 2 {
		return path, "", ref
	}
	repo = segments[0] + "/" + segments[1]
	if len(segments) > 2 {
		subpath = strings.Join(segments[2:], "/")
	}
	return repo, subpath, ref
}

// IsLocal reports whether the reference points at an action in this repository.
func (u UsesRef) IsLocal() bool {
	repo, _, _ := u.Parts()
	return repo == ""
}
