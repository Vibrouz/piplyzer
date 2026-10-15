package parse

// PermissionScope is the shape of a permissions: block.
type PermissionScope string

const (
	// PermissionUnspecified is a permissions key with an empty or null value.
	// What it actually grants depends on the repository or organization
	// default, which this package cannot know, so rules must resolve that
	// themselves rather than reading it as "nothing is granted".
	PermissionUnspecified PermissionScope = "unspecified"
	// PermissionWriteAll is permissions: write-all.
	PermissionWriteAll PermissionScope = "write-all"
	// PermissionReadAll is permissions: read-all.
	PermissionReadAll PermissionScope = "read-all"
	// PermissionMap is an explicit map such as contents: read, id-token: write.
	PermissionMap PermissionScope = "map"
)

// PermissionLevel says where a permissions block was declared, which is what
// lets a finding explain that a job inherited a workflow level restriction
// rather than having one of its own.
type PermissionLevel string

const (
	PermissionLevelWorkflow PermissionLevel = "workflow"
	PermissionLevelJob      PermissionLevel = "job"
)

// Permissions is one permissions: block, workflow level or job level.
//
// Both levels are parsed because a job with no block of its own inherits the
// workflow block. Treating a missing job block as unrestricted warns on every
// correctly scoped repository, which is the failure mode rule 11 has to avoid.
type Permissions struct {
	// Declared is true when the key was present, including when it was present
	// but empty. A key that was absent and a key that was empty mean different
	// things to GitHub, so the difference is preserved.
	Declared bool
	Level    PermissionLevel
	Scope    PermissionScope
	// Values holds the entries of an explicit map. Empty for the other scopes.
	Values Values
	Line   int
}

// Grants reports whether the block gives the named permission at write level.
//
// The three documented scopes are mechanical to resolve, and rule 11 and the
// sensitiveJob predicate both need "is id-token write here". Deriving it once
// keeps the two from disagreeing. An unspecified block reports false because
// the repository default is not known here; callers that care about the default
// resolve it themselves.
func (p *Permissions) Grants(name string) bool {
	if p == nil {
		return false
	}
	switch p.Scope {
	case PermissionWriteAll:
		return true
	case PermissionReadAll, PermissionUnspecified:
		return false
	}
	entry, ok := p.Values.Get(name)
	return ok && entry.Text == "write"
}
