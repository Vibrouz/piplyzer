package parse

import "gopkg.in/yaml.v3"

// Triggers reads the workflow's on: block.
//
// The key is read as node text. Under YAML 1.1, which some readers still
// implement, an unquoted `on` resolves to the boolean true, so `on: push`
// arrives carrying the key `true`. Rules 7, 8, and 9 then never fire and nothing
// errors.
//
// Note what protects us here, because it is narrower than it looks. We read
// node.Value, and a YAML 1.1 reader would have rewritten that value to "true",
// so pairs() would record the key as "true" and this function would never be
// called. Reading the key as text does not by itself survive a 1.1 reader: the
// original spelling is not recoverable from the node. What actually holds the
// line is TestOnKeyIsReadAsText in quirk_test.go, which asserts on the reader's
// behavior directly and fails on a dependency upgrade rather than silently
// disarming three rules.
func (p *parser) triggers(node *yaml.Node) (Triggers, error) {
	triggers := Triggers{Present: true, Line: node.Line}

	switch {
	case p.isNull(node):
		// `on:` with nothing after it declares no events.
		return triggers, nil
	case node.Kind == yaml.ScalarNode:
		// on: push
		triggers.Specs = []TriggerSpec{{Event: node.Value, Line: node.Line}}
		return triggers, nil
	case node.Kind == yaml.SequenceNode:
		// on: [push, pull_request]
		events, err := p.list(node, "on")
		if err != nil {
			return Triggers{}, err
		}
		triggers.Specs = make([]TriggerSpec, 0, len(events))
		for _, event := range events {
			triggers.Specs = append(triggers.Specs, TriggerSpec{Event: event, Line: node.Line})
		}
		return triggers, nil
	case node.Kind != yaml.MappingNode:
		return Triggers{}, p.errf(node.Line, "on must be a value, a list, or a mapping of events, got %s", kindName(node.Kind))
	}

	// on:
	//   push:
	//     branches: [main]
	pairs, err := p.pairs(node, "on")
	if err != nil {
		return Triggers{}, err
	}
	for _, entry := range pairs {
		spec := TriggerSpec{Event: entry.key, Line: entry.keyNode.Line}
		// schedule is the one event whose body is a list of crontab entries
		// rather than a mapping of filters.
		if !p.isNull(entry.val) && entry.val.Kind != yaml.SequenceNode {
			body, err := p.pairs(entry.val, "on."+entry.key)
			if err != nil {
				return Triggers{}, err
			}
			for _, field := range body {
				var target *[]string
				switch field.key {
				case "branches":
					target = &spec.Branches
				case "branches-ignore":
					target = &spec.BranchesIgnore
				case "paths":
					target = &spec.Paths
				case "paths-ignore":
					target = &spec.PathsIgnore
				case "tags":
					target = &spec.Tags
				case "tags-ignore":
					target = &spec.TagsIgnore
				case "types":
					target = &spec.Types
				default:
					// workflow_call inputs, schedule entries, and filters ppe
					// does not read. workflow_call in particular carries an
					// inputs mapping that is not a filter at all.
					continue
				}
				list, err := p.list(field.val, "on."+entry.key+"."+field.key)
				if err != nil {
					return Triggers{}, err
				}
				*target = list
			}
		}
		triggers.Specs = append(triggers.Specs, spec)
	}
	return triggers, nil
}

// Permissions reads a permissions: block at either level.
func (p *parser) permissions(node *yaml.Node, level PermissionLevel) (*Permissions, error) {
	perms := &Permissions{Declared: true, Level: level, Line: node.Line}

	switch {
	case p.isNull(node):
		// The key is there with no value. Not the same as the key being absent,
		// and not the same as an empty map either.
		perms.Scope = PermissionUnspecified
	case node.Kind == yaml.ScalarNode:
		switch node.Value {
		case string(PermissionWriteAll), string(PermissionReadAll):
			perms.Scope = PermissionScope(node.Value)
		default:
			return nil, p.errf(node.Line,
				"permissions must be a mapping, \"write-all\", or \"read-all\", got %q", node.Value)
		}
	case node.Kind == yaml.MappingNode:
		perms.Scope = PermissionMap
		values, err := p.values(node, string(level)+" permissions")
		if err != nil {
			return nil, err
		}
		perms.Values = values
	default:
		return nil, p.errf(node.Line, "permissions must be a mapping, \"write-all\", or \"read-all\", got %s", kindName(node.Kind))
	}
	return perms, nil
}
