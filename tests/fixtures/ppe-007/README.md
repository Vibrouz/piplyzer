# Fixtures for rule 7, PPE-007: `on: push` with no ref or path filter.
#
# | Fixture      | Expected        | What it pins down                        |
# |--------------|-----------------|------------------------------------------|
# | unfiltered.yml | 1 PPE-007, Warn | push with no filters at all             |
# | filtered.yml   | 0             | a `branches:` filter, the case build_plan.md names |
#
# Warn, not Block. An unfiltered push is extremely common and often deliberate,
# so blocking it would be noise on a gate that has to survive contact with real
# repositories. It is still a component of the GhostAction composite, which is
# allowed to block because it needs three of rules 4 to 8, not one.
#
# The other filter shapes are covered by an inline table in `ppe_test.go` rather
# than by files here, because a workflow has exactly one `on:` block and each
# shape would need its own file. `tags:` and `paths:` count as filters: a push
# that only runs for `v*` tags is restricted, and calling it unfiltered is a
# false positive.