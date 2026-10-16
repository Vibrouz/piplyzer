# Fixtures for rule 2, PPE-002: untrusted context interpolated into a `run:` block.
#
# | Fixture    | Expected          | What it pins down                                  |
# |------------|-------------------|----------------------------------------------------|
# | injected.yml | 7 PPE-002 (4 Block, 3 Warn) | every tier and the write-gated demotion |
# | safe.yml   | 0                 | every shape that must not match, with reasons      |
#
# Two deliberate limits:
#
# - Rule 2 reads `run:` blocks only. A value in a step `with:` or in an `env:`
#   block is not script text, and GitHub documents passing it through an
#   environment variable as *the* mitigation for this attack. Scanning `env:`
#   would flag the recommended fix. That is in `safe.yml`.
# - The suffix is compared as a whole final path segment. `number` is not a
#   suffix and does not match; `github.event.pull_request.number` is the case a
#   substring matcher gets wrong.
#
# The matcher handles two shapes of context reference: `github.head_ref`, where
# the property follows the context directly, and `github.event.issue.title`,
# where several segments come first. The pattern printed in plan.md
# (`github\.(event\.)?\w+[.\w]*\.(suffix)`) requires a dot before the suffix and
# therefore does not match `github.head_ref` or `github.ref`, which are the most
# common ref-suffix references there are. `decisions.md` section 22 records it.
#
# `name` is Block tier in `plan.md` but ships as Warn until P2 measures it
# against real repositories. It is the widest of the ten suffixes and blocking
# on an unmeasured suffix is the one way this rule could cost us the gate.
# `decisions.md` section 22.