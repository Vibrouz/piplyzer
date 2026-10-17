# Parser fixtures for internal/parse.
#
# Each file here covers one row of the "Parser coverage" table in
# the parser. A row is a case where a plausible looking parser
# compiles, passes a naive test, and silently misses the real thing, so each of
# these is a specific trap rather than a sample workflow.
#
# | Fixture               | Covers                                                |
# |-----------------------|-------------------------------------------------------|
# | triggers.yml          | a real `on:` block: mapping form, event filters, `schedule:` as a list of crontab entries, `workflow_call:` carrying `inputs:` that is not a filter at all |
# | triggers-scalar.yml   | `on: push`, the single value form                       |
# | triggers-list.yml     | `on: [push, pull_request]`, the list form               |
# | uses-locations.yml    | `uses:` at workflow, job, and step level in one file, plus local and container actions |
# | run-block-scalars.yml | `run: |`, `|-`, `>`, quoted, and empty forms             |
# | permissions.yml       | `permissions:` at workflow and job level, and the jobs that inherit |
# | jobs-steps.yml        | steps grouped per job, the grouping rule 6 correlates on |
| anchors.yml           | anchors and aliases, which Actions resolves, including a mapping, a block scalar, and the line numbers aliased content keeps |
#
# The credentials in run-block-scalars.yml are pattern-matching fakes
# (AKIAIOSFODNN7EXAMPLE is the documentation example value). They exist so the
# credential regexes have something to match, and they are not live keys.
#
# Parse failures are written inline in the tests rather than kept here: each one
# needs its own expectation, and a fixture of valid YAML cannot express "this
# file is broken".