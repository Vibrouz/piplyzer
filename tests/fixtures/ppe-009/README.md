# Fixtures for rule 9.
#
# | Fixture                | Expected | What it pins down                                |
# |------------------------|----------|--------------------------------------------------|
# | ppe-009/pwn_request.yml | 5 Block | one step per shape, across four separate jobs    |
# | ppe-009/workflow_run.yml | 1 Block | the same rule on the other privileged trigger     |
# | ppe-009/negatives.yml   | 0        | every shape on every trigger that is not privileged |
#
# `pwn_request.yml` puts each shape in its own job on purpose. A rule that
# matched only one of the three shapes would still pass a fixture containing all
# three, because a hit anywhere in the file looks the same as a hit in each of
# them. Separate jobs make that impossible to hide, and the unit test
# `TestRule9FindsEachShapeSeparately` checks the same thing one step at a time.
#
# The checkouts are SHA pinned, and `negatives.yml` is clean for every rule and
# not only for rule 9. A fixture that happens to be quiet for the rule it belongs
# to is a weak assertion, and that file is the one place that says "nothing here
# is wrong at all".
#
# `pwn_request.yml` does produce one rule 2 finding, from the step that echoes
# the pull request title. That is correct and it is in the expected sequence in
# `TestRulesRunThroughTheEngine` rather than removed to make the numbers tidier.
#
# No credentials appear in these fixtures.
#
# ## The negatives matter more than the positives here
#
# A plain `pull_request` job that checks out the pull request's code is how
# GitHub tells you your change is broken. It runs with a read-only token, cannot
# see repository secrets, and cannot run a workflow file written by the fork at
# all. A rule that flagged it would be flagging most of GitHub Actions, which is
# how a blocking rule gets uninstalled. `negatives.yml` therefore carries every
# dangerous shape on an unprivileged trigger, and the same `pull_request_target`
# trigger with no untrusted fetch is asserted in
# `TestRule9PrivilegedTriggerWithNoFetch`.
#
# ## Comments are not commands
#
# `# do not forget to git fetch origin main` is an ordinary thing for someone to
# write. A Block rule that matched it would block a repository on a line nobody
# runs, so the run text has its shell comments stripped first. The `#` only
# starts a comment at the start of a line or after whitespace, which leaves the
# other job of the character intact: it is also the fragment separator in a URL,
# and it appears inside quoted strings and after an `=`.
