# Fixtures for rule 9.
#
# | Fixture                | Expected | What it pins down                                |
# |------------------------|----------|--------------------------------------------------|
# | ppe-009/pwn_request.yml | 5 Block | one step per shape, across four separate jobs    |
# | ppe-009/workflow_run.yml | 1 Block | the same rule on the other privileged trigger     |
# | ppe-009/negatives.yml   | 0        | every shape on every trigger that is not privileged |
# | ppe-009/base_fetch.yml  | 0        | the fetch shapes that are the documented hardening move |
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

# ## The false positives that were found by auditing against real projects
#
# `workflow_run.yml` and `base_fetch.yml` exist because an earlier version of
# rule 9 blocked every one of their lines. Each came from a real repository:
#
# - `git fetch origin main` under pull_request_target. This is the documented
#   hardening move, not a mistake: pull the base branch's own tooling and run
#   that instead of the contributor's code, precisely because the job is
#   privileged. Found in Xiaomi's miloco, Microsoft's discovery, chadbyte/clay,
#   and a template five other repositories copied.
# - `git fetch origin pull/N/head` followed by `git show` or `git merge-base`.
#   GitHub Security Lab's guidance is that pull request contents treated as
#   passive data are safe, and it says so explicitly. Implemented in Sherlock,
#   servo, InstructLab and OWASP.
# - `gh run download` on workflow_run. GitHub Security Lab recommends this pair
#   as the safe replacement for pull_request_target, CodeQL's
#   actions-untrusted-checkout query documents it, and it is how real pipelines
#   promote a build to a deploy job.
#
# So `gh run download` is not a finding at all, and `git fetch` needs all three
# of fetch a PR ref, check it out, and run something. The gap that leaves is
# real and deliberate: an artifact hand-off from an untrusted triggering run is
# undetected, and covering it means knowing whether the *other* workflow was
# untrusted, which is not a question one file can answer.
