# Fixtures for rule 12.
#
# | Fixture                   | Expected | What it pins down                              |
# |---------------------------|----------|------------------------------------------------|
# | ppe-012/fingerprint.yml   | 1 Block  | all five components at once                     |
# | ppe-012/negatives.yml     | 0        | the ways it stays quiet, one per condition      |
#
# ## Why this can Block when the Warn rules it counts cannot
#
# By the time it fires, a Block tier rule has already matched, because the trigger
# requires one of rules 4, 5 or 6. The merge was already blocked. This adds no new
# friction, which is the only argument that makes a sixth signal able to block
# rather than annotate.
#
# ## It is a separate rule, not a severity bump
#
# Changing rules 4 through 8 to escalate each other would mean those rules knew
# about one another, and every rule here is a pure `func(*parse.File) findings.Findings`
# on purpose. The signal is also genuinely different: rule 4 alone is an internal
# service, rule 5 alone is a false match, but the two together in a workflow with
# an unfiltered push is a different claim from either.
#
# ## The negatives are the interesting half
#
# `negatives.yml` is three ways this could become noise:
#
# - `two-weak-signals` has rules 4 and 5 and nothing else. One more component
#   anywhere in the file makes it match, so this is the design working rather than a
#   near miss.
# - `with-a-deploy-button` is the case the spec is most careful about. An unfiltered
#   push plus a manual trigger job is an ordinary repository, and without the
#   mechanic requirement every repository with a deploy button would match.
# - `changelog` is rule 6 alone, which is a changelog job.
#
# The trigger is deliberately filtered in this file. An unfiltered push is rule 7,
# and rule 7 here would supply the third component these jobs otherwise lack.
#
# ## Repeated findings are still one component
#
# `TestRule12CountsComponentsNotFindings` pins that two hardcoded endpoints produce
# two rule 4 findings but count as one component. Without that, a workflow with
# several literal endpoints would reach the threshold on its own.
