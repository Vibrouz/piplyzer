# Fixtures for rule 8, PPE-008: `workflow_dispatch` on a job that can reach credentials.
#
# | Fixture                | Expected        | What it pins down                          |
# |------------------------|-----------------|--------------------------------------------|
# | dispatch-sensitive.yml | 3 PPE-008, Warn | three jobs, sensitive for three different reasons |
# | dispatch-clean.yml     | 0               | dispatch with nothing privileged behind it |
#
# `dispatch-clean.yml` is the one that matters. A `workflow_dispatch` trigger
# with no credentials behind it is how deploy buttons get built, and flagging it
# would fire on a large share of legitimate repositories. That is why rule 8 is
# Warn rather than Block.
#
# Three notes on the fixture that are decisions, not accidents:
#
# - Job level `permissions:` **replaces** the workflow level block rather than
#   merging with it. `dispatch-sensitive.yml` has `read-all` at the workflow
#   level so that `build` and `docs` are clean, and `oidc` sensitive because of
#   its own block. An earlier version put `id-token: write` at the workflow
#   level and all five jobs fired, which was the inheritance working correctly.
# - `secrets:` with nothing after it still counts as declared. A job with any
#   `secrets:` key has been given the chance to hold credentials.
# - A job referencing `github.token` counts as sensitive, per plan.md. Ordinary
#   API-calling workflows do reference it, so this is a known false positive
#   source and it is covered by a test rather than hidden from the fixture.
