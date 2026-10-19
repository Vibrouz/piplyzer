# Fixtures for rule 11.
#
# | Fixture                   | Expected          | What it pins down                       |
# |---------------------------|-------------------|------------------------------------------|
# | ppe-011/overgrant.yml     | 2 Warn            | the two ways a job is over-scoped        |
# | ppe-011/oidc-forgery.yml  | 1 Block + 1 Warn  | the one Block case, and its two near misses |
# | ppe-011/workflow_token.yml| 2 Warn            | the workflow token with no scope declared |
#
# ## The workflow token is a different question from a repository secret
#
# `workflow_token.yml` covers the case decisions.md section 23 said this rule
# should gain. The workflow token is available in every job, so using it does
# not make a job sensitive: the harm rules 8 and 11 target is a credential the
# attacker would not otherwise have, and a stolen PAT is strictly more capable
# than any GITHUB_TOKEN.
#
# The question here is different. The token's scope is whatever the effective
# permissions say, and when nothing declares them the scope is the repository
# default, which is read-write for a repository or organisation created before
# 2 Feb 2023. The job is using a credential whose scope nothing here can see.
#
# Both spellings are covered, because GitHub documents `github.token` as
# "functionally equivalent to the GITHUB_TOKEN secret". A rule that matched one
# and not the other would be wrong about half the workflows that use a token,
# and `TestWorkflowTokenIsNotCountedAsARealSecret` holds the two apart so they
# cannot drift.
#
# The two negatives earn their place. A job that uses the token but declares
# its permissions has nothing left to be over-privileged about, and a job that
# does not use the token at all has nothing to be over-privileged about, and
# flagging every job in every repository that declares no permissions would be
# noise on a large share of real workflows.
#
# ## Almost everything here is Warn, on purpose
#
# `write-all` is what a repository has before anyone thinks about permissions, and
# a job with no `permissions:` block inherits a read-write default on anything
# created before 2 Feb 2023. Blocking either would block most of GitHub Actions.
#
# The single Block case is `oidc-forgery.yml`, and it is a different kind of
# finding rather than a stricter severity: `id-token: write`, on an event a fork
# can trigger, with untrusted input reaching a `run:` block. A cloud credential
# minted for the workflow's identity is tradeable for anything that identity can
# reach, and that is an exploitable path rather than over-grant.
#
# `TestRule11BlockNeedsAllThreeParts` drops one part at a time and asserts no
# Block, because a Block reachable by any two of them is a Block on a large share
# of real workflows.
#
# ## Two things that look like bugs in these fixtures
#
# **`permissions:` is a job level key.** An earlier version of `overgrant.yml`
# put it on a step, where it is not valid, so the parser ignored it and the
# fixture tested nothing while reading correctly.
#
# **The forged job interpolates `head.ref`, not `pull_request.number`.** Numeric
# fields cannot be injected, so a fixture using one would demonstrate nothing. An
# earlier version did exactly that and the Block silently stopped firing.
#
# ## Negatives that earn their place
#
# `restricted` and `scoped-write` in `overgrant.yml` are sensitive jobs that
# declare what they need. They stay silent, and `TestRule11RespectsInheritedRestrictions`
# covers the workflow level versions of the same thing. Flagging those would mean
# flagging every deliberate grant, and there is no way to tell deliberate from
# careless from the text alone.
#
# `not-sensitive` is the case that decides whether this rule is noise: a job that
# touches no secret, mints no token and checks out nobody's code gets no finding,
# or every ordinary CI banner in every repository gets one.
#
# An empty `permissions:` key parses as declared-but-unspecified, and unspecified
# resolves to the same repository default that an absent key does. It is silent
# because the scope is unknown here, not because the key restricted anything.
