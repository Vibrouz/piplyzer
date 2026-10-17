# Fixtures for rule 11.
#
# | Fixture                   | Expected          | What it pins down                       |
# |---------------------------|-------------------|------------------------------------------|
# | ppe-011/overgrant.yml     | 2 Warn            | the two ways a job is over-scoped        |
# | ppe-011/oidc-forgery.yml  | 1 Block + 1 Warn  | the one Block case, and its two near misses |
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
