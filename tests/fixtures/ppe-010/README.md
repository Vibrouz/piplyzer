# Fixtures for rule 10.
#
# | Fixture                  | Expected | What it pins down                                  |
# |--------------------------|----------|----------------------------------------------------|
# | ppe-010/third_party.yml  | 3 Warn   | the three external reference shapes                |
# | ppe-010/same_org.yml     | 2 Warn   | same-org versus third-party, with a known owner    |
#
# `same_org.yml` needs a known repository, which in CI comes from
# `GITHUB_REPOSITORY`. Without one the tool cannot tell a colleague's repository
# from a stranger's, so `TestRule10WithoutAKnownRepository` covers that case
# separately and the message says so rather than guessing.
#
# Every ref here is SHA pinned except the reusable workflow, which is on `main`
# so that rule 1 and rule 10 both have something to say about the same line.
#
# ## Rule 10 and rule 1 answer different questions
#
# This is the reason the two rules are separate rather than one rule with two
# severities.
#
# - Rule 1 asks whether the *reference* can be moved under you. SHA pinning answers
#   that, and pinning is the supply chain control.
# - Rule 10 asks what is *inside* the reference. Pinning does not answer that at
#   all, because a pinned reference to an unreadable repository is still
#   unreadable.
#
# `TestRule10IsIndependentOfRule1` pins the pairing in both directions: a pinned
# reference silences rule 1 and not rule 10, and a mutable one makes both speak
# without either suppressing the other. That is visible in the engine
# expectations too, where `ppe-001/pinned.yml` produces four rule 10 findings and
# no rule 1 ones.
#
# ## Local actions and containers are not hops
#
# A `./build/action` reference is code in this repository, which is the
# repository the run scans. A `docker://alpine` reference names an image rather
# than a repository. Neither is a transitivity hop, and
# `TestRule10IgnoresLocalAndContainerReferences` holds that line along with
# `../other/action`, which is a local action written with a parent path.
