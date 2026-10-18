# Fixtures for rule 10.
#
# | Fixture                  | Expected | What it pins down                                  |
# |--------------------------|----------|----------------------------------------------------|
# | ppe-010/third_party.yml  | 3 Warn   | the three external reference shapes                |
# | ppe-010/same_org.yml     | 2 Warn   | same-org versus third-party, with a known owner    |
# | ppe-010/first_party.yml  | 0 Warn   | actions/ and github/ are exempt, rule 1 is not     |
#
# `same_org.yml` needs a known repository, which in CI comes from
# `GITHUB_REPOSITORY`. Without one the tool cannot tell a colleague's repository
# from a stranger's, so `TestRule10WithoutAKnownRepository` covers that case
# separately and the message says so rather than guessing.
#
# Every ref here is SHA pinned except the reusable workflow, which is on `main`
# so that rule 1 and rule 10 both have something to say about the same line.
#
# ## GitHub's own actions are exempt
#
# References owned by `actions` or `github` are trusted by name and never
# reported, pinned or not. GitHub's own security documentation draws the same
# line, describing a policy that allows "only actions that are created by GitHub"
# before widening it to third parties.
#
# The reason is signal rather than safety. A rule that fires on `actions/checkout`
# fires on effectively every workflow ever written, and a finding that is always
# present stops being read, which takes the findings that matter down with it.
# Nothing is lost by the exemption, because rule 10's unique contribution is on
# SHA pinned third party references, where rule 1 is silent.
#
# It costs something, and the cost is real: this is a hardcoded trust list with no
# configuration file behind it, so an organisation that has audited its own
# actions cannot turn this off. v1 accepts that. When a config layer lands this
# becomes the default rather than the only setting.
#
# `first_party.yml` is the fixture that holds the line, and it holds it in both
# directions: three GitHub owned references that must be silent, and one third
# party reference that must not be, so it fails if the exemption is widened into
# silence rather than narrowed into a judgement.
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
