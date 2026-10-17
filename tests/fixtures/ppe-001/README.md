# Fixtures for rule 1, PPE-001: `uses:` pinned to a mutable ref.
#
# | Fixture      | Expected              | What it pins down                                       |
# |--------------|-----------------------|---------------------------------------------------------|
# | unpinned.yml | 4 PPE-001, all Block  | a mutable ref at all three `uses:` locations            |
# | pinned.yml   | 0                     | every shape rule 1 deliberately does not flag, and why  |
# | short-sha.yml| 2 PPE-001, all Block  | an abbreviated SHA resolves today but is not a pin     |
#
# The three locations matter because a step-only walk misses reusable workflow
# calls, which run another repository's jobs. All three are in `unpinned.yml` so
# a step-only implementation cannot pass it.
#
# `pinned.yml` is the one that gives the others meaning: a rule with only a
# positive fixture passes whether or not it works. Each exclusion in it is
# commented with the reasoning, because "we do not flag this" is a decision and
# not an oversight.
#
# SHA values in these fixtures are fabricated. They are not object names in any
# repository.