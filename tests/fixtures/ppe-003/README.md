# Fixtures for rules 3 to 6.
#
# | Fixture                        | Expected | What it pins down                              |
# |--------------------------------|----------|------------------------------------------------|
# | ppe-003/malicious.yml          | 9 (7 Block, 2 Warn) | rules 3, 4 and 5 together in one workflow |
# | ppe-006/correlated.yml         | 3 Block  | rule 6, both signals in the same job          |
# | ppe-006/split_job.yml          | 0        | rule 6, the signals in different jobs         |
#
# Rules 3, 4 and 5 share one fixture on purpose. All three read the same resolved
# scripts, so a reader comparing them learns more from one workflow than from
# three near-identical ones, and it is harder to write a matcher that passes by
# accident against a file that was built for it.
#
# `ppe-006` is split across two files because correlation is per job: a workflow
# has one `jobs:` mapping, so both halves of the false positive have to live in
# the same file. `correlated.yml` is the three positive shapes, `split_job.yml` is
# the four negative ones.
#
# Every credential in these fixtures is a pattern-matching fake.
# `AKIAIOSFODNN7EXAMPLE` is the AWS documentation example value, and the `ghp_`
# value is `EXAMPLE` repeated, not a token. They are here so the regexes have
# something to match.
#
# Two things in `ppe-003/malicious.yml` are honest limitations rather than clean
# negatives, and are labelled in the file:
#
# - `echo "building 1.2.3.4"` DOES match rule 4. A version string shaped like an
#   address is indistinguishable from an address.
# - The `clean` job's `AKIA_REGION` and `sk-directory` do not match rule 5,
#   because the patterns require the credential body, not just the prefix.