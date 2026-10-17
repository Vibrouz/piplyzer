# Fixtures for rules 3 to 6.
#
# | Fixture                        | Expected | What it pins down                              |
# |--------------------------------|----------|------------------------------------------------|
# | ppe-003/malicious.yml          | 13 (9 Block, 4 Warn) | rules 3, 4 and 5 together in one workflow |
# | ppe-003/legitimate.yml         | 0 Block, 3 Warn  | rule 4, real workflows an earlier version blocked |
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
# - Rule 4 reads literal script text and cannot follow indirection, so
#   `IP=198.51.100.42` on one line and `curl $IP` on the next is not reported.
#   The same applies to the secret patterns in rule 5.
# - The `clean` job's `AKIA_REGION` and `sk-directory` do not match rule 5,
#   because the patterns require the credential body, not just the prefix.
# `legitimate.yml` holds every rule 4 false positive found by auditing the rule
# against real projects rather than against imagined ones. Two families:
#
# - An address used as data. Managing addresses over an HTTP API is a category of
#   tooling (DNS providers, fail2ban and CrowdSec wrappers, allowlist editors)
#   where a dotted quad beside a curl is the entire point. Real examples taken
#   from Porkbun's API reference, a mailcow issue, and crowdsec and ALBIS
#   wrappers.
# - Loopback. `curl --resolve host:80:127.0.0.1 http://host/` is curl's own
#   documented local vhost test. RFC1918 is deliberately NOT exempt: private
#   space is where exfiltration goes.
#
# It emits 3 Warn findings, all plain http://, which is rule 4 working rather
# than failing. The assertion is that nothing here blocks.
