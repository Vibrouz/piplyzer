# Fixtures for rule 14.
#
# | Fixture                | Expected  | What it pins down                       |
# |------------------------|-----------|------------------------------------------|
# | ppe-014/unredacted.yml | 3 PPE-014 | a secret read as a structured value      |
#
# ## What the rule is about
#
# The runner hides a secret from the log by matching its exact string value.
# That works when the workflow refers to the secret as a whole:
#
#     env:
#       PASSWORD: ${{ secrets.MY_SECRET }}
#
# It stops working the moment the secret is treated as a structured value. If
# the secret holds a JSON document and the workflow takes one field out of it:
#
#     env:
#       PASSWORD: ${{ fromJSON(secrets.MY_SECRET).password }}
#
# then the value in the log is a substring of the secret, not the secret, and
# there is nothing for the runner to match. The password is printed in full.
#
# The whole context has the same problem. `toJSON(secrets)` puts every secret
# in the log at once, and that is reported by the same rule.
#
# ## Why this is Block
#
# It needs no attacker at all. The value is in the job log, and anyone who can
# read the log can read the secret. On a public repository the logs are
# public. This is the most straightforwardly exploitable finding in the
# ruleset.
#
# ## The two shapes, and the detail that matters
#
# The whole context is written "secrets", with no dot in it. A check that
# looked for a dotted member of the context would miss exactly the case that
# hands over everything, so the search is for the context itself and a word
# boundary keeps an unrelated word ending in "secrets" from matching.
#
# `TestRule14WhichShapesLeak` holds both halves: the four shapes that leak and
# the four that do not, including a function applied to something that is not
# the secret.
#
# ## The negative that earns its place
#
# The "ordinary way" step refers to a secret as a whole, which is the shape the
# runner can redact. It stays silent, and a rule that flagged it would fire on
# essentially every workflow that uses a secret.
