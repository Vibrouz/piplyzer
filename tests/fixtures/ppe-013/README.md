# Fixtures for rule 13.
#
# | Fixture                    | Expected    | What it pins down                     |
# |----------------------------|-------------|---------------------------------------|
# | ppe-013/secrets_inherit.yml| 2 PPE-013   | inherit across a repository boundary  |
#
# ## What the rule is about
#
# A job that calls a reusable workflow can pass secrets two ways. The explicit
# form names each one:
#
#     secrets:
#       DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
#
# The inherit form passes all of them:
#
#     secrets: inherit
#
# The explicit form says what leaves the repository and the reader can check it
# against what the called workflow uses. The inherit form says "everything",
# and what everything is depends on the repository's secret store, which is not
# in the file and can change without the workflow changing at all.
#
# ## Why this is Block and not Warn
#
# Every other rule in this ruleset that mentions a secret is about a credential
# being exposed to code that might misuse it, which is something a reader can
# look at and decide. This one is different. The secret is handed to a
# repository this tool cannot read, so there is nothing to look at: the
# receiving code is in a different repository and the tool does not scan it.
#
# That is the same reason rule 10 is a Warn rather than a Block, and the
# opposite reason. Rule 10 says "this code is unreadable", which a reader can
# weigh. Rule 13 says "every secret has been handed to code you cannot read",
# which a reader can only weigh by going and reading that other repository.
#
# ## The negatives that earn their place
#
# `local` is the important one. A workflow in this repository is code the
# reader can already see, and inherit is a reasonable way to pass secrets
# between two workflows one team owns. Flagging it would flag the most ordinary
# way to use a reusable workflow.
#
# `explicit` is the shape the finding asks for. The explicit form names what
# leaves, and a reader can check that against what the called workflow uses.
#
# `same-org` is a finding and not a negative, and the reasoning is worth
# stating. A workflow in this organisation is still a different repository, and
# a workflow in the same organisation can itself call a third party workflow
# and pass the secrets on. The boundary that matters is the repository
# boundary, not the organisation one.
#
# ## Why the references are SHA pinned
#
# So that rule 1 stays quiet. This fixture is about the secrets and not about
# the pinning, and a rule 1 finding on the same line would say nothing about
# which rule was being tested.
