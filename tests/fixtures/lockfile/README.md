# Fixtures for the lockfile reader.
#
# | Fixture                   | What it is                                                  |
# |---------------------------|-------------------------------------------------------------|
# | npm-v3.json               | a real lockfile written by npm install                      |
# | npm-v2.json               | a real lockfile written by npm install with lockfileVersion 2 |
# | v3.json                   | hand-built, for the shapes a small lockfile does not reach   |
# | v1.json                   | a version 1 lockfile, with the nested dependencies tree      |
# | registry-mismatch.json    | every shape of resolved URL, for the registry check          |
# | diff-base.json            | the base of a diff, with one of every case                   |
# | diff-head.json            | the head of that diff                                        |
# | diff-base-v1.json         | a version 1 base that shares packages with the head          |
#
# ## The real ones are real
#
# `npm-v3.json` and `npm-v2.json` were produced by running `npm install
# --package-lock-only` and copying what npm wrote. They are not written by
# hand.
#
# That matters because a hand-written lockfile has the shape the author
# expected, and the whole point of reading a lockfile is to read the shape npm
# actually produces. Every field the checks depend on, the resolved URL and the
# hasInstallScript flag, was confirmed against these two files and against
# npm's own documentation of the format.
#
# `v3.json` is hand-built, to reach the shapes a one-dependency lockfile does
# not: a package with an install script, a nested package, and a dev-only
# dependency.
#
# `v1.json` is hand-built because npm 9 no longer writes version 1 lockfiles.
# Its shape is taken from npm's documentation of the format, and the tree is
# the one npm wrote before version 7: a hierarchy of dependencies rather than a
# flat map.
#
# ## The diff pair
#
# `diff-base.json` and `diff-head.json` are one of every case, so the diff has a
# single place that shows all of them:
#
# | Package                  | In the base | In the head | Verdict |
# |--------------------------|-------------|-------------|---------|
# | existing                 | yes         | yes         | silent  |
# | upgraded                 | v1.0.0      | v2.0.0      | silent  |
# | gained-a-script          | no script   | script      | finding |
# | always-had-a-script      | script      | script      | silent  |
# | brand-new                | no          | yes         | finding |
# | brand-new-with-a-script  | no          | yes, script | finding |
#
# The version bump is the case that decides whether the check is usable. A
# dependency update is the most ordinary thing in a lockfile, and if it read as
# a new package then every dependency bump in every pull request would be a
# finding.
#
# `diff-base-v1.json` is a version 1 base that shares packages with the head.
# It has to share them, or the version floor test would pass without testing
# anything: a base with nothing in common has no package to have gained a
# script.
#
# ## Every shape of resolved URL
#
# `registry-mismatch.json` has one package for each shape the registry check has
# to tell apart, which is the point of it:
#
# | Package                       | Resolved from                | Verdict |
# |-------------------------------|------------------------------|---------|
# | from-the-right-registry       | the default registry         | silent  |
# | the-npmjs-magic-value         | registry.npmjs.org           | silent  |
# | a-relative-path               | a relative path              | silent  |
# | @myorg/from-the-scope-registry| the scope's private registry | silent  |
# | from-another-registry         | a third host                 | finding |
#
# The npmjs.org case is the one that matters most and the one a check that
# compared strings would get wrong. It is what npm writes for every package in
# a lockfile created against the public registry, which is most lockfiles, and
# it means "the currently configured registry" rather than that host. The
# relative path is the same idea: npm resolves it against the registry serving
# the package.
#
# ## The version matters more than it looks
#
# A version 1 lockfile has a nested dependencies tree and does not record
# hasInstallScript at all. A version 2 or later lockfile has a flat packages
# map and does record it.
#
# So "the lockfile does not say" and "the package has no install script" are
# different answers, and reading the absent field as false would be a silent
# false negative on the check that blocks install-time malware. The reader keeps
# the difference, which is why hasInstallScript is a three-state value rather
# than a bool.
#
# ## A note on scoped packages
#
# The sandbox this was written in cannot fetch scoped packages, so no fixture
# here contains one produced by npm. The scoped path shape is in `v3.json`'s
# sibling cases and in the reader's tests, and it was taken from npm's
# documented format rather than from a generated file. A real scoped package
# resolves to a path like node_modules/@scope/pkg, and the name is the part
# after the last node_modules/, scope included.
