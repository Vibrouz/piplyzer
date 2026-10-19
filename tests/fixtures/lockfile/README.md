# Fixtures for the lockfile reader.
#
# | Fixture          | What it is                                                  |
# |------------------|-------------------------------------------------------------|
# | npm-v3.json      | a real lockfile written by npm install                      |
# | npm-v2.json      | a real lockfile written by npm install with lockfileVersion 2 |
# | v3.json          | hand-built, for the shapes a small lockfile does not reach   |
# | v1.json          | a version 1 lockfile, with the nested dependencies tree      |
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
