package main

import (
	"testing"
)

// testEnv is the environment the tests run against.
//
// It is empty, and that is the point. The CLI reads GITHUB_REPOSITORY,
// GITHUB_EVENT_PATH, NPM_CONFIG_REGISTRY and NO_COLOR, and a test that
// inherited whatever the machine running it had set would be a different test
// on a laptop and on a CI runner. A CI run has GITHUB_REPOSITORY set and
// usually has an npm registry configured, and a golden file written against a
// laptop is then wrong on the runner.
//
// A test that needs one of these uses withEnv, or passes a lookup of its own.
func testEnv(t *testing.T) func(string) string {
	t.Helper()
	return func(string) string { return "" }
}

// withEnv returns a lookup over a fixed map.
//
// It is for a test that needs one or two variables set. The map is the whole
// environment, so a variable that is not in it is unset, which is what a test
// means by it not being there.
func withEnv(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}
