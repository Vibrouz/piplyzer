// Package check turns a scan into a GitHub check run.
//
// It owns two things: the decision that a result fails the check, and the
// rendering of that result for the pull request. The decision is deliberately
// fail-closed. A scan that could not read a workflow, or found no workflows at
// all, is a failure rather than a success, because a required check that is
// green because it looked at nothing is worse than no check.
package check

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Vibrouz/whoa/internal/engine"
	"github.com/Vibrouz/whoa/internal/findings"
)

// Name is the check run name. It is the name a ruleset requires, so changing it
// is a breaking change for every repository that has already configured one.
const Name = "piplyzer"

const (
	// maxSummary and maxText are below GitHub's 65535 character limit, leaving
	// room for the truncation notice.
	maxSummary = 60_000
	maxText    = 60_000

	apiVersion = "2022-11-28"
)

// Conclusion is the check run conclusion.
type Conclusion string

const (
	Success Conclusion = "success"
	Failure Conclusion = "failure"
)

// Output is what the pull request shows.
type Output struct {
	Title   string
	Summary string
	Text    string
}

// Result is everything a scan produced.
type Result struct {
	// Scan is the workflow result.
	Scan engine.Report
	// Unreadable names workflow files that could not be read from the tree.
	Unreadable []string
	// Deps is the dependency result, valid when HasLockfile is true.
	Deps engine.DepsReport
	// HasLockfile says whether a dependency check was attempted.
	HasLockfile bool
	// DepsErr is set when a lockfile was present but could not be read. That
	// is a gap, not a clean dependency result.
	DepsErr error
	// AllowNoWorkflows treats an empty workflow set as a successful scan.
	//
	// The server sets it because it knows the tree is the repository root and
	// .github/workflows is the only place Actions runs from, so finding nothing
	// there means there is nothing to check. The CLI does not set it: a path on
	// a command line can be a typo, and reporting a typo as a clean repository
	// is the false clean the exit code exists to prevent.
	AllowNoWorkflows bool
}

// Evaluate decides the conclusion and renders the output.
//
// A Block fails the check. A gap fails it too. Warnings do not: a gate that
// fails on a pattern legitimate repositories use is a gate that gets turned
// off, which takes the blocking checks with it.
func Evaluate(r Result) (Conclusion, Output) {
	blocks := r.Scan.Blocks()
	warnings := r.Scan.Warnings()
	if r.HasLockfile {
		blocks += r.Deps.Findings.Count(findings.SeverityBlock)
		warnings += r.Deps.Findings.Count(findings.SeverityWarn)
	}

	incomplete := r.incomplete()

	var b strings.Builder
	if blocks > 0 {
		fmt.Fprintf(&b, "### Blocking (%d)\n\n", blocks)
		writeFindings(&b, r.Scan.Findings())
		if r.HasLockfile {
			writeFindings(&b, r.Deps.Findings.Blocking())
		}
		b.WriteString("\n")
	}

	if warnings > 0 {
		fmt.Fprintf(&b, "### Warnings (%d)\n\n", warnings)
		writeWarnings(&b, r.Scan.Findings())
		if r.HasLockfile {
			writeWarnings(&b, r.Deps.Findings)
		}
		b.WriteString("\n")
	}

	if incomplete {
		b.WriteString("### Not checked\n\n")
		if len(r.Scan.Files) == 0 {
			b.WriteString("- no workflows were found under .github/workflows\n")
		}
		for _, u := range r.Scan.Unchecked {
			fmt.Fprintf(&b, "- `%s`: %s\n", u.Path, oneLine(u.Err.Error()))
		}
		for _, path := range r.Unreadable {
			fmt.Fprintf(&b, "- `%s`: could not be read\n", path)
		}
		if r.DepsErr != nil {
			fmt.Fprintf(&b, "- dependency check: %s\n", oneLine(r.DepsErr.Error()))
		}
		b.WriteString("\n")
	}

	if b.Len() == 0 {
		if len(r.Scan.Files) == 0 && r.AllowNoWorkflows {
			b.WriteString("No workflows found, so there was nothing to check.\n")
		} else {
			b.WriteString("No findings.\n")
		}
	}

	title := "No issues found"
	switch {
	case blocks > 0:
		title = fmt.Sprintf("%s found", plural(blocks, "blocking issue", "blocking issues"))
	case incomplete:
		title = "Scan incomplete"
	case len(r.Scan.Files) == 0 && r.AllowNoWorkflows:
		title = "No workflows found"
	case warnings > 0:
		title = fmt.Sprintf("No blocking issues, %s", plural(warnings, "warning", "warnings"))
	}

	summary := fmt.Sprintf("scanned %s, %s, %s",
		plural(r.Scan.Scanned(), "workflow", "workflows"),
		plural(blocks, "block", "blocks"),
		plural(warnings, "warning", "warnings"))
	if r.HasLockfile {
		packages := 0
		if r.Deps.Lockfile != nil {
			packages = len(r.Deps.Lockfile.Packages)
		}
		summary += fmt.Sprintf("; checked %s", plural(packages, "dependency", "dependencies"))
	}
	if incomplete {
		summary += "; some files were not checked"
	}
	summary += fmt.Sprintf(" (ruleset %s)", findings.RulesetVersion)

	return conclusion(blocks, incomplete), Output{
		Title:   title,
		Summary: truncate(summary, maxSummary),
		Text:    truncate(b.String(), maxText),
	}
}

func (r Result) incomplete() bool {
	return len(r.Scan.Unchecked) > 0 ||
		len(r.Unreadable) > 0 ||
		(len(r.Scan.Files) == 0 && !r.AllowNoWorkflows) ||
		r.DepsErr != nil
}

func conclusion(blocks int, incomplete bool) Conclusion {
	if blocks > 0 || incomplete {
		return Failure
	}
	return Success
}

func writeFindings(b *strings.Builder, list findings.Findings) {
	for _, f := range list {
		if !f.Severity.Blocking() {
			continue
		}
		writeFinding(b, f)
	}
}

func writeWarnings(b *strings.Builder, list findings.Findings) {
	for _, f := range list {
		if f.Severity.Blocking() {
			continue
		}
		writeFinding(b, f)
	}
}

func writeFinding(b *strings.Builder, f findings.Finding) {
	fmt.Fprintf(b, "- **%s** `%s` %s\n", f.RuleID, f.Location.String(), oneLine(f.Message))
}

// oneLine collapses whitespace so that a message cannot break out of its list
// item or smuggle markdown structure into the check output.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	const notice = "\n\n... truncated\n"
	if limit <= len(notice) {
		return s[:limit]
	}
	return s[:limit-len(notice)] + notice
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Client posts check runs.
type Client struct {
	HTTP    *http.Client
	BaseURL string
	Token   string
}

// NewClient returns a client for an installation token.
func NewClient(token string) *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		BaseURL: "https://api.github.com",
		Token:   token,
	}
}

// Run is the check run to post.
type Run struct {
	// Name defaults to Name.
	Name       string
	HeadSHA    string
	Conclusion Conclusion
	Output     Output
	DetailsURL string
}

// Post creates the check run on a commit and returns its id.
//
// The run is created completed. The scan has already finished when this is
// called, so there is no in-progress state to publish, and a run that is left
// in-progress by a crash would block the pull request forever.
func (c *Client) Post(ctx context.Context, owner, repo string, run Run) (int64, error) {
	if owner == "" || repo == "" || run.HeadSHA == "" {
		return 0, errors.New("owner, repository and head sha are required")
	}
	if run.Conclusion != Success && run.Conclusion != Failure {
		return 0, fmt.Errorf("unsupported conclusion %q", run.Conclusion)
	}
	name := run.Name
	if name == "" {
		name = Name
	}

	body := map[string]any{
		"name":       name,
		"head_sha":   run.HeadSHA,
		"status":     "completed",
		"conclusion": run.Conclusion,
		"output": map[string]string{
			"title":   run.Output.Title,
			"summary": run.Output.Summary,
			"text":    run.Output.Text,
		},
	}
	if run.DetailsURL != "" {
		body["details_url"] = run.DetailsURL
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}

	base := c.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/check-runs", strings.TrimRight(base, "/"), owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)

	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("posting the check run: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("posting the check run: %s", responseMessage(resp))
	}

	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return 0, fmt.Errorf("reading the check run: %w", err)
	}
	return out.ID, nil
}

func responseMessage(resp *http.Response) string {
	var body struct {
		Message string `json:"message"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err == nil && json.Unmarshal(data, &body) == nil && body.Message != "" && len(body.Message) < 200 {
		return fmt.Sprintf("%s: %s", resp.Status, body.Message)
	}
	return resp.Status
}
