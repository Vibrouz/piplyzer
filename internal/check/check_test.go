package check

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Vibrouz/whoa/internal/engine"
	"github.com/Vibrouz/whoa/internal/findings"
)

func finding(id string, severity findings.Severity, message string) findings.Finding {
	return findings.New(id, severity, message, findings.At(".github/workflows/ci.yml", 12))
}

func report(fileFindings ...findings.Finding) engine.Report {
	return engine.Report{Files: []engine.File{{
		Path:     ".github/workflows/ci.yml",
		Findings: fileFindings,
	}}}
}

func TestEvaluate(t *testing.T) {
	tests := map[string]struct {
		result     Result
		conclusion Conclusion
		title      string
		text       string
	}{
		"clean": {
			result:     Result{Scan: report()},
			conclusion: Success,
			title:      "No issues found",
			text:       "No findings.",
		},
		"warning": {
			result:     Result{Scan: report(finding("PPE-001", findings.SeverityWarn, "Pin it."))},
			conclusion: Success,
			title:      "No blocking issues, 1 warning",
			text:       "### Warnings (1)",
		},
		"block": {
			result:     Result{Scan: report(finding("PPE-002", findings.SeverityBlock, "Do not run it."))},
			conclusion: Failure,
			title:      "1 blocking issue found",
			text:       "**PPE-002** `.github/workflows/ci.yml:12`",
		},
		"no workflows": {
			result:     Result{},
			conclusion: Failure,
			title:      "Scan incomplete",
			text:       "no workflows were found",
		},
		"parse error": {
			result: Result{Scan: engine.Report{
				Files:     []engine.File{{Path: ".github/workflows/ok.yml"}},
				Unchecked: []engine.Unreadable{{Path: ".github/workflows/bad.yml", Err: errors.New("bad yaml")}},
			}},
			conclusion: Failure,
			title:      "Scan incomplete",
			text:       ".github/workflows/bad.yml",
		},
		"unreadable": {
			result: Result{
				Scan:       report(),
				Unreadable: []string{".github/workflows/locked.yml"},
			},
			conclusion: Failure,
			title:      "Scan incomplete",
			text:       "could not be read",
		},
		"dependency block": {
			result: Result{
				Scan:        report(),
				HasLockfile: true,
				Deps: engine.DepsReport{
					Findings: findings.Findings{finding("DEP-D3", findings.SeverityBlock, "Wrong registry.")},
				},
			},
			conclusion: Failure,
			title:      "1 blocking issue found",
			text:       "**DEP-D3**",
		},
		"dependency error": {
			result: Result{
				Scan:        report(),
				HasLockfile: true,
				DepsErr:     errors.New("could not read the lockfile"),
			},
			conclusion: Failure,
			title:      "Scan incomplete",
			text:       "dependency check: could not read the lockfile",
		},
		"no lockfile is not a gap": {
			result:     Result{Scan: report()},
			conclusion: Success,
			title:      "No issues found",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotConclusion, out := Evaluate(tc.result)
			if gotConclusion != tc.conclusion {
				t.Errorf("conclusion is %q, want %q", gotConclusion, tc.conclusion)
			}
			if out.Title != tc.title {
				t.Errorf("title is %q, want %q", out.Title, tc.title)
			}
			if !strings.Contains(out.Text, tc.text) {
				t.Errorf("text does not contain %q:\n%s", tc.text, out.Text)
			}
		})
	}
}

func TestEvaluateSummarisesBothChecks(t *testing.T) {
	_, out := Evaluate(Result{
		Scan:        report(finding("PPE-001", findings.SeverityWarn, "Pin it.")),
		HasLockfile: true,
		Deps: engine.DepsReport{
			Findings: findings.Findings{finding("DEP-D3", findings.SeverityBlock, "Wrong registry.")},
		},
	})

	for _, want := range []string{"scanned 1 workflow", "1 block", "1 warning", "checked 0 dependencies"} {
		if !strings.Contains(out.Summary, want) {
			t.Errorf("summary does not contain %q: %s", want, out.Summary)
		}
	}
}

func TestEvaluateTruncatesTheText(t *testing.T) {
	long := strings.Repeat("word ", 20_000)
	_, out := Evaluate(Result{Scan: report(finding("PPE-001", findings.SeverityBlock, long))})

	if len(out.Text) > maxText {
		t.Errorf("text is %d bytes, want at most %d", len(out.Text), maxText)
	}
	if !strings.Contains(out.Text, "truncated") {
		t.Error("text does not say it was truncated")
	}
}

func TestPostCreatesACompletedRun(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/repos/o/r/check-runs" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("authorization is %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type is %q", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":77}`))
	}))
	defer server.Close()

	client := NewClient("tok")
	client.BaseURL = server.URL
	id, err := client.Post(context.Background(), "o", "r", Run{
		HeadSHA:    "sha",
		Conclusion: Failure,
		Output:     Output{Title: "title", Summary: "summary", Text: "text"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != 77 {
		t.Errorf("id is %d, want 77", id)
	}

	if got["name"] != Name || got["head_sha"] != "sha" || got["status"] != "completed" || got["conclusion"] != "failure" {
		t.Errorf("body is %v", got)
	}
	output, ok := got["output"].(map[string]any)
	if !ok || output["title"] != "title" || output["summary"] != "summary" || output["text"] != "text" {
		t.Errorf("output is %v", got["output"])
	}
}

func TestPostReportsAnAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message":"Validation Failed"}`))
	}))
	defer server.Close()

	client := NewClient("tok")
	client.BaseURL = server.URL
	_, err := client.Post(context.Background(), "o", "r", Run{HeadSHA: "sha", Conclusion: Success})
	if err == nil || !strings.Contains(err.Error(), "422") || !strings.Contains(err.Error(), "Validation Failed") {
		t.Fatalf("error is %v", err)
	}
}

func TestPostValidatesItsInput(t *testing.T) {
	client := NewClient("tok")
	if _, err := client.Post(context.Background(), "", "r", Run{HeadSHA: "s", Conclusion: Success}); err == nil {
		t.Error("expected an error for a missing owner")
	}
	if _, err := client.Post(context.Background(), "o", "r", Run{Conclusion: Success}); err == nil {
		t.Error("expected an error for a missing sha")
	}
	if _, err := client.Post(context.Background(), "o", "r", Run{HeadSHA: "s", Conclusion: "neutral"}); err == nil {
		t.Error("expected an error for an unsupported conclusion")
	}
}
