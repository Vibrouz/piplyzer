package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSecret = "it is a secret"

func sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func pullRequestPayload(action string) []byte {
	return []byte(`{
		"action": "` + action + `",
		"number": 3,
		"installation": {"id": 123},
		"repository": {
			"full_name": "Vibrouz/ppe-test",
			"name": "ppe-test",
			"owner": {"login": "Vibrouz"}
		},
		"pull_request": {
			"draft": false,
			"head": {
				"sha": "head-sha",
				"repo": {"full_name": "someone/ppe-test", "fork": true}
			},
			"base": {
				"sha": "base-sha",
				"repo": {"full_name": "Vibrouz/ppe-test"}
			},
			"user": {"login": "someone"}
		},
		"sender": {"login": "someone"}
	}`)
}

func TestVerify(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	good := sign([]byte(testSecret), body)

	tests := map[string]struct {
		secret []byte
		header string
		want   bool
	}{
		"good":             {[]byte(testSecret), good, true},
		"wrong secret":     {[]byte("not it"), good, false},
		"empty secret":     {nil, good, false},
		"missing header":   {[]byte(testSecret), "", false},
		"wrong prefix":     {[]byte(testSecret), strings.Replace(good, "sha256=", "sha1=", 1), false},
		"not hex":          {[]byte(testSecret), "sha256=zz", false},
		"truncated digest": {[]byte(testSecret), good[:20], false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Verify(tc.secret, body, tc.header); got != tc.want {
				t.Errorf("Verify = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParsePullRequest(t *testing.T) {
	d, err := Parse("pull_request", "delivery-1", pullRequestPayload("synchronize"))
	if err != nil {
		t.Fatal(err)
	}

	if d.Event != "pull_request" || d.ID != "delivery-1" || d.Action != "synchronize" {
		t.Errorf("identity is %+v", d)
	}
	if d.InstallationID != 123 || d.Number != 3 {
		t.Errorf("installation %d, number %d", d.InstallationID, d.Number)
	}
	if d.Repo != "Vibrouz/ppe-test" || d.Owner != "Vibrouz" || d.Name != "ppe-test" {
		t.Errorf("repository is %+v", d)
	}
	if d.HeadSHA != "head-sha" || d.BaseSHA != "base-sha" {
		t.Errorf("commits are %+v", d)
	}
	if d.HeadRepo != "someone/ppe-test" || !d.IsFork {
		t.Errorf("head is %+v", d)
	}
	if d.Sender != "someone" {
		t.Errorf("sender is %q", d.Sender)
	}
	if !d.ShouldScan() {
		t.Error("ShouldScan = false")
	}
}

func TestParseAForkThatWasDeleted(t *testing.T) {
	body := []byte(`{
		"action": "opened",
		"number": 1,
		"installation": {"id": 1},
		"repository": {"full_name": "o/r", "name": "r", "owner": {"login": "o"}},
		"pull_request": {
			"head": {"sha": "s", "repo": null},
			"base": {"sha": "b", "repo": {"full_name": "o/r"}}
		}
	}`)

	d, err := Parse("pull_request", "", body)
	if err != nil {
		t.Fatal(err)
	}
	if d.HeadRepo != "o/r" || d.IsFork {
		t.Errorf("head is %+v", d)
	}
}

func TestShouldScanOnlyPullRequestChanges(t *testing.T) {
	base, err := Parse("pull_request", "", pullRequestPayload("opened"))
	if err != nil {
		t.Fatal(err)
	}

	for _, action := range []string{"opened", "synchronize", "reopened", "ready_for_review"} {
		d := base
		d.Action = action
		if !d.ShouldScan() {
			t.Errorf("%s: ShouldScan = false", action)
		}
	}
	for _, action := range []string{"closed", "labeled", "edited", "converted_to_draft"} {
		d := base
		d.Action = action
		if d.ShouldScan() {
			t.Errorf("%s: ShouldScan = true", action)
		}
	}

	d := base
	d.Event = "push"
	if d.ShouldScan() {
		t.Error("push: ShouldScan = true")
	}
}

func TestParseRejectsARepositoryWithoutAName(t *testing.T) {
	body := []byte(`{"action":"opened","repository":{"full_name":""}}`)
	if _, err := Parse("pull_request", "", body); err == nil {
		t.Fatal("expected an error")
	}
}

func TestHandlerQueuesAVerifiedDelivery(t *testing.T) {
	queue := make(chan Delivery, 1)
	h := &Handler{Secret: []byte(testSecret), Queue: queue}
	body := pullRequestPayload("opened")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(signatureHeader, sign([]byte(testSecret), body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", "abc")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status is %d, want 202", rec.Code)
	}
	select {
	case d := <-queue:
		if d.ID != "abc" || d.HeadSHA != "head-sha" {
			t.Errorf("queued %+v", d)
		}
	default:
		t.Error("nothing was queued")
	}
}

func TestHandlerRejectsABadSignature(t *testing.T) {
	queue := make(chan Delivery, 1)
	h := &Handler{Secret: []byte(testSecret), Queue: queue}
	body := pullRequestPayload("opened")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(signatureHeader, "sha256="+strings.Repeat("0", 64))
	req.Header.Set("X-GitHub-Event", "pull_request")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status is %d, want 401", rec.Code)
	}
	if len(queue) != 0 {
		t.Error("a rejected delivery was queued")
	}
}

func TestHandlerAnswersPing(t *testing.T) {
	h := &Handler{Secret: []byte(testSecret), Queue: make(chan Delivery, 1)}
	body := []byte(`{"zen":"Keep it logically awesome."}`)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(signatureHeader, sign([]byte(testSecret), body))
	req.Header.Set("X-GitHub-Event", "ping")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status is %d, want 200", rec.Code)
	}
}

func TestHandlerIgnoresAnActionItDoesNotScan(t *testing.T) {
	queue := make(chan Delivery, 1)
	h := &Handler{Secret: []byte(testSecret), Queue: queue}
	body := pullRequestPayload("labeled")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(signatureHeader, sign([]byte(testSecret), body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status is %d, want 202", rec.Code)
	}
	if len(queue) != 0 {
		t.Error("an ignored delivery was queued")
	}
}

func TestHandlerReportsAFullQueue(t *testing.T) {
	queue := make(chan Delivery, 1)
	queue <- Delivery{}
	h := &Handler{Secret: []byte(testSecret), Queue: queue}
	body := pullRequestPayload("opened")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(signatureHeader, sign([]byte(testSecret), body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status is %d, want 503", rec.Code)
	}
}

func TestHandlerRejectsOtherMethods(t *testing.T) {
	h := &Handler{Secret: []byte(testSecret), Queue: make(chan Delivery, 1)}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/webhook", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status is %d, want 405", rec.Code)
	}
}

func TestHandlerCapsTheBody(t *testing.T) {
	h := &Handler{Secret: []byte(testSecret), Queue: make(chan Delivery, 1), MaxBody: 10}
	body := pullRequestPayload("opened")

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set(signatureHeader, sign([]byte(testSecret), body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status is %d, want 413", rec.Code)
	}
}
