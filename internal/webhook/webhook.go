// Package webhook verifies and understands GitHub webhook deliveries.
//
// The signature is the only thing standing between the internet and a process
// that writes check runs, so it is checked before the body is parsed and before
// anything is queued. A delivery that fails verification is not logged with its
// body and never reaches the scanner.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// signatureHeader is the SHA-256 signature GitHub sends. The SHA-1 header is
// ignored: accepting both would let the weaker one decide.
const signatureHeader = "X-Hub-Signature-256"

// maxBody is the largest delivery accepted. GitHub payloads for a pull request
// are well under a megabyte, and the cap keeps a stray client from making the
// server allocate without bound.
const maxBody = 25 << 20

// Delivery is the part of a webhook payload the scanner needs.
type Delivery struct {
	// Event is the X-GitHub-Event value, such as "pull_request".
	Event string
	// ID is X-GitHub-Delivery, for logs and for recognising a redelivery.
	ID string
	// Action is the pull request action, such as "opened".
	Action string

	// InstallationID is the app installation that should be charged for the
	// API calls, and is the id an installation token is minted for.
	InstallationID int64

	// Repo is the base repository, owner/name. The check run is posted here,
	// because that is where the pull request lives and where the ruleset looks.
	Repo  string
	Owner string
	Name  string
	// Number is the pull request number.
	Number int

	// HeadSHA is the commit the check run is attached to. For a fork it is a
	// commit in the fork, which is why HeadRepo is recorded separately.
	HeadSHA string
	// BaseSHA is the commit the pull request is based on.
	BaseSHA string
	// HeadRepo is the fork, owner/name, or the base repository when the branch
	// is in the same repository.
	HeadRepo string
	// IsFork is true when the head is in a different repository.
	IsFork bool
	// Sender is the login that triggered the delivery.
	Sender string
}

// ShouldScan reports whether this delivery is a pull request change worth
// checking.
//
// Only actions that can change the files are scanned. A label or a comment does
// not create a new commit, and re-scanning on every one of them would spend an
// installation token on a result that cannot have changed.
//
// Drafts are scanned. A draft can still be merged once it is marked ready, and
// a check that only runs after that leaves the author waiting for a result at
// the worst moment.
func (d Delivery) ShouldScan() bool {
	if d.Event != "pull_request" {
		return false
	}
	if d.HeadSHA == "" || d.Repo == "" || d.InstallationID <= 0 || d.Number <= 0 {
		return false
	}
	switch d.Action {
	case "opened", "synchronize", "reopened", "ready_for_review":
		return true
	default:
		return false
	}
}

// Verify checks the HMAC on a delivery body.
//
// GitHub signs the bytes it sent, so the caller must verify before decoding.
// An empty secret is treated as misconfiguration and verifies nothing.
func Verify(secret, body []byte, header string) bool {
	if len(secret) == 0 {
		return false
	}
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil || len(got) != sha256.Size {
		return false
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// Parse reads the fields the scanner needs from a pull request payload.
//
// It accepts the delivery only after the signature has been verified. The
// payload is decoded into a purpose-built shape rather than into a model of the
// whole event, so a field this server does not use cannot influence it.
func Parse(event, id string, body []byte) (Delivery, error) {
	d := Delivery{Event: event, ID: id}

	var payload struct {
		Action       string `json:"action"`
		Number       int    `json:"number"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		Repository struct {
			FullName string `json:"full_name"`
			Name     string `json:"name"`
			Owner    struct {
				Login string `json:"login"`
			} `json:"owner"`
		} `json:"repository"`
		PullRequest struct {
			Draft bool `json:"draft"`
			Head  struct {
				SHA  string `json:"sha"`
				Repo *struct {
					FullName string `json:"full_name"`
					Fork     bool   `json:"fork"`
				} `json:"repo"`
			} `json:"head"`
			Base struct {
				SHA  string `json:"sha"`
				Repo *struct {
					FullName string `json:"full_name"`
				} `json:"repo"`
			} `json:"base"`
			User struct {
				Login string `json:"login"`
			} `json:"user"`
		} `json:"pull_request"`
		Sender struct {
			Login string `json:"login"`
		} `json:"sender"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return d, fmt.Errorf("decoding the delivery: %w", err)
	}

	d.Action = payload.Action
	d.Number = payload.Number
	d.InstallationID = payload.Installation.ID
	d.HeadSHA = payload.PullRequest.Head.SHA
	d.BaseSHA = payload.PullRequest.Base.SHA
	d.Sender = payload.Sender.Login
	if d.Sender == "" {
		d.Sender = payload.PullRequest.User.Login
	}

	// The base repository is the one the check belongs to. Prefer the explicit
	// owner and name, and fall back to splitting full_name if an event omits
	// them, which some GitHub Enterprise versions do.
	d.Owner = payload.Repository.Owner.Login
	d.Name = payload.Repository.Name
	d.Repo = payload.Repository.FullName
	if d.Owner == "" || d.Name == "" {
		owner, name, ok := splitRepo(d.Repo)
		if !ok {
			return d, errors.New("the delivery does not name a repository")
		}
		d.Owner, d.Name = owner, name
	}
	if d.Repo == "" {
		d.Repo = d.Owner + "/" + d.Name
	}

	// head.repo is null when a fork was deleted. Leaving HeadRepo empty makes
	// the fetch fail closed rather than scanning the base by mistake.
	if payload.PullRequest.Head.Repo != nil {
		d.HeadRepo = payload.PullRequest.Head.Repo.FullName
	}
	if d.HeadRepo == "" {
		d.HeadRepo = d.Repo
	}
	d.IsFork = d.HeadRepo != d.Repo
	if d.HeadRepo == "" {
		d.IsFork = false
	}

	return d, nil
}

func splitRepo(full string) (string, string, bool) {
	owner, name, ok := strings.Cut(full, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	return owner, name, true
}

// Handler receives deliveries, verifies them and queues the ones that matter.
//
// It deliberately does no scanning itself. GitHub expects a webhook response
// within ten seconds, and a scan downloads a tarball and calls the API; doing
// that inline would make GitHub time out and redeliver, which is how one push
// becomes three scans.
type Handler struct {
	// Secret is the webhook secret configured on the app.
	Secret []byte
	// Queue receives the deliveries that should be scanned. It must be bounded,
	// and a full queue is reported as unavailable so GitHub retries.
	Queue chan<- Delivery
	// MaxBody caps the request body. Zero uses 25 MiB.
	MaxBody int64
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := h.MaxBody
	if limit <= 0 {
		limit = maxBody
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "could not read the body", http.StatusBadRequest)
		return
	}

	if !Verify(h.Secret, body, r.Header.Get(signatureHeader)) {
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}

	event := r.Header.Get("X-GitHub-Event")
	deliveryID := r.Header.Get("X-GitHub-Delivery")

	// A ping is how GitHub checks that the endpoint exists and the secret is
	// right. It carries no pull request and should still be a success.
	if event == "ping" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong\n"))
		return
	}

	delivery, err := Parse(event, deliveryID, body)
	if err != nil {
		http.Error(w, "malformed delivery", http.StatusBadRequest)
		return
	}
	if !delivery.ShouldScan() {
		// Accepted and ignored. A 2xx tells GitHub not to redeliver an event
		// this server will never act on.
		w.WriteHeader(http.StatusAccepted)
		return
	}

	select {
	case h.Queue <- delivery:
		w.WriteHeader(http.StatusAccepted)
	default:
		// The queue is bounded so that a burst cannot exhaust memory. Saying so
		// with 503 is the one response that makes GitHub retry, which is what
		// should happen to a delivery that was not accepted.
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}
}
