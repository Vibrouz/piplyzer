package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Vibrouz/whoa/internal/appauth"
	"github.com/Vibrouz/whoa/internal/check"
	"github.com/Vibrouz/whoa/internal/engine"
	"github.com/Vibrouz/whoa/internal/parse"
	"github.com/Vibrouz/whoa/internal/repofetch"
	"github.com/Vibrouz/whoa/internal/webhook"
)

// serve is the entry point for "ppe serve".
//
// It is the external check: GitHub calls this process when a pull request
// changes, and the process posts a check run on the commit. Because the check
// is posted by an app rather than by a workflow, a pull request cannot remove
// the check by editing the workflow that would have run it.
//
// The configuration is environment only, for the same reason the CLI's
// environment is injected in tests: a secret is not something to put on a
// command line where it lands in the process list and the shell history.
func serve(cmd command, _ io.Writer, stderr io.Writer, env func(string) string) int {
	secret := env("PPE_WEBHOOK_SECRET")
	if secret == "" {
		fmt.Fprintln(stderr, "ppe: PPE_WEBHOOK_SECRET is not set")
		return exitIncomplete
	}

	cfg, err := appauth.Load(env("PPE_APP_ID"), env("PPE_PRIVATE_KEY_PATH"))
	if err != nil {
		fmt.Fprintf(stderr, "ppe: %v\n", err)
		return exitIncomplete
	}

	logger := log.New(stderr, "ppe: ", log.LstdFlags)
	srv := newServer(serverOptions{
		Addr:    cmd.addr,
		Workers: cmd.workers,
		Timeout: cmd.timeout,
		Secret:  []byte(secret),
		Auth:    appauth.NewClient(cfg),
		Fetcher: repofetch.New(),
		Log:     logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Printf("listening on %s", cmd.addr)
	if err := srv.run(ctx); err != nil {
		fmt.Fprintf(stderr, "ppe: %v\n", err)
		return exitIncomplete
	}
	return exitOK
}

// serverOptions is everything the server needs, so that a test can build one
// without a process, a signal, or a real GitHub.
type serverOptions struct {
	Addr    string
	Workers int
	Timeout time.Duration
	Secret  []byte
	Auth    *appauth.Client
	Fetcher *repofetch.Fetcher
	// CheckBaseURL overrides the API used to post check runs. Empty uses
	// api.github.com.
	CheckBaseURL string
	Log          *log.Logger
}

type server struct {
	http    *http.Server
	queue   chan webhook.Delivery
	workers int
	scan    *scanner
	log     *log.Logger
}

func newServer(opts serverOptions) *server {
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 60 * time.Second
	}
	if opts.Log == nil {
		opts.Log = log.New(io.Discard, "", 0)
	}

	queue := make(chan webhook.Delivery, 128)
	sc := &scanner{
		auth:         opts.Auth,
		fetcher:      opts.Fetcher,
		checkBaseURL: opts.CheckBaseURL,
		timeout:      opts.Timeout,
		log:          opts.Log,
	}

	mux := http.NewServeMux()
	mux.Handle("/webhook", &webhook.Handler{Secret: opts.Secret, Queue: queue})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Write([]byte("ok\n"))
	})

	return &server{
		http: &http.Server{
			Addr:              opts.Addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		queue:   queue,
		workers: opts.Workers,
		scan:    sc,
		log:     opts.Log,
	}
}

// run serves until ctx is cancelled or the listener fails.
func (s *server) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.work(ctx)
		}()
	}

	shutdown := make(chan struct{})
	go func() {
		defer close(shutdown)
		<-ctx.Done()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		s.http.Shutdown(shutCtx)
	}()

	err := s.http.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	cancel()
	<-shutdown
	wg.Wait()
	return err
}

// work takes deliveries until the context is cancelled.
//
// The queue is not closed on shutdown. A handler that is still running could
// otherwise send on a closed channel, and cancelling the context already tells
// every worker to stop.
func (s *server) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-s.queue:
			s.scan.process(ctx, d)
		}
	}
}

// scanner turns one delivery into one check run.
type scanner struct {
	auth         *appauth.Client
	fetcher      *repofetch.Fetcher
	checkBaseURL string
	timeout      time.Duration
	log          *log.Logger
}

func (s *scanner) process(ctx context.Context, d webhook.Delivery) {
	if s.auth == nil || s.fetcher == nil {
		s.log.Printf("delivery=%s: the scanner is not configured", d.ID)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	token, err := s.auth.Token(ctx, d.InstallationID)
	if err != nil {
		// Without a token there is nothing to post with, so this is the one
		// failure that cannot become a check run.
		s.log.Printf("delivery=%s repo=%s pr=%d: %v", d.ID, d.Repo, d.Number, err)
		return
	}

	tree, err := s.fetch(ctx, d, token)
	if err != nil {
		s.log.Printf("delivery=%s repo=%s pr=%d: %v", d.ID, d.Repo, d.Number, err)
		s.fail(d, token, "Could not fetch the pull request", err)
		return
	}
	defer tree.Close()

	rep, err := engine.Tree(tree.Dir)
	if err != nil {
		s.log.Printf("delivery=%s repo=%s pr=%d: %v", d.ID, d.Repo, d.Number, err)
		s.fail(d, token, "Could not read the pull request", err)
		return
	}

	repo, _ := parse.ParseRepository(d.Repo)
	result := check.Result{
		Scan:       engine.Scan(rep.Sources, repo),
		Unreadable: rep.Unreadable,
	}

	// The dependency check compares against a base commit when it can. A
	// tarball has no history, so only the checks that need no diff run here.
	// A missing lockfile is not a gap: most repositories have no npm packages.
	if hasLockfile(tree.Dir) {
		result.HasLockfile = true
		deps, depsErr := engine.CheckDeps(tree.Dir, engine.DepsOptions{NoDiff: true})
		if depsErr != nil {
			result.DepsErr = depsErr
		} else {
			result.Deps = deps
		}
	}

	conclusion, out := check.Evaluate(result)
	if err := s.post(d, token, conclusion, out); err != nil {
		s.log.Printf("delivery=%s repo=%s pr=%d: %v", d.ID, d.Repo, d.Number, err)
		return
	}
	s.log.Printf("delivery=%s repo=%s pr=%d head=%s conclusion=%s",
		d.ID, d.Repo, d.Number, shortSHA(d.HeadSHA), conclusion)
}

// fetch downloads the commit the check is attached to.
//
// The first attempt is against the base repository, because a pull request
// head is reachable there through refs/pull/N/head. A fork that is public is
// fetched directly when that fails. A private fork the app cannot see fails
// both ways, and the check says so rather than scanning the wrong tree.
func (s *scanner) fetch(ctx context.Context, d webhook.Delivery, token string) (*repofetch.Tree, error) {
	tree, err := s.fetcher.Fetch(ctx, d.Owner, d.Name, d.HeadSHA, token)
	if err == nil {
		return tree, nil
	}
	if !d.IsFork {
		return nil, err
	}

	owner, name, ok := splitRepo(d.HeadRepo)
	if !ok {
		return nil, err
	}
	forkTree, forkErr := s.fetcher.Fetch(ctx, owner, name, d.HeadSHA, token)
	if forkErr == nil {
		return forkTree, nil
	}
	return nil, fmt.Errorf("%v; and from the fork: %w", err, forkErr)
}

// post publishes the result.
//
// It uses its own context rather than the scan's. A scan that timed out still
// has to report a failure, and cancelling the post along with the scan would
// leave the pull request with no check at all.
func (s *scanner) post(d webhook.Delivery, token string, conclusion check.Conclusion, out check.Output) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := check.NewClient(token)
	if s.checkBaseURL != "" {
		client.BaseURL = s.checkBaseURL
	}
	_, err := client.Post(ctx, d.Owner, d.Name, check.Run{
		HeadSHA:    d.HeadSHA,
		Conclusion: conclusion,
		Output:     out,
	})
	return err
}

func (s *scanner) fail(d webhook.Delivery, token, title string, cause error) {
	if err := s.post(d, token, check.Failure, check.Output{
		Title:   title,
		Summary: "The check could not run, so this pull request is not known to be safe.",
		Text:    "### Not checked\n\n- " + oneLine(cause.Error()) + "\n",
	}); err != nil {
		s.log.Printf("delivery=%s repo=%s pr=%d: %v", d.ID, d.Repo, d.Number, err)
	}
}

func hasLockfile(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "package-lock.json"))
	return err == nil && info.Mode().IsRegular()
}

func splitRepo(full string) (string, string, bool) {
	owner, name, ok := strings.Cut(full, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	return owner, name, true
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// oneLine collapses whitespace so that an error cannot break the check text.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
