// Package repofetch downloads a repository at a commit and extracts it safely.
//
// The input is a tarball GitHub produced from a repository a pull request
// touched, which means both the bytes and the paths inside it are controlled by
// someone else. Extraction therefore refuses absolute paths, paths that escape
// the destination, links and special files, and caps both the compressed and
// the extracted size.
package repofetch

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultMaxCompressed = 200 << 20
	defaultMaxExtracted  = 500 << 20
	defaultMaxFiles      = 200_000
)

// Fetcher downloads repository tarballs.
type Fetcher struct {
	// Client is the HTTP client. It should have a timeout; the zero value uses
	// a client with one.
	Client *http.Client
	// BaseURL is the codeload host. Empty uses https://codeload.github.com.
	BaseURL string
	// MaxCompressed caps the download.
	MaxCompressed int64
	// MaxExtracted caps the sum of the file sizes written to disk.
	MaxExtracted int64
	// MaxFiles caps how many regular files are extracted.
	MaxFiles int
}

// New returns a Fetcher with the production limits.
func New() *Fetcher {
	return &Fetcher{
		Client:        &http.Client{Timeout: 2 * time.Minute},
		BaseURL:       "https://codeload.github.com",
		MaxCompressed: defaultMaxCompressed,
		MaxExtracted:  defaultMaxExtracted,
		MaxFiles:      defaultMaxFiles,
	}
}

// Tree is an extracted repository. Close removes it.
type Tree struct {
	Dir string

	cleanup func() error
}

// Close removes the extracted tree.
func (t *Tree) Close() error {
	if t == nil || t.cleanup == nil {
		return nil
	}
	return t.cleanup()
}

// Fetch downloads owner/repo at ref and extracts it.
//
// ref is a commit SHA. A SHA is immutable, so the tree that is scanned is the
// tree the check is posted against even if the branch moves during the scan; a
// branch name would not give that guarantee.
//
// token may be empty for a public repository. It is sent as a bearer token and
// never included in an error.
func (f *Fetcher) Fetch(ctx context.Context, owner, repo, ref, token string) (*Tree, error) {
	if owner == "" || repo == "" || ref == "" {
		return nil, errors.New("owner, repository and ref are required")
	}

	base := f.BaseURL
	if base == "" {
		base = "https://codeload.github.com"
	}
	endpoint := strings.TrimRight(base, "/") + "/" + url.PathEscape(owner) + "/" +
		url.PathEscape(repo) + "/tar.gz/" + url.PathEscape(ref)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading %s/%s at %s: %w", owner, repo, ref, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s/%s at %s: %s", owner, repo, ref, resp.Status)
	}

	maxCompressed := f.MaxCompressed
	if maxCompressed <= 0 {
		maxCompressed = defaultMaxCompressed
	}
	maxExtracted := f.MaxExtracted
	if maxExtracted <= 0 {
		maxExtracted = defaultMaxExtracted
	}
	maxFiles := f.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}

	dir, err := os.MkdirTemp("", "ppe-tree-")
	if err != nil {
		return nil, fmt.Errorf("creating a directory for the tree: %w", err)
	}
	tree := &Tree{Dir: dir, cleanup: func() error { return os.RemoveAll(dir) }}

	limited := &countingReader{r: io.LimitReader(resp.Body, maxCompressed+1)}
	if err := extract(ctx, limited, dir, maxExtracted, maxFiles); err != nil {
		tree.Close()
		// A download that hit the cap usually fails inside gzip as a truncated
		// stream. Saying "larger than" is the useful answer, and the byte count
		// is the only place that knows which happened.
		if limited.n > maxCompressed {
			return nil, fmt.Errorf("the tarball is larger than %d bytes", maxCompressed)
		}
		return nil, err
	}
	if limited.n > maxCompressed {
		tree.Close()
		return nil, fmt.Errorf("the tarball is larger than %d bytes", maxCompressed)
	}
	return tree, nil
}

// countingReader records how many bytes were read, so that a capped download
// can say it was capped rather than looking like a corrupt archive.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func extract(ctx context.Context, r io.Reader, root string, maxExtracted int64, maxFiles int) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("reading the tarball: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var total int64
	files := 0

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading the tarball: %w", err)
		}

		if path.IsAbs(hdr.Name) {
			return fmt.Errorf("refusing absolute path %q from the tarball", hdr.Name)
		}

		rel, ok := stripTop(hdr.Name)
		if !ok {
			// The tarball's root directory itself, or an entry with no path
			// below it. Neither is a file to extract.
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := safeMkdir(root, rel); err != nil {
				return err
			}
		case tar.TypeReg:
			files++
			if files > maxFiles {
				return fmt.Errorf("the tarball has more than %d files", maxFiles)
			}
			total += hdr.Size
			if total > maxExtracted {
				return fmt.Errorf("the tarball expands to more than %d bytes", maxExtracted)
			}
			if err := safeWrite(root, rel, tr, hdr.Size); err != nil {
				return err
			}
		default:
			// Symlinks, hard links, devices and anything else are skipped.
			// A repository can contain them, but a scan only needs regular
			// files, and following a link out of the tree would let a pull
			// request read the runner.
			continue
		}
	}
}

// stripTop removes the single top-level directory GitHub puts around a
// tarball, so that .github/workflows is directly under the returned root.
func stripTop(name string) (string, bool) {
	name = strings.TrimPrefix(name, "./")
	_, rest, ok := strings.Cut(name, "/")
	if !ok || rest == "" {
		return "", false
	}
	return rest, true
}

func safeMkdir(root, rel string) error {
	target, err := safePath(root, rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", rel, err)
	}
	return nil
}

func safeWrite(root, rel string, r io.Reader, size int64) error {
	target, err := safePath(root, rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", rel, err)
	}

	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating %s: %w", rel, err)
	}
	defer file.Close()

	if _, err := io.CopyN(file, r, size); err != nil {
		return fmt.Errorf("writing %s: %w", rel, err)
	}
	return nil
}

// safePath turns a tar entry name into a path under root, or refuses.
func safePath(root, rel string) (string, error) {
	clean := path.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return "", fmt.Errorf("refusing path %q from the tarball", rel)
	}

	target := filepath.Join(root, filepath.FromSlash(clean))
	back, err := filepath.Rel(root, target)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("refusing path %q from the tarball", rel)
	}
	return target, nil
}
