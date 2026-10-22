package repofetch

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

func tarball(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, e := range entries {
		mode := int64(0o644)
		if e.typeflag == tar.TypeDir {
			mode = 0o755
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     mode,
			Size:     int64(len(e.body)),
			Typeflag: e.typeflag,
			Linkname: e.linkname,
		}
		if e.typeflag == tar.TypeDir || e.typeflag == tar.TypeSymlink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func serve(t *testing.T, body []byte, wantPath, wantAuth string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			t.Errorf("path is %s, want %s", r.URL.Path, wantPath)
		}
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Errorf("authorization is %q, want %q", got, wantAuth)
		}
		w.Write(body)
	}))
}

func TestFetchExtractsTheTreeWithoutTheTopDirectory(t *testing.T) {
	body := tarball(t,
		entry{name: "o-r-abc/", typeflag: tar.TypeDir},
		entry{name: "o-r-abc/.github/workflows/ci.yml", body: "on: push\n", typeflag: tar.TypeReg},
		entry{name: "o-r-abc/README.md", body: "hi\n", typeflag: tar.TypeReg},
	)
	server := serve(t, body, "/o/r/tar.gz/abc", "Bearer tok")
	defer server.Close()

	f := New()
	f.BaseURL = server.URL
	tree, err := f.Fetch(context.Background(), "o", "r", "abc", "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()

	data, err := os.ReadFile(filepath.Join(tree.Dir, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "on: push\n" {
		t.Errorf("file is %q", data)
	}
}

func TestFetchSkipsLinks(t *testing.T) {
	body := tarball(t,
		entry{name: "o-r-abc/", typeflag: tar.TypeDir},
		entry{name: "o-r-abc/real.yml", body: "on: push\n", typeflag: tar.TypeReg},
		entry{name: "o-r-abc/link.yml", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		entry{name: "o-r-abc/hard.yml", typeflag: tar.TypeLink, linkname: "o-r-abc/real.yml"},
	)
	server := serve(t, body, "/o/r/tar.gz/abc", "")
	defer server.Close()

	f := New()
	f.BaseURL = server.URL
	tree, err := f.Fetch(context.Background(), "o", "r", "abc", "")
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()

	if _, err := os.Lstat(filepath.Join(tree.Dir, "link.yml")); !os.IsNotExist(err) {
		t.Error("a symlink was extracted")
	}
	if _, err := os.Lstat(filepath.Join(tree.Dir, "hard.yml")); !os.IsNotExist(err) {
		t.Error("a hard link was extracted")
	}
	if _, err := os.Stat(filepath.Join(tree.Dir, "real.yml")); err != nil {
		t.Error(err)
	}
}

func TestFetchRefusesAnEscapingPath(t *testing.T) {
	for name, entries := range map[string][]entry{
		"parent": {
			{name: "o-r-abc/", typeflag: tar.TypeDir},
			{name: "o-r-abc/../../evil.yml", body: "x", typeflag: tar.TypeReg},
		},
		"absolute": {
			{name: "/etc/evil.yml", body: "x", typeflag: tar.TypeReg},
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := serve(t, tarball(t, entries...), "/o/r/tar.gz/abc", "")
			defer server.Close()

			f := New()
			f.BaseURL = server.URL
			tree, err := f.Fetch(context.Background(), "o", "r", "abc", "")
			if err == nil {
				tree.Close()
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), "refusing") {
				t.Errorf("error is %q", err)
			}
		})
	}
}

func TestFetchCapsTheDownload(t *testing.T) {
	// Highly compressible content so that the tarball is small but the
	// extracted size is not.
	body := tarball(t,
		entry{name: "o-r-abc/", typeflag: tar.TypeDir},
		entry{name: "o-r-abc/big.yml", body: strings.Repeat("a", 4096), typeflag: tar.TypeReg},
	)
	server := serve(t, body, "/o/r/tar.gz/abc", "")
	defer server.Close()

	f := New()
	f.BaseURL = server.URL
	f.MaxCompressed = 10

	if _, err := f.Fetch(context.Background(), "o", "r", "abc", ""); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("error is %q", err)
	}
}

func TestFetchCapsTheExtractedSize(t *testing.T) {
	body := tarball(t,
		entry{name: "o-r-abc/", typeflag: tar.TypeDir},
		entry{name: "o-r-abc/big.yml", body: strings.Repeat("a", 4096), typeflag: tar.TypeReg},
	)
	server := serve(t, body, "/o/r/tar.gz/abc", "")
	defer server.Close()

	f := New()
	f.BaseURL = server.URL
	f.MaxExtracted = 100

	if _, err := f.Fetch(context.Background(), "o", "r", "abc", ""); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "expands to more than") {
		t.Errorf("error is %q", err)
	}
}

func TestFetchReportsAnHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	f := New()
	f.BaseURL = server.URL
	_, err := f.Fetch(context.Background(), "o", "r", "abc", "")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error is %v", err)
	}
}

func TestCloseRemovesTheTree(t *testing.T) {
	body := tarball(t,
		entry{name: "o-r-abc/", typeflag: tar.TypeDir},
		entry{name: "o-r-abc/a.yml", body: "x", typeflag: tar.TypeReg},
	)
	server := serve(t, body, "/o/r/tar.gz/abc", "")
	defer server.Close()

	f := New()
	f.BaseURL = server.URL
	tree, err := f.Fetch(context.Background(), "o", "r", "abc", "")
	if err != nil {
		t.Fatal(err)
	}
	dir := tree.Dir
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the tree still exists: %v", err)
	}
}

func TestFetchRequiresItsArguments(t *testing.T) {
	if _, err := New().Fetch(context.Background(), "", "r", "abc", ""); err == nil {
		t.Fatal("expected an error")
	}
}
