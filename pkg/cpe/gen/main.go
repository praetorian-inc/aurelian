// Command gen regenerates pkg/cpe/cpemap.json.gz and pkg/cpe/snapshot_gen.go
// from the NVD CPE dictionary bulk feed.
//
// It runs only under `go generate`. The generated table is committed, so
// `go build` and `go test` never reach the network.
//
// The feed is anonymous: no API key, no rate limiting, one conditional request.
// The 85 MB archive is cached under os.UserCacheDir() and re-downloaded only
// when the feed's .meta sha256 changes.
package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	metaURL     = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta"
	archiveURL  = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
	userAgent   = "aurelian-cpegen"
	minProducts = 40000
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatalf("cpegen: %v", err)
	}
}

func run() error {
	meta, err := fetchMeta()
	if err != nil {
		return err
	}
	log.Printf("feed snapshot %s sha256 %s", meta.lastModified, meta.sha256[:16])

	archive, err := cachedArchive(meta)
	if err != nil {
		return err
	}
	defer archive.Close()

	// Two passes over the archive. A rename chain spans chunks — igor_sysoev:nginx
	// is in chunk 1 while the nginx:nginx records it points at span chunks 1-8,
	// with no live nginx:nginx record anywhere — so the whole feed's deprecation
	// edges must be known before any chunk is distilled. Resolving per chunk
	// stops the walk early and records a deprecated vendor as live, which is the
	// nginx:nginx-instead-of-f5:nginx mis-vendoring the design forbids.
	idx := DeprecationIndex{}
	chunks, err := eachChunk(archive, func(body []byte) error { return IndexChunk(body, idx) })
	if err != nil {
		return err
	}
	log.Printf("indexed %d chunks, %d dictionary names", chunks, len(idx))

	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind archive: %w", err)
	}

	table := Table{}
	chunks, err = eachChunk(archive, func(body []byte) error {
		return DistillChunkWithIndex(body, table, idx)
	})
	if err != nil {
		return err
	}
	log.Printf("distilled %d chunks into %d products", chunks, len(table))

	if len(table) < minProducts {
		return fmt.Errorf("table holds %d products, fewer than the %d sanity floor: truncated download or schema change",
			len(table), minProducts)
	}

	// `go generate` runs a directive with the working directory set to the
	// package that holds it, i.e. pkg/cpe. An explicit argument overrides that
	// for a manual `go run ./pkg/cpe/gen <dir>` from the repository root.
	outDir := "."
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := writeTable(filepath.Join(outDir, "cpemap.json.gz"), table); err != nil {
		return err
	}
	return writeSnapshot(filepath.Join(outDir, "snapshot_gen.go"), meta.lastModified)
}

type feedMeta struct {
	lastModified string
	sha256       string
}

func fetchMeta() (feedMeta, error) {
	body, err := get(metaURL)
	if err != nil {
		return feedMeta{}, err
	}
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil {
		return feedMeta{}, fmt.Errorf("read meta: %w", err)
	}
	var m feedMeta
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch k {
		case "lastModifiedDate":
			m.lastModified = v
		case "sha256":
			m.sha256 = strings.ToLower(v)
		}
	}
	if m.lastModified == "" || m.sha256 == "" {
		return feedMeta{}, fmt.Errorf("meta missing lastModifiedDate or sha256")
	}
	return m, nil
}

// cachedArchive returns the feed archive, downloading it only when the feed has
// changed since the cached copy was taken.
//
// The meta's sha256 is used as a cache *key*, not as an integrity check.
// Measured 2026-11-20: the published sha256 (8ad6fb1b…) matches neither
// nvdcpe-2.0.tar.gz (a558025f…) nor nvdcpe-2.0.zip (6d428615…), so it covers
// neither artifact a client can download and cannot verify what we fetch. The
// defences that remain are HTTPS transport integrity to nvd.nist.gov and the
// minProducts sanity floor, which fails the build on a truncated or corrupt
// archive rather than silently shrinking coverage.
func cachedArchive(meta feedMeta) (*os.File, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("locate user cache dir: %w", err)
	}
	dir := filepath.Join(base, "aurelian", "nvd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	path := filepath.Join(dir, "nvdcpe-2.0.tar.gz")
	keyPath := path + ".meta-sha256"

	if key, err := os.ReadFile(keyPath); err == nil && strings.TrimSpace(string(key)) == meta.sha256 {
		if f, err := os.Open(path); err == nil {
			log.Printf("cache hit: %s", path)
			return f, nil
		}
	}

	log.Printf("downloading %s (~85 MB)", archiveURL)
	body, err := get(archiveURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	tmp, err := os.CreateTemp(dir, "nvdcpe-*.part")
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}
	if _, err := io.Copy(tmp, body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("download archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("install archive: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(meta.sha256+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("record cache key: %w", err)
	}
	return os.Open(path)
}

// eachChunk streams the gzipped tar and hands every JSON member to fn. A
// product's vendors and versions span chunks, so callers accumulate across
// them rather than taking any one file as complete.
func eachChunk(r io.Reader, fn func(body []byte) error) (int, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, fmt.Errorf("open archive gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	chunks := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return chunks, fmt.Errorf("read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".json") {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return chunks, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		if err := fn(body); err != nil {
			return chunks, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		chunks++
	}
	return chunks, nil
}

// writeTable writes product -> vendor -> sorted versions as gzipped JSON.
// Map keys are emitted sorted by encoding/json and version slices are sorted
// explicitly, so regenerating an unchanged feed produces an identical file.
func writeTable(path string, table Table) error {
	out := make(map[string]map[string][]string, len(table))
	for product, byVendor := range table {
		vendors := make(map[string][]string, len(byVendor))
		for vendor, versions := range byVendor {
			vs := make([]string, 0, len(versions))
			for v := range versions {
				vs = append(vs, v)
			}
			sort.Strings(vs)
			vendors[vendor] = vs
		}
		out[product] = vendors
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	// Fixed compression level and no gzip header timestamp, so the bytes are a
	// pure function of the feed.
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	gz.ModTime = time.Time{}
	enc := json.NewEncoder(gz)
	if err := enc.Encode(out); err != nil {
		gz.Close()
		return fmt.Errorf("encode table: %w", err)
	}
	return gz.Close()
}

func writeSnapshot(path, lastModified string) error {
	const tmpl = `// Code generated by pkg/cpe/gen. DO NOT EDIT.

package cpe

// NVDSnapshot is the lastModifiedDate of the NVD CPE dictionary feed that
// cpemap.json.gz was distilled from.
const NVDSnapshot = %q
`
	return os.WriteFile(path, []byte(fmt.Sprintf(tmpl, lastModified)), 0o644)
}

func get(url string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}
