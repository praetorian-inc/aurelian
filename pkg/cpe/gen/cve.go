package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// cveChunk is one NVD CVE 2.0 feed file, or one /cves/2.0 REST response — they
// share a schema. Only the applicability statements are read; nothing else in
// a CVE record bears on which vendor spellings exist.
type cveChunk struct {
	Vulnerabilities []struct {
		CVE struct {
			ID             string      `json:"id"`
			Configurations []cveConfig `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type cveConfig struct {
	Nodes []cveNode `json:"nodes"`
}

type cveNode struct {
	CPEMatch []struct {
		Criteria string `json:"criteria"`
	} `json:"cpeMatch"`
	Children []cveNode `json:"children"`
}

// maxNodeDepth bounds the children walk. NVD's own schema nests two levels
// ("application running on platform"); the bound only has to stop a
// pathological document, not to be tight.
const maxNodeDepth = 32

// HarvestCVEChunk accumulates the (product, vendor) pairs cited by one CVE 2.0
// feed file into `into`, alongside whatever the dictionary pass recorded.
//
// This source exists because the CPE dictionary and the CVE corpus disagree
// about which names exist, and the CVE corpus is the one that decides whether
// an emission matches. Measured 2026-11-24 over 19 products, ten vendor
// spellings are cited by live CVE configurations and carry no dictionary
// record at all — not a deprecated one, not any:
//
//	sun:openjdk                      17 CVEs
//	yukihiro_matsumoto:ruby           8
//	memcachedb:memcached              4
//	php_group:php                     3
//	a1webserver:http_server           2
//	bughunter:http_server             2
//	nginx:nginx                       2
//	python_software_foundation:python 2
//	mongodb:node.js                   1
//	zeroo:http_server                 1
//
// Most are historical vendor renames NVD never back-filled into old
// configurations (Sun -> Oracle, PHP Group -> PHP, Matsumoto -> ruby-lang).
// The rest are unrelated software that happens to share a product name. Both
// are harmless to record and necessary to emit: a table built from the
// dictionary alone can never reach those CVEs, and the homonyms are inert
// because the version does the filtering at resolution time
// (see pkg/cpe/cpemap.go).
//
// Only `part == "a"` entries are kept, matching the dictionary pass.
func HarvestCVEChunk(body []byte, into Table) error {
	var chunk cveChunk
	if err := json.Unmarshal(body, &chunk); err != nil {
		return fmt.Errorf("parse cve chunk: %w", err)
	}

	for _, v := range chunk.Vulnerabilities {
		for _, cfg := range v.CVE.Configurations {
			for _, node := range cfg.Nodes {
				harvestNode(node, into, 0)
			}
		}
	}
	return nil
}

func harvestNode(node cveNode, into Table, depth int) {
	if depth > maxNodeDepth {
		return
	}
	for _, m := range node.CPEMatch {
		// A criteria string is a CPE 2.3 formatted name whose version
		// components may be wildcards bounded by the sibling
		// versionStartIncluding/versionEndExcluding fields. Only the vendor
		// and product are read here, so those bounds are irrelevant.
		_, product, vendor, _, ok := splitCPE(m.Criteria)
		if !ok {
			continue
		}
		record(into, product, vendor)
	}
	for _, child := range node.Children {
		harvestNode(child, into, depth+1)
	}
}

// harvestCVEFeeds streams every yearly NVD CVE 2.0 feed into `into`.
//
// The feeds are plain gzipped JSON (nvdcve-2.0-YYYY.json.gz), anonymous and
// unauthenticated, about 250 MB compressed in total. Each is cached under
// os.UserCacheDir() keyed on its sibling .meta sha256, exactly as the CPE
// archive is, so a regeneration after a dictionary-only change re-downloads
// nothing but the current year.
//
// The year range ends at the current year rather than at a constant: a feed
// for a year NVD has not published yet 404s, and a hardcoded end would stop
// harvesting on New Year's Day without failing anything.
func harvestCVEFeeds(into Table) error {
	last := time.Now().UTC().Year()
	for year := firstCVEYear; year <= last; year++ {
		body, err := cachedCVEYear(year)
		if err != nil {
			return fmt.Errorf("cve feed %d: %w", year, err)
		}
		if err := HarvestCVEChunk(body, into); err != nil {
			return fmt.Errorf("cve feed %d: %w", year, err)
		}
		log.Printf("cve %d: %d products so far", year, len(into))
	}
	return nil
}

// cachedCVEYear returns one year's decompressed feed, downloading it only when
// the published sha256 differs from the cached copy's key.
//
// As with the CPE archive, the sha256 is a cache *key*, not an integrity
// check: NVD's published digest covers neither downloadable artifact. What
// guards the content is HTTPS transport integrity to nvd.nist.gov plus the
// minCVEVendorProducts floor in main.
func cachedCVEYear(year int) ([]byte, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("locate user cache dir: %w", err)
	}
	dir := filepath.Join(base, "aurelian", "nvd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	url := fmt.Sprintf(cveFeedBase, year)
	path := filepath.Join(dir, fmt.Sprintf("nvdcve-2.0-%d.json.gz", year))
	keyPath := path + ".meta-sha256"

	want, err := cveMetaSHA(url + ".meta")
	if err != nil {
		return nil, err
	}

	if got, err := os.ReadFile(keyPath); err != nil || strings.TrimSpace(string(got)) != want {
		if err := downloadTo(url+".json.gz", path); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, []byte(want+"\n"), 0o644); err != nil {
			return nil, fmt.Errorf("record cache key: %w", err)
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = gz.Close() }()
	return io.ReadAll(gz)
}

func cveMetaSHA(url string) (string, error) {
	body, err := get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = body.Close() }()
	raw, err := io.ReadAll(body)
	if err != nil {
		return "", fmt.Errorf("read meta: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == "sha256" {
			return strings.ToLower(v), nil
		}
	}
	return "", fmt.Errorf("meta %s carries no sha256", url)
}

// downloadTo writes url to path through a temporary file, so an interrupted
// download never leaves a short file that the next run would read as cached.
func downloadTo(url, path string) error {
	log.Printf("downloading %s", url)
	body, err := get(url)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.part")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	if _, err := io.Copy(tmp, body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("download %s: %w", url, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}
