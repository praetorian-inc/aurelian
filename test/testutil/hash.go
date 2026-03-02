package testutil

import (
	"crypto/md5"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// computeFixtureHash computes a deterministic MD5 hash of all files in the
// given directory. Files are sorted lexicographically by relative path, and
// each (path, contents) pair is fed into a single MD5 hash. The .terraform/
// directory and .terraform.lock.hcl are excluded.
func computeFixtureHash(dir string) (string, error) {
	type entry struct {
		relPath string
		absPath string
	}

	var entries []entry
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)

		if d.IsDir() && d.Name() == ".terraform" {
			return filepath.SkipDir
		}
		if d.Name() == ".terraform.lock.hcl" {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		entries = append(entries, entry{relPath: rel, absPath: path})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("walk fixture dir: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].relPath < entries[j].relPath
	})

	h := md5.New()
	for _, e := range entries {
		// Hash the relative path so renames/additions/deletions are detected.
		fmt.Fprintf(h, "path:%s\n", e.relPath)

		data, err := os.ReadFile(e.absPath)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", e.relPath, err)
		}
		h.Write(data)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
