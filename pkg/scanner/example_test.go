package scanner_test

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/scanner"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Example demonstrates how to use PersistentScanner
func ExamplePersistentScanner() {
	// Create scanner with default path
	ps, err := scanner.NewPersistentScanner("")
	if err != nil {
		fmt.Printf("Error creating scanner: %v\n", err)
		return
	}
	defer ps.Close()
	defer os.RemoveAll("aurelian-output") // Cleanup for example

	// Scan content
	content := []byte("aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{
		FilePath: "credentials.txt",
	}

	matches, err := ps.ScanContent(content, blobID, provenance)
	if err != nil {
		fmt.Printf("Error scanning: %v\n", err)
		return
	}

	fmt.Printf("Found %d matches\n", len(matches))
	fmt.Printf("Database path: %s\n", ps.DBPath())

	// Scanning again uses cached results (incremental scanning)
	cachedMatches, err := ps.ScanContent(content, blobID, provenance)
	if err != nil {
		fmt.Printf("Error scanning: %v\n", err)
		return
	}

	fmt.Printf("Cached matches: %d\n", len(cachedMatches))
}
