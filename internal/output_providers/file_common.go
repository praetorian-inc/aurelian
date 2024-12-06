package outputproviders

import (
	"crypto/rand"
	"encoding/hex"
	"os"
)

// GetFullPath constructs the full file path from filename and output path
func GetFullPath(filename string, outputPath string) string {
	return outputPath + string(os.PathSeparator) + filename
}

// GenerateShortUUID generates a random 10-character UUID
func GenerateShortUUID() string {
	b := make([]byte, 5) // 5 bytes = 10 hex characters
	if _, err := rand.Read(b); err != nil {
		return "" // In case of error, return empty string
	}
	return hex.EncodeToString(b)
}
