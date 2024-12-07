package outputproviders

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"time"
)

// GetFullPath constructs the full file path from filename and output path
func GetFullPath(filename string, outputPath string) string {
	return outputPath + string(os.PathSeparator) + filename
}

// GenerateShortUUID generates a random 5-character UUID
func GenerateShortUUID() string {
	b := make([]byte, 3) // 3 bytes = 5 hex characters when truncated
	if _, err := rand.Read(b); err != nil {
		return "" // In case of error, return empty string
	}
	return hex.EncodeToString(b)[:5]
}

// DefaultFileName generates a standardized filename in the format:
// prefix-timestamp-account-uuid.extension
func DefaultFileName(prefix string, extension string) string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	uuid := GenerateShortUUID()

	return prefix + "-" + timestamp + "-" + uuid + "." + extension
}
