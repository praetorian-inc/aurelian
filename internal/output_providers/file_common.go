package outputproviders

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/praetorian-inc/nebula/internal/helpers"
)

// GetFullPath constructs the full file path from filename and output path
func GetFullPath(filename string, outputPath string) string {
	return outputPath + string(os.PathSeparator) + filename
}

// DefaultFileName generates a standardized filename in the format:
// prefix-accountid-timestamp.extension
func DefaultFileName(prefix string, extension string) string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Get AWS config and account ID using existing helper
	cfg, err := helpers.GetAWSCfg("", "")
	if err != nil {
		return fmt.Sprintf("%s-%s-%s.%s", prefix, "unknown", timestamp, extension)
	}

	accountId, err := helpers.GetAccountId(cfg)
	if err != nil {
		accountId = "unknown"
	}

	return fmt.Sprintf("%s-%s-%s.%s", prefix, accountId, timestamp, extension)
}
