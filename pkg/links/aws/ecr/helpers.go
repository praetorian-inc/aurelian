package ecr

import (
	"fmt"
	"regexp"
	"strings"
)

func ExtractRegion(url string) (string, error) {
	if strings.Contains(url, "public.ecr.aws") {
		return "us-east-1", nil
	}

	pattern := regexp.MustCompile(`ecr\.([-a-z0-9]+)\.amazonaws\.com`)

	matches := pattern.FindStringSubmatch(url)
	if len(matches) < 2 {
		return "", fmt.Errorf("no region found in URL: %s", url)
	}

	return matches[1], nil
}
