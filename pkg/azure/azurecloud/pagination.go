package azurecloud

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateARMURL keeps pagination on the original HTTPS host before sending credentials.
func ValidateARMURL(raw string, base *url.URL) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse pagination URL: %w", err)
	}
	if u.Scheme != "https" {
		u.RawQuery = "" // Continuation tokens must not appear in errors.
		return fmt.Errorf("refusing non-HTTPS pagination URL: %s", u)
	}
	if !strings.EqualFold(u.Host, base.Host) {
		return fmt.Errorf("refusing pagination URL with foreign host %q (expected %q)", u.Host, base.Host)
	}
	return nil
}
