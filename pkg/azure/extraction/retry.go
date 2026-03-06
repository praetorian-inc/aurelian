package extraction

import (
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// newAzurePaginator returns a Paginator configured for Azure API throttling errors.
func newAzurePaginator() *ratelimit.Paginator {
	p := ratelimit.NewPaginator()
	p.ShouldRetry = azureShouldRetry
	return p
}

func azureShouldRetry(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "TooManyRequests") ||
		strings.Contains(msg, "429") ||
		strings.Contains(msg, "RequestRateTooLarge") ||
		strings.Contains(msg, "Retry-After")
}
