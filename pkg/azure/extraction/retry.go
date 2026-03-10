package extraction

import (
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// newAzurePaginator returns a Paginator configured for Azure API throttling errors.
func newAzurePaginator() *ratelimit.Paginator {
	return ratelimit.NewAzurePaginator()
}
