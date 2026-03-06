package gcperrors

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDisabledAPI(t *testing.T) {
	assert.True(t, IsDisabledAPI(fmt.Errorf("googleapi: Error 403: Cloud Functions API has not been used in project 123 before or it is disabled, forbidden")))
	assert.False(t, IsDisabledAPI(fmt.Errorf("some other error")))
	assert.False(t, IsDisabledAPI(nil))
}

func TestIsPermissionDenied(t *testing.T) {
	assert.True(t, IsPermissionDenied(fmt.Errorf("googleapi: Error 403: The caller does not have permission, forbidden")))
	assert.False(t, IsPermissionDenied(fmt.Errorf("some other error")))
	assert.False(t, IsPermissionDenied(nil))
}

func TestIsQuotaExceeded(t *testing.T) {
	assert.True(t, IsQuotaExceeded(fmt.Errorf("googleapi: Error 429: RATE_LIMIT_EXCEEDED")))
	assert.True(t, IsQuotaExceeded(fmt.Errorf("googleapi: Error 429: QUOTA_EXCEEDED")))
	assert.True(t, IsQuotaExceeded(fmt.Errorf("googleapi: Error 429: rateLimitExceeded")))
	assert.False(t, IsQuotaExceeded(fmt.Errorf("some other error")))
	assert.False(t, IsQuotaExceeded(nil))
}

func TestShouldSkip(t *testing.T) {
	assert.True(t, ShouldSkip(fmt.Errorf("googleapi: Error 403: API has not been used, forbidden")))
	assert.True(t, ShouldSkip(fmt.Errorf("googleapi: Error 403: PERMISSION_DENIED")))
	assert.False(t, ShouldSkip(fmt.Errorf("connection timeout")))
	assert.False(t, ShouldSkip(nil))
}
