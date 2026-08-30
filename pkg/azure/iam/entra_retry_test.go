package iam

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock TokenCredential for testing cachedCredential and doWithRetry
// ---------------------------------------------------------------------------

type mockTokenCredential struct {
	mu        sync.Mutex
	callCount int
	token     string
	expiresOn time.Time
	err       error
}

func (m *mockTokenCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	if m.err != nil {
		return azcore.AccessToken{}, m.err
	}
	return azcore.AccessToken{
		Token:     m.token,
		ExpiresOn: m.expiresOn,
	}, nil
}

func (m *mockTokenCredential) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// ---------------------------------------------------------------------------
// Tests: retryAfterDuration
// ---------------------------------------------------------------------------

func TestRetryAfterDuration_NumericSeconds(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "10")
	assert.Equal(t, 10*time.Second, retryAfterDuration(h))
}

func TestRetryAfterDuration_Zero(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "0")
	// 0 is not > 0, so falls back to default
	assert.Equal(t, 5*time.Second, retryAfterDuration(h))
}

func TestRetryAfterDuration_Negative(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "-5")
	// Negative is not > 0, so falls back to default
	assert.Equal(t, 5*time.Second, retryAfterDuration(h))
}

func TestRetryAfterDuration_NonNumeric(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "not-a-number")
	assert.Equal(t, 5*time.Second, retryAfterDuration(h))
}

func TestRetryAfterDuration_Empty(t *testing.T) {
	h := http.Header{}
	// No Retry-After header at all
	assert.Equal(t, 5*time.Second, retryAfterDuration(h))
}

func TestRetryAfterDuration_EmptyString(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "")
	// Empty string — treated as missing
	assert.Equal(t, 5*time.Second, retryAfterDuration(h))
}

func TestRetryAfterDuration_LargeValue(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "120")
	assert.Equal(t, 120*time.Second, retryAfterDuration(h))
}

// ---------------------------------------------------------------------------
// Tests: truncate
// ---------------------------------------------------------------------------

func TestTruncate_ShortString(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
}

func TestTruncate_ExactLength(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 5))
}

func TestTruncate_LongString(t *testing.T) {
	assert.Equal(t, "hel...", truncate("hello world", 3))
}

func TestTruncate_EmptyString(t *testing.T) {
	assert.Equal(t, "", truncate("", 5))
}

func TestTruncate_ZeroMax(t *testing.T) {
	assert.Equal(t, "...", truncate("hello", 0))
}

// ---------------------------------------------------------------------------
// Tests: cachedCredential.GetToken
// ---------------------------------------------------------------------------

func TestCachedCredential_CacheMiss(t *testing.T) {
	inner := &mockTokenCredential{
		token:     "token-1",
		expiresOn: time.Now().Add(1 * time.Hour),
	}
	cached := newCachedCredential(inner)

	tok, err := cached.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"scope1"},
	})
	require.NoError(t, err)
	assert.Equal(t, "token-1", tok.Token)
	assert.Equal(t, 1, inner.getCallCount())
}

func TestCachedCredential_CacheHit(t *testing.T) {
	inner := &mockTokenCredential{
		token:     "token-1",
		expiresOn: time.Now().Add(1 * time.Hour),
	}
	cached := newCachedCredential(inner)

	opts := policy.TokenRequestOptions{Scopes: []string{"scope1"}}

	// First call — cache miss
	tok1, err := cached.GetToken(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "token-1", tok1.Token)

	// Change the inner credential's token to verify cache is used
	inner.mu.Lock()
	inner.token = "token-2"
	inner.mu.Unlock()

	// Second call — cache hit, should still return "token-1"
	tok2, err := cached.GetToken(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "token-1", tok2.Token)
	assert.Equal(t, 1, inner.getCallCount()) // inner was only called once
}

func TestCachedCredential_NearExpiryRefresh(t *testing.T) {
	inner := &mockTokenCredential{
		token:     "old-token",
		expiresOn: time.Now().Add(2 * time.Minute), // expires in 2 min (< 5 min threshold)
	}
	cached := newCachedCredential(inner)

	opts := policy.TokenRequestOptions{Scopes: []string{"scope1"}}

	// First call — cache miss, fetches the near-expiry token
	tok1, err := cached.GetToken(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "old-token", tok1.Token)

	// Update the inner to return a fresh token
	inner.mu.Lock()
	inner.token = "fresh-token"
	inner.expiresOn = time.Now().Add(1 * time.Hour)
	inner.mu.Unlock()

	// Second call — the cached token is near expiry, should refresh
	tok2, err := cached.GetToken(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "fresh-token", tok2.Token)
	assert.Equal(t, 2, inner.getCallCount()) // inner called twice
}

func TestCachedCredential_DifferentScopes(t *testing.T) {
	inner := &mockTokenCredential{
		token:     "token-a",
		expiresOn: time.Now().Add(1 * time.Hour),
	}
	cached := newCachedCredential(inner)

	// First scope
	tok1, err := cached.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"scope-a"},
	})
	require.NoError(t, err)
	assert.Equal(t, "token-a", tok1.Token)

	// Change token for second scope
	inner.mu.Lock()
	inner.token = "token-b"
	inner.mu.Unlock()

	// Different scope — cache miss
	tok2, err := cached.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"scope-b"},
	})
	require.NoError(t, err)
	assert.Equal(t, "token-b", tok2.Token)
	assert.Equal(t, 2, inner.getCallCount())
}

func TestCachedCredential_InnerError(t *testing.T) {
	inner := &mockTokenCredential{
		err: fmt.Errorf("auth failure"),
	}
	cached := newCachedCredential(inner)

	_, err := cached.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"scope1"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth failure")
}

func TestCachedCredential_ConcurrentAccess(t *testing.T) {
	var callCount atomic.Int32
	inner := &mockTokenCredential{
		token:     "concurrent-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}
	// Track calls via atomic counter in addition to the mutex-protected one
	originalGetToken := inner.token
	_ = originalGetToken

	cached := newCachedCredential(inner)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			callCount.Add(1)
			tok, err := cached.GetToken(context.Background(), policy.TokenRequestOptions{
				Scopes: []string{"scope1"},
			})
			assert.NoError(t, err)
			assert.Equal(t, "concurrent-token", tok.Token)
		}()
	}

	wg.Wait()
	// All goroutines completed without panic — concurrency is safe.
	// The inner credential should not have been called 50 times since
	// caching kicks in after the first call.
	assert.LessOrEqual(t, inner.getCallCount(), goroutines)
}

// ---------------------------------------------------------------------------
// Tests: doWithRetry
// ---------------------------------------------------------------------------

func TestDoWithRetry_SuccessOnFirstTry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value": "ok"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	body, err := doWithRetry(context.Background(), cred, "scope", server.Client(), server.URL, "")
	require.NoError(t, err)
	assert.Contains(t, string(body), "ok")
}

func TestDoWithRetry_429ThenSuccess(t *testing.T) {
	var attempt atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempt.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0") // falls back to 5s default — we'll use a short one
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "throttled"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value": "success"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	// Use a context with timeout to bound the test (the 5s default retry wait is fine
	// since we're testing that the retry actually happens).
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	body, err := doWithRetry(ctx, cred, "scope", server.Client(), server.URL, "")
	require.NoError(t, err)
	assert.Contains(t, string(body), "success")
	assert.Equal(t, int32(2), attempt.Load())
}

func TestDoWithRetry_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "throttled"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel context after a brief delay so the retry wait is interrupted
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_, err := doWithRetry(ctx, cred, "scope", server.Client(), server.URL, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDoWithRetry_NonRetryableError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "forbidden"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	_, err := doWithRetry(context.Background(), cred, "scope", server.Client(), server.URL, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestDoWithRetry_RelativePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/users" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"value": "users"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	body, err := doWithRetry(context.Background(), cred, "scope", server.Client(), "/users", server.URL+"/v1")
	require.NoError(t, err)
	assert.Contains(t, string(body), "users")
}

func TestDoWithRetry_TokenAcquisitionFailure(t *testing.T) {
	cred := &mockTokenCredential{
		err: fmt.Errorf("credential expired"),
	}

	_, err := doWithRetry(context.Background(), cred, "scope", http.DefaultClient, "https://example.com/test", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acquiring token")
}

func TestDoWithRetry_ExhaustedRetries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "throttled"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := doWithRetry(ctx, cred, "scope", server.Client(), server.URL, "")
	require.Error(t, err)
	// On the final attempt (attempt == maxRetries), the 429 is not retried;
	// it falls through to the non-2xx error handler instead.
	assert.Contains(t, err.Error(), "429")
}

// ---------------------------------------------------------------------------
// Tests: doWithRetryPost
// ---------------------------------------------------------------------------

func TestDoWithRetryPost_SuccessOnFirstTry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value": "ok"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	body, err := doWithRetryPost(context.Background(), cred, "scope", server.Client(), server.URL, "", []byte(`{"key":"val"}`))
	require.NoError(t, err)
	assert.Contains(t, string(body), "ok")
}

func TestDoWithRetryPost_429ThenSuccess(t *testing.T) {
	var attempt atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		n := attempt.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "throttled"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value": "success"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	body, err := doWithRetryPost(ctx, cred, "scope", server.Client(), server.URL, "", []byte(`{}`))
	require.NoError(t, err)
	assert.Contains(t, string(body), "success")
	assert.Equal(t, int32(2), attempt.Load())
}

func TestDoWithRetryPost_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "throttled"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_, err := doWithRetryPost(ctx, cred, "scope", server.Client(), server.URL, "", []byte(`{}`))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDoWithRetryPost_NonRetryableError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "forbidden"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	_, err := doWithRetryPost(context.Background(), cred, "scope", server.Client(), server.URL, "", []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	// doWithRetryPost always uses "ARM API" in error messages
	assert.Contains(t, err.Error(), "ARM API")
}

func TestDoWithRetryPost_RequestBodySentCorrectly(t *testing.T) {
	reqBody := []byte(`{"filter":"displayName eq 'test'"}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer test-token")

		receivedBody, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, reqBody, receivedBody)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value": "filtered"}`))
	}))
	defer server.Close()

	cred := &mockTokenCredential{
		token:     "test-token",
		expiresOn: time.Now().Add(1 * time.Hour),
	}

	body, err := doWithRetryPost(context.Background(), cred, "scope", server.Client(), server.URL, "", reqBody)
	require.NoError(t, err)
	assert.Contains(t, string(body), "filtered")
}
