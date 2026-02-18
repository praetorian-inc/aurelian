package secrets

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// downloadURL fetches the content at the given URL. Used for Lambda presigned code URLs.
func downloadURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	// Limit to 250MB to prevent memory issues
	data, err := io.ReadAll(io.LimitReader(resp.Body, 250*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return data, nil
}
