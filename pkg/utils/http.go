package utils

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

func Cached_httpGet(url string) ([]byte, error) {

	if IsCacheValid(CreateCachedFileName(url)) {
		return ReadCache(CreateCachedFileName(url))
	} else {
		res, err := http.Get(url)
		if err != nil {
			return nil, err
		}

		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			slog.Error(fmt.Sprintf("Error reading response body: %v", err))
		}

		WriteCache(CreateCachedFileName(url), body)
		return body, nil
	}
}
