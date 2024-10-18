package utils

import (
	"fmt"
	"io"
	"net/http"

	"github.com/praetorian-inc/nebula/internal/logs"
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
			logs.ConsoleLogger().Error(fmt.Sprintf("Error reading response body: %v", err))
		}

		WriteCache(CreateCachedFileName(url), body)
		return body, nil
	}
}
