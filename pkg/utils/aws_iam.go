package utils

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func GaadReplaceURLEncodedPolicies(data []byte) ([]byte, error) {
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	var decode func(interface{}) interface{}
	decode = func(v interface{}) interface{} {
		switch val := v.(type) {
		case map[string]interface{}:
			for k, v := range val {
				if str, ok := v.(string); ok && strings.HasPrefix(str, "%7B") {
					decoded, err := url.QueryUnescape(str)
					if err == nil {
						var policy interface{}
						if err := json.Unmarshal([]byte(decoded), &policy); err == nil {
							val[k] = policy
						}
					}
				} else {
					val[k] = decode(v)
				}
			}
			return val
		case []interface{}:
			for i, item := range val {
				val[i] = decode(item)
			}
			return val
		default:
			return v
		}
	}

	jsonData = decode(jsonData)
	return json.Marshal(jsonData)
}
