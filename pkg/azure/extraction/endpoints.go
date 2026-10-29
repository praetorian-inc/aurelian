package extraction

// Resource Graph supplies untyped properties; reuse its endpoint to avoid an extra ARM read.
// Missing, empty, or mistyped values return "", so callers fall back to a typed ARM SDK
// resource lookup, which requires management-plane read permission. Callers return an
// error if that lookup fails or the SDK response also lacks an endpoint.
func endpointFromResourceProperties(properties map[string]any, path ...string) string {
	var value any = properties
	for _, key := range path {
		object, ok := value.(map[string]any)
		if !ok {
			return ""
		}
		value = object[key]
	}
	endpoint, _ := value.(string)
	return endpoint
}
