package extraction

func resourcePropertyString(properties map[string]any, path ...string) string {
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
