package software

// DecodeForTest exposes what a resource type's decoders extracted — product
// and version — *before* resolution. It keeps decoder tests independent of the
// vendor table, which fans one product out to a CPE per vendor and changes
// whenever the NVD feed is regenerated.
func DecodeForTest(resourceType string, props map[string]any) (product, version string) {
	return decode(resourceType, props)
}
