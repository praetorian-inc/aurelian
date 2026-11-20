package software

// DecodeForTest exposes what a resource type's decoders extracted — product and
// version — *before* the CPE dictionary is consulted.
//
// The decoding logic and the resolution rule fail independently: EKS, Lambda
// and OpenSearch report minor-only versions that no live dictionary entry
// carries, so Detect emits nothing for them even when the decoder read them
// correctly. Without this seam those decoders would be untestable, and widening
// the resolution rule later would mean rewriting them.
func DecodeForTest(resourceType string, props map[string]any) (product, version string) {
	return decode(resourceType, props)
}
