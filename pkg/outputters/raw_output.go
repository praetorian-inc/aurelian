// raw_output.go
package outputters

// RawOutput is a marker type that signals FormatterAdapter to bypass
// Finding conversion and output the wrapped data directly as JSON.
//
// Use this when your command returns data that is NOT a security finding
// (Risk, SecretFinding, CloudResource) but you want it to appear in the
// output unchanged.
//
// Example:
//
//     result := map[string]any{"status": "success", "arn": arnResult}
//     return l.Send(outputters.RawOutput{Data: result})
//
// The Data field will be serialized directly to JSON without the
// Finding wrapper (no "id", "title", "severity" fields added).
type RawOutput struct {
	// Data is the raw value to output. Can be any JSON-serializable type:
	// map[string]any, []any, struct, primitive types, etc.
	Data any
}

// NewRawOutput creates a RawOutput marker wrapping the given data.
// Convenience constructor for cleaner code.
func NewRawOutput(data any) RawOutput {
	return RawOutput{Data: data}
}
