package cmd

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/outputters"
)

func TestSelectOutputter_NewFormats(t *testing.T) {
	tests := []struct {
		name           string
		format         string
		expectNil      bool
		expectNonNil   bool
	}{
		{
			name:         "terminal format returns constructor",
			format:       OutputFormatTerminal,
			expectNonNil: true,
		},
		{
			name:         "json format returns constructor",
			format:       OutputFormatJSON,
			expectNonNil: true,
		},
		{
			name:         "ndjson format returns constructor",
			format:       OutputFormatNDJSON,
			expectNonNil: true,
		},
		{
			name:         "markdown format returns constructor",
			format:       OutputFormatMarkdown,
			expectNonNil: true,
		},
		{
			name:         "sarif format returns constructor",
			format:       OutputFormatSARIF,
			expectNonNil: true,
		},
		{
			name:      "default format returns nil",
			format:    OutputFormatDefault,
			expectNil: true,
		},
		{
			name:      "unknown format returns nil",
			format:    "unknown",
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SelectOutputter(tt.format)

			if tt.expectNil && result != nil {
				t.Errorf("SelectOutputter(%q) = %v, want nil", tt.format, result)
			}

			if tt.expectNonNil && result == nil {
				t.Errorf("SelectOutputter(%q) = nil, want non-nil OutputterConstructor", tt.format)
			}

			// Verify the result is actually an OutputterConstructor if non-nil
			if tt.expectNonNil && result != nil {
				var _ outputters.OutputterConstructor = result
			}
		})
	}
}

func TestSelectOutputter_ReturnsValidConstructor(t *testing.T) {
	formats := []string{
		OutputFormatTerminal,
		OutputFormatJSON,
		OutputFormatNDJSON,
		OutputFormatMarkdown,
		OutputFormatSARIF,
	}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			constructor := SelectOutputter(format)
			if constructor == nil {
				t.Errorf("SelectOutputter(%q) returned nil, expected valid constructor", format)
			}

			// Verify it's a valid OutputterConstructor type
			var _ outputters.OutputterConstructor = constructor
		})
	}
}
