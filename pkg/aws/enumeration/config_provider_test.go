package enumeration

import "testing"

// TestNormalizeConfigRegion verifies the provider maps region-less sentinels used
// for global resources (empty string, and the literal "global" stamped by the IAM
// enumerator) onto us-east-1, so GetAWSConfig never hands an invalid region to
// NewAWSConfig. Real regions pass through untouched.
func TestNormalizeConfigRegion(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   string
	}{
		{"empty falls back to us-east-1", "", "us-east-1"},
		{"global sentinel falls back to us-east-1", "global", "us-east-1"},
		{"real region passes through", "eu-west-1", "eu-west-1"},
		{"us-east-1 passes through", "us-east-1", "us-east-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeConfigRegion(tt.region); got != tt.want {
				t.Errorf("normalizeConfigRegion(%q) = %q, want %q", tt.region, got, tt.want)
			}
		})
	}
}
