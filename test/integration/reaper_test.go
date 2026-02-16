//go:build integration

package integration

import (
	"testing"
	"time"
)

func TestParseStateKey(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		wantOK    bool
		wantMod   string
		wantTime  time.Time
	}{
		{
			name:     "valid aws/list key",
			key:      "integration-tests/aws/list/20260213T181726-565711354f37962c/terraform.tfstate",
			wantOK:   true,
			wantMod:  "aws/list",
			wantTime: time.Date(2026, 2, 13, 18, 17, 26, 0, time.UTC),
		},
		{
			name:     "valid aws/gaad key",
			key:      "integration-tests/aws/gaad/20260101T000000-abcdef0123456789/terraform.tfstate",
			wantOK:   true,
			wantMod:  "aws/gaad",
			wantTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "deeper module path",
			key:      "integration-tests/aws/deep/nested/module/20260615T120000-aabbccdd11223344/terraform.tfstate",
			wantOK:   true,
			wantMod:  "aws/deep/nested/module",
			wantTime: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		},
		{
			name:   "missing prefix",
			key:    "other-prefix/aws/list/20260213T181726-565711354f37962c/terraform.tfstate",
			wantOK: false,
		},
		{
			name:   "missing terraform.tfstate suffix",
			key:    "integration-tests/aws/list/20260213T181726-565711354f37962c/other.file",
			wantOK: false,
		},
		{
			name:   "no module dir (too few segments)",
			key:    "integration-tests/20260213T181726-565711354f37962c/terraform.tfstate",
			wantOK: false,
		},
		{
			name:   "invalid timestamp",
			key:    "integration-tests/aws/list/notadate-565711354f37962c/terraform.tfstate",
			wantOK: false,
		},
		{
			name:   "no dash in timestamp-runid segment",
			key:    "integration-tests/aws/list/20260213T181726abcdef01/terraform.tfstate",
			wantOK: false,
		},
		{
			name:   "empty key",
			key:    "",
			wantOK: false,
		},
		{
			name:   "just the prefix",
			key:    "integration-tests/",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stack, ok := parseStateKey(tt.key)
			if ok != tt.wantOK {
				t.Fatalf("parseStateKey(%q) ok = %v, want %v", tt.key, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if stack.moduleDir != tt.wantMod {
				t.Errorf("moduleDir = %q, want %q", stack.moduleDir, tt.wantMod)
			}
			if !stack.timestamp.Equal(tt.wantTime) {
				t.Errorf("timestamp = %v, want %v", stack.timestamp, tt.wantTime)
			}
			if stack.stateKey != tt.key {
				t.Errorf("stateKey = %q, want %q", stack.stateKey, tt.key)
			}
		})
	}
}
