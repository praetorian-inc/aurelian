// raw_output_test.go
package outputters

import (
	"testing"
)

func TestRawOutput_Wrapping(t *testing.T) {
	data := map[string]any{"status": "success", "arn": "arn:aws:sts::123456789012:assumed-role/test"}
	raw := RawOutput{Data: data}

	if raw.Data == nil {
		t.Error("expected data to be wrapped, got nil")
	}

	actualData, ok := raw.Data.(map[string]any)
	if !ok {
		t.Errorf("expected map[string]any, got %T", raw.Data)
	}

	if actualData["status"] != "success" {
		t.Errorf("expected status='success', got %v", actualData["status"])
	}

	if actualData["arn"] != "arn:aws:sts::123456789012:assumed-role/test" {
		t.Errorf("expected specific ARN, got %v", actualData["arn"])
	}
}

func TestNewRawOutput_Constructor(t *testing.T) {
	data := map[string]any{"key": "value"}
	raw := NewRawOutput(data)

	if raw.Data == nil {
		t.Error("expected data to be wrapped, got nil")
	}

	actualData, ok := raw.Data.(map[string]any)
	if !ok {
		t.Errorf("expected map[string]any, got %T", raw.Data)
	}

	if actualData["key"] != "value" {
		t.Errorf("expected key='value', got %v", actualData["key"])
	}
}
