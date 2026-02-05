package outputters

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func TestFormatterAdapter_OutputRisk(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &buf,
	})
	if err != nil {
		t.Fatalf("failed to create formatter: %v", err)
	}

	adapter := NewFormatterAdapter(f, &buf)
	if err := adapter.Initialize(plugin.Config{}); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	risk := &output.Risk{
		Name:        "test-risk",
		Status:      "TH",
		Description: "Test description",
		Target: &output.CloudResource{
			ResourceID:   "arn:aws:s3:::test-bucket",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
			AccountRef:   "123456789012",
		},
	}

	if err := adapter.Output(risk); err != nil {
		t.Fatalf("Output failed: %v", err)
	}

	if err := adapter.Complete(); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("expected output, got empty buffer")
	}
}

func TestNewFormatterAdapterConstructor(t *testing.T) {
	// Call the constructor factory with JSON format
	var buf bytes.Buffer
	constructor := NewFormatterAdapterConstructor("json", &buf)

	// Call the constructor to create an outputter
	outputter := constructor()

	// Verify it returns a non-nil FormatterAdapter
	if outputter == nil {
		t.Fatal("expected non-nil outputter, got nil")
	}

	// Type assert to ensure it's a FormatterAdapter
	adapter, ok := outputter.(*FormatterAdapter)
	if !ok {
		t.Fatalf("expected *FormatterAdapter, got %T", outputter)
	}

	// Verify the adapter has a formatter
	if adapter.formatter == nil {
		t.Error("expected adapter to have non-nil formatter")
	}
}

func TestFormatterAdapter_formatRaw(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &buf,
	})
	if err != nil {
		t.Fatalf("failed to create formatter: %v", err)
	}

	adapter := NewFormatterAdapter(f, &buf)
	if err := adapter.Initialize(plugin.Config{}); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Test raw output
	data := map[string]any{"status": "success", "arn": "arn:aws:sts::123456789012:assumed-role/test"}
	err = adapter.formatRaw(data)
	if err != nil {
		t.Fatalf("formatRaw failed: %v", err)
	}

	if err := adapter.Complete(); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	// Verify output contains raw data, not Finding wrapper
	output := buf.String()
	if output == "" {
		t.Error("expected output, got empty buffer")
	}
	// The output should contain the data field
	// We're not checking exact format since formatRaw implementation may vary
	// Just ensure it's not the "Unknown finding type" wrapper
	if bytes.Contains(buf.Bytes(), []byte("Unknown finding type")) {
		t.Error("output should not contain 'Unknown finding type' wrapper")
	}
}

func TestFormatterAdapter_OutputRawOutput(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &buf,
	})
	if err != nil {
		t.Fatalf("failed to create formatter: %v", err)
	}

	adapter := NewFormatterAdapter(f, &buf)
	if err := adapter.Initialize(plugin.Config{}); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Test RawOutput marker
	data := map[string]any{"status": "success", "arn": "arn:aws:sts::123456789012:assumed-role/test"}
	err = adapter.Output(RawOutput{Data: data})
	if err != nil {
		t.Fatalf("Output failed: %v", err)
	}

	if err := adapter.Complete(); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	// Verify raw data in output, not "Unknown finding type"
	output := buf.String()
	if output == "" {
		t.Error("expected output, got empty buffer")
	}
	// Should NOT contain "Unknown finding type" wrapper
	if bytes.Contains(buf.Bytes(), []byte("Unknown finding type")) {
		t.Error("output should not contain 'Unknown finding type' wrapper")
	}
}

func TestFormatterAdapter_RawOutput_NoFindingWrapper(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &buf,
	})
	if err != nil {
		t.Fatalf("failed to create formatter: %v", err)
	}

	adapter := NewFormatterAdapter(f, &buf)
	if err := adapter.Initialize(plugin.Config{}); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Create test data matching whoami output
	data := map[string]any{
		"status":  "no_error_found",
		"message": "API calls succeeded",
		"action":  "all",
	}

	// Output using RawOutput marker
	err = adapter.Output(RawOutput{Data: data})
	if err != nil {
		t.Fatalf("Output failed: %v", err)
	}

	if err := adapter.Complete(); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	// Parse the JSON output
	output := buf.String()
	if output == "" {
		t.Fatal("expected output, got empty buffer")
	}

	var result []map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nOutput: %s", err, output)
	}

	// Should have exactly one element in the array
	if len(result) != 1 {
		t.Fatalf("expected 1 element in array, got %d", len(result))
	}

	// The first element should be the raw data directly, NOT wrapped in a Finding
	firstElement := result[0]

	// CRITICAL: Should NOT have Finding wrapper fields
	if _, hasID := firstElement["id"]; hasID && firstElement["id"] == "raw" {
		t.Error("output should not have 'id': 'raw' - this indicates Finding wrapper")
	}
	if _, hasMetadata := firstElement["metadata"]; hasMetadata {
		t.Error("output should not have 'metadata' field - this indicates Finding wrapper")
	}

	// SHOULD have the raw data fields directly
	if status, ok := firstElement["status"].(string); !ok || status != "no_error_found" {
		t.Errorf("expected status='no_error_found', got %v", firstElement["status"])
	}
	if message, ok := firstElement["message"].(string); !ok || message != "API calls succeeded" {
		t.Errorf("expected message='API calls succeeded', got %v", firstElement["message"])
	}
	if action, ok := firstElement["action"].(string); !ok || action != "all" {
		t.Errorf("expected action='all', got %v", firstElement["action"])
	}
}
