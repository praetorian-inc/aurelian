package test

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/praetorian-inc/nebula/pkg/utils"
)

func TestPerformJqQuery(t *testing.T) {
	// Create a temporary JSON file for testing
	jsonContent := `{"name": "John", "age": 30}`
	tempFile, err := os.CreateTemp("", "test.json")
	if err != nil {
		t.Fatalf("Error creating temporary file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	tempFile.Write([]byte(jsonContent))

	// Define the test cases
	testCases := []struct {
		filePath   string
		jqQuery    string
		expected   []byte
		expectErr  bool
		errMessage string
	}{
		// Test case 1: Valid query
		{
			filePath:   tempFile.Name(),
			jqQuery:    ".age",
			expected:   []byte("30"),
			expectErr:  false,
			errMessage: "",
		},
		// Test case 2: Invalid query
		{
			filePath:   tempFile.Name(),
			jqQuery:    ".nonexistent",
			expected:   nil,
			expectErr:  true,
			errMessage: "key not found",
		},
		// Test case 3: Nonexistent file
		{
			filePath:   "nonexistent.json",
			jqQuery:    ".age",
			expected:   nil,
			expectErr:  true,
			errMessage: "open nonexistent.json: no such file or directory",
		},
	}

	// Run the test cases
	for _, tc := range testCases {
		fmt.Println("tc.filePath: ", tc.filePath)
		fmt.Println("tc.jqQuery: ", tc.jqQuery)
		result, err := utils.PerformJqQueryOnFile(tc.filePath, tc.jqQuery)

		if tc.expectErr {
			if err == nil {
				t.Errorf("Expected an error, but got none")
			} else if tc.errMessage != "" && err.Error() != tc.errMessage {
				t.Errorf("Expected error message '%s', but got '%s'", tc.errMessage, err.Error())
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			} else if !bytes.Equal(result, tc.expected) {
				t.Errorf("Expected '%s', but got '%v'", tc.expected, result)
				fmt.Printf("result: [%v]\n", result)
			}
		}
	}
}
