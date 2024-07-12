package jq

import (
	"os"

	"github.com/savaki/jq"
)

func PerformJqQueryOnFile(filePath string, jqQuery string) ([]byte, error) {
	// Read the content of the JSON file
	jsonContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return PerformJqQuery(jsonContent, jqQuery)
}

func PerformJqQuery(jsonContent []byte, jqQuery string) ([]byte, error) {

	// Create a new jq processor
	op, err := jq.Parse(jqQuery)
	if err != nil {
		return nil, err
	}

	// Process the JSON content using the jq query
	result, err := op.Apply(jsonContent)
	if err != nil {
		return nil, err
	}

	return result, nil
}
