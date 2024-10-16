package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/itchyny/gojq"
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
	query, err := gojq.Parse(jqQuery)
	if err != nil {
		return nil, err
	}

	var jsonData interface{}
	if err := json.Unmarshal(jsonContent, &jsonData); err != nil {
		return nil, err
	}

	iter := query.Run(jsonData)
	// Process the JSON content using the jq query
	v, ok := iter.Next()
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	if err, ok := v.(error); ok {
		if err, ok := err.(*gojq.HaltError); ok && err.Value() == nil {
			return nil, err
		}
		log.Fatalln(err)
	}
	fmt.Printf("%#v\n", v)

	result, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return result, nil

}
