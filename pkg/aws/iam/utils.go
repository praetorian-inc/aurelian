package iam

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// Helper function to extract account ID from ARN
func getAccountFromArn(arnStr string) string {
	a, err := arn.Parse(arnStr)
	if err != nil {
		return ""
	}
	return a.AccountID
}

func deepCopy(src, dst any) error {
	if src == nil || dst == nil {
		return fmt.Errorf("src and dst cannot be nil")
	}
	if srcType, dstType := fmt.Sprintf("%T", src), fmt.Sprintf("%T", dst); srcType != dstType {
		return fmt.Errorf("type mismatch: src is %s, dst is %s", srcType, dstType)
	}
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func getIdentifierForEvalRequest(erd *types.EnrichedResourceDescription) string {
	return erd.Arn.String()
}

func LoadJSONFile[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &result, nil
}
