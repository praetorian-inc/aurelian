package aws

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/nebula/pkg/types"
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
	if erd.TypeName == "AWS::Service" {
		return erd.Identifier
	}
	return erd.Arn.String()
}
