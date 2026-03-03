package extraction

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("AWS::SSM::Document", "ssm-document", extractSSM)
}

func extractSSM(_ extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	if len(r.Properties) == 0 {
		return nil
	}

	data, err := json.Marshal(r.Properties)
	if err != nil {
		return fmt.Errorf("failed to marshal SSM document properties: %w", err)
	}

	out.Send(output.ScanInput{Content: data, ResourceID: r.ResourceID, ResourceType: r.ResourceType, Region: r.Region, AccountID: r.AccountRef, Label: "Document"})
	return nil
}
