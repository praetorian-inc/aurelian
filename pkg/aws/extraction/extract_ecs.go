package extraction

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("AWS::ECS::TaskDefinition", "ecs-task-definition", extractECS)
}

func extractECS(_ extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	if len(r.Properties) == 0 {
		return nil
	}

	data, err := json.Marshal(r.Properties)
	if err != nil {
		return fmt.Errorf("failed to marshal ECS task definition properties: %w", err)
	}

	out.Send(output.ScanInputFromAWSResource(r, "TaskDefinition", data))
	return nil
}
