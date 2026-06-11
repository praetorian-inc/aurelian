package extraction

import (
	"encoding/json"
	"fmt"
	"strings"

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

	out.Send(output.ScanInputFromAWSResource(r, "ECS Task Definition", data))

	// json.Marshal sorts map keys, so paired env vars (e.g. an access key and its
	// secret) end up separated by structural JSON text that exceeds the proximity
	// window of secret rules like np.aws.6. Emit the container environment variables
	// as adjacent NAME=VALUE lines so paired credentials stay close enough to match.
	if envLines := ecsEnvLines(r.Properties); envLines != "" {
		out.Send(output.ScanInputFromAWSResource(r, "ECS Task Definition Env", []byte(envLines)))
	}

	return nil
}

// ecsEnvLines walks the (PascalCase, CloudControl-shaped) task definition properties
// and returns each container environment variable as a NAME=VALUE line. Missing or
// mistyped fields are skipped rather than treated as errors.
func ecsEnvLines(props map[string]any) string {
	containers, ok := props["ContainerDefinitions"].([]any)
	if !ok {
		return ""
	}

	var b strings.Builder
	for _, c := range containers {
		container, ok := c.(map[string]any)
		if !ok {
			continue
		}
		env, ok := container["Environment"].([]any)
		if !ok {
			continue
		}
		for _, e := range env {
			entry, ok := e.(map[string]any)
			if !ok {
				continue
			}
			name, ok := entry["Name"].(string)
			if !ok {
				continue
			}
			value, ok := entry["Value"].(string)
			if !ok {
				continue
			}
			b.WriteString(name)
			b.WriteByte('=')
			b.WriteString(value)
			b.WriteByte('\n')
		}
	}

	return b.String()
}
