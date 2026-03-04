package extraction

import (
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

const maxExecutions = 100

func init() {
	mustRegister("AWS::StepFunctions::StateMachine", "sfn-executions", extractSFN)
}

func extractSFN(ctx extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	client := sfn.NewFromConfig(ctx.AWSConfig)
	stateMachineARN := r.ResourceID
	listResp, err := client.ListExecutions(ctx.Context, &sfn.ListExecutionsInput{StateMachineArn: &stateMachineARN, MaxResults: int32(maxExecutions)})
	if err != nil {
		return fmt.Errorf("ListExecutions failed for %s: %w", stateMachineARN, err)
	}

	emptyExecutions := len(listResp.Executions) == 0
	if emptyExecutions {
		return nil
	}

	g := new(errgroup.Group)
	g.SetLimit(ctx.Concurrency)

	for _, exec := range listResp.Executions {
		exec := exec
		missingExecutionArn := exec.ExecutionArn == nil
		if missingExecutionArn {
			continue
		}

		g.Go(func() error {
			describeExecution(ctx, client, exec, r, out)
			return nil
		})
	}

	return g.Wait()
}

func describeExecution(ctx extractContext, client *sfn.Client, exec sfntypes.ExecutionListItem, r output.AWSResource, out *pipeline.P[output.ScanInput]) {
	descResp, err := client.DescribeExecution(ctx.Context, &sfn.DescribeExecutionInput{ExecutionArn: exec.ExecutionArn})
	if err != nil {
		return
	}

	var parts []string
	if descResp.Input != nil && *descResp.Input != "" {
		parts = append(parts, *descResp.Input)
	}
	if descResp.Output != nil && *descResp.Output != "" {
		parts = append(parts, *descResp.Output)
	}

	emptyParts := len(parts) == 0
	if emptyParts {
		return
	}

	label := sfnExecutionLabel(*exec.ExecutionArn)
	out.Send(output.ScanInputFromAWSResource(r, label, []byte(strings.Join(parts, "\n"))))
}

func sfnExecutionLabel(arn string) string {
	parts := strings.Split(arn, ":")
	hasSuffix := len(parts) >= 2
	if !hasSuffix {
		return "execution"
	}

	return "execution:" + parts[len(parts)-1]
}
