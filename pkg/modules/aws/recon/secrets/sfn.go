package secrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// SFNClient is the subset of the Step Functions API needed by the SFN extractor.
type SFNClient interface {
	ListExecutions(
		ctx context.Context,
		input *sfn.ListExecutionsInput,
		opts ...func(*sfn.Options),
	) (*sfn.ListExecutionsOutput, error)
	DescribeExecution(
		ctx context.Context,
		input *sfn.DescribeExecutionInput,
		opts ...func(*sfn.Options),
	) (*sfn.DescribeExecutionOutput, error)
}

// maxExecutions is the maximum number of executions to inspect per state machine.
const maxExecutions = 100

// extractSFN lists recent executions of a Step Functions state machine and
// emits each execution's input+output as a ScanInput.
func extractSFN(cfg ExtractorConfig, r output.AWSResource, out *pipeline.P[ScanInput]) error {
	awsCfg, err := cfg.AWSConfigFactory(r.Region)
	if err != nil {
		return fmt.Errorf("failed to create AWS config: %w", err)
	}
	client := sfn.NewFromConfig(awsCfg)
	return extractSFNWithClient(client, r, out)
}

// extractSFNWithClient is the testable core of the SFN extractor.
func extractSFNWithClient(client SFNClient, r output.AWSResource, out *pipeline.P[ScanInput]) error {
	stateMachineArn := r.ResourceID

	// List recent executions
	listResp, err := client.ListExecutions(context.Background(), &sfn.ListExecutionsInput{
		StateMachineArn: &stateMachineArn,
		MaxResults:      int32(maxExecutions),
	})
	if err != nil {
		return fmt.Errorf("ListExecutions failed for %s: %w", stateMachineArn, err)
	}

	if len(listResp.Executions) == 0 {
		return nil
	}

	for _, exec := range listResp.Executions {
		if exec.ExecutionArn == nil {
			continue
		}

		descResp, err := client.DescribeExecution(context.Background(), &sfn.DescribeExecutionInput{
			ExecutionArn: exec.ExecutionArn,
		})
		if err != nil {
			continue // skip executions we can't describe
		}

		// Combine input and output into a single content blob
		var parts []string
		if descResp.Input != nil && *descResp.Input != "" {
			parts = append(parts, *descResp.Input)
		}
		if descResp.Output != nil && *descResp.Output != "" {
			parts = append(parts, *descResp.Output)
		}

		if len(parts) == 0 {
			continue
		}

		content := strings.Join(parts, "\n")

		// Extract execution name from ARN for the label
		label := executionLabel(*exec.ExecutionArn)

		out.Send(ScanInput{
			Content:      []byte(content),
			ResourceID:   r.ResourceID,
			ResourceType: r.ResourceType,
			Region:       r.Region,
			AccountID:    r.AccountRef,
			Label:        label,
		})
	}

	return nil
}

// executionLabel extracts a human-readable label from an execution ARN.
// e.g. "arn:aws:states:us-east-1:123:execution:my-sm:exec-1" → "execution:exec-1"
func executionLabel(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 2 {
		return "execution:" + parts[len(parts)-1]
	}
	return "execution"
}
