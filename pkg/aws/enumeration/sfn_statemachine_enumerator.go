package enumeration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// SFNStateMachineEnumerator enumerates Step Functions state machines using the native
// Step Functions SDK. State machines have no resource policy; they are emitted so the
// resource_service_role enricher can link a state machine to the IAM role it RUNS AS
// (DescribeStateMachine.RoleArn) via a (StateMachine)-[:HAS_ROLE]->(Role) edge, which
// the stepfunctions privesc methods re-point their CAN_PRIVESC edge at.
//
// ListStateMachines summaries do NOT include the role, so each is described per-ARN via
// DescribeStateMachine.
type SFNStateMachineEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewSFNStateMachineEnumerator creates an SFNStateMachineEnumerator that uses the native Step Functions SDK.
func NewSFNStateMachineEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *SFNStateMachineEnumerator {
	return &SFNStateMachineEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for Step Functions state machines.
func (l *SFNStateMachineEnumerator) ResourceType() string {
	return "AWS::StepFunctions::StateMachine"
}

// EnumerateByARN describes a single state machine by ARN and emits it.
func (l *SFNStateMachineEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}
	if _, ok := strings.CutPrefix(parsed.Resource, "stateMachine:"); !ok {
		return fmt.Errorf("invalid step functions state machine ARN resource: %q", parsed.Resource)
	}
	if parsed.Region == "" {
		return fmt.Errorf("step functions state machine ARN missing region: %q", arn)
	}

	cfg, err := l.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create Step Functions client for %s: %w", parsed.Region, err)
	}
	client := sfn.NewFromConfig(*cfg)
	result, err := describeStateMachineWithKMSFallback(client, aws.String(arn))
	if err != nil {
		if op := ClassifySkippable(err, "stepfunctions", "DescribeStateMachine", parsed.Region); op != nil {
			l.skipReport.Record(*op)
			return nil
		}
		return fmt.Errorf("describe state machine %s: %w", arn, err)
	}

	resource := buildSFNStateMachineResource(result, parsed.AccountID, parsed.Region)
	l.stampLastModified(client, parsed.Region, &resource, result)
	out.Send(resource)
	return nil
}

// EnumerateAll enumerates all Step Functions state machines owned by the account across configured regions.
func (l *SFNStateMachineEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listStateMachinesInRegion(region, accountID, out)
	})
}

func (l *SFNStateMachineEnumerator) listStateMachinesInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create Step Functions client for %s: %w", region, err)
	}
	client := sfn.NewFromConfig(*cfg)

	paginator := sfn.NewListStateMachinesPaginator(client, &sfn.ListStateMachinesInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "stepfunctions", "ListStateMachines", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list state machines in %s: %w", region, err)
		}
		for _, summary := range page.StateMachines {
			arn := aws.ToString(summary.StateMachineArn)
			if arn == "" {
				continue
			}
			detail, err := describeStateMachineWithKMSFallback(client, summary.StateMachineArn)
			if err != nil {
				if op := ClassifySkippable(err, "stepfunctions", "DescribeStateMachine", region); op != nil {
					skipped = append(skipped, *op)
					continue
				}
				return fmt.Errorf("describe state machine %s in %s: %w", arn, region, err)
			}
			resource := buildSFNStateMachineResource(detail, accountID, region)
			l.stampLastModified(client, region, &resource, detail)
			out.Send(resource)
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

// describeStateMachineWithKMSFallback calls DescribeStateMachine with full data.
// If the call fails due to a KMS permission or state error (encrypted state machine
// the caller cannot decrypt), it retries with METADATA_ONLY to still capture the
// machine's name, ARN, and RoleArn without requiring kms:Decrypt.
func describeStateMachineWithKMSFallback(client *sfn.Client, machineARN *string) (*sfn.DescribeStateMachineOutput, error) {
	result, err := client.DescribeStateMachine(context.Background(), &sfn.DescribeStateMachineInput{
		StateMachineArn: machineARN,
	})
	if err != nil && isKMSError(err) {
		return client.DescribeStateMachine(context.Background(), &sfn.DescribeStateMachineInput{
			StateMachineArn: machineARN,
			IncludedData:    sfntypes.IncludedDataMetadataOnly,
		})
	}
	return result, err
}

func isKMSError(err error) bool {
	var kmsAccess *sfntypes.KmsAccessDeniedException
	var kmsState *sfntypes.KmsInvalidStateException
	var kmsThrottle *sfntypes.KmsThrottlingException
	return errors.As(err, &kmsAccess) || errors.As(err, &kmsState) || errors.As(err, &kmsThrottle)
}

func buildSFNStateMachineResource(detail *sfn.DescribeStateMachineOutput, accountID, region string) output.AWSResource {
	name := aws.ToString(detail.Name)

	// StateMachineArn is the full ARN; fall back to a synthesized ARN if absent so the
	// node still keys cleanly (DescribeStateMachine always returns the ARN).
	arn := aws.ToString(detail.StateMachineArn)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:states:%s:%s:stateMachine:%s", region, accountID, name)
	}

	return output.AWSResource{
		ResourceType: "AWS::StepFunctions::StateMachine",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"Name": name,
			// RoleArn is the role the state machine's executions assume;
			// resource_service_role.yaml substring-matches this quoted ARN value inside the
			// flattened `properties` JSON string to create the (StateMachine)-[:HAS_ROLE]->(Role) edge.
			"RoleArn": aws.ToString(detail.RoleArn),
		},
	}
}

// stampLastModified sets r.LastModified to the later of the newest execution's
// start and stop times, falling back to the state machine's CreationDate when
// it has never run.
//
// find-secrets scans execution input and output only (see extractSFN), so the
// newest execution bounds everything it can read; the definition is never
// scanned, so UpdateStateMachine needs no signal here. A machine with no
// executions yields no scan input at all, and CreationDate is a safe floor for
// it. The CreationDate comes from the DescribeStateMachine this enumerator
// already makes, so stamping costs one ListExecutions per state machine.
//
// A failure affects only this resource: it is recorded or logged and
// LastModified is left nil, so the state machine is always scanned.
func (l *SFNStateMachineEnumerator) stampLastModified(client *sfn.Client, region string, r *output.AWSResource, detail *sfn.DescribeStateMachineOutput) {
	// ListExecutions returns the most recent execution first.
	resp, err := client.ListExecutions(context.Background(), &sfn.ListExecutionsInput{
		StateMachineArn: aws.String(r.ARN),
		MaxResults:      1,
	})
	if err != nil {
		if op := ClassifySkippable(err, "stepfunctions", "ListExecutions", region); op != nil {
			l.skipReport.Record(*op)
			return
		}
		logTimestampFailure(slog.LevelWarn, err, "stepfunctions", "ListExecutions", region, r)
		return
	}

	if len(resp.Executions) > 0 {
		newest := resp.Executions[0]
		if newest.StartDate == nil {
			logTimestampFailure(slog.LevelError, fmt.Errorf("ListExecutions returned execution %s of %s without StartDate",
				aws.ToString(newest.ExecutionArn), r.ARN), "", "", region, r)
			return
		}
		latest := *newest.StartDate
		if newest.StopDate != nil && newest.StopDate.After(latest) {
			latest = *newest.StopDate
		}
		r.LastModified = &latest
		return
	}

	if detail.CreationDate == nil {
		logTimestampFailure(slog.LevelError, fmt.Errorf("DescribeStateMachine returned %s in %s without CreationDate",
			r.ARN, region), "", "", region, r)
		return
	}
	created := *detail.CreationDate
	r.LastModified = &created
}
