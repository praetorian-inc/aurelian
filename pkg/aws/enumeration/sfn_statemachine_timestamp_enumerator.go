package enumeration

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// sfnStateMachineLastModified stamps state machines with the later of the
// newest execution's start and stop times; the extractor scans executions
// only, and the API exposes no definition revision date. A state machine with
// no executions keeps its CreationDate.
type sfnStateMachineLastModified struct {
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

func NewSFNStateMachineTimestampEnumerator(cc *CloudControlEnumerator, provider *AWSConfigProvider, skipReport *SkipReport) *CloudControlTimestampEnumerator {
	return newCloudControlTimestampEnumerator(cc, "AWS::StepFunctions::StateMachine", &sfnStateMachineLastModified{provider: provider, skipReport: skipReport})
}

// regionStamper lists the region's state machines once, and only when a
// state machine without executions needs its CreationDate.
func (s *sfnStateMachineLastModified) regionStamper(region string) stampFunc {
	var creationDates map[string]*time.Time
	loaded := false
	lookup := func(r *output.AWSResource) (*time.Time, error) {
		arn := r.ResourceID
		if !loaded {
			loaded = true
			creationDates = s.listCreationDates(region)
		}
		if creationDates == nil {
			return nil, nil
		}
		created, found := creationDates[arn]
		if !found {
			// Created after the list call; describe it directly.
			return s.describeCreationDate(region, r)
		}
		if created == nil {
			return nil, fmt.Errorf("ListStateMachines returned %s in %s without CreationDate", arn, region)
		}
		return created, nil
	}
	return func(r *output.AWSResource) error {
		return s.stamp(region, r, lookup)
	}
}

func (s *sfnStateMachineLastModified) resourceStamper(region string) stampFunc {
	return func(r *output.AWSResource) error {
		return s.stamp(region, r, func(r *output.AWSResource) (*time.Time, error) {
			return s.describeCreationDate(region, r)
		})
	}
}

// creationDateLookup returns (nil, nil) when the call failed and was recorded.
type creationDateLookup func(r *output.AWSResource) (*time.Time, error)

func (s *sfnStateMachineLastModified) stamp(region string, r *output.AWSResource, creationDate creationDateLookup) error {
	// CloudControl's identifier for a state machine is its ARN.
	arn := r.ResourceID

	client, err := s.client(region)
	if err != nil {
		logTimestampFailure(slog.LevelWarn, err, "stepfunctions", "ListExecutions", region, r)
		return nil
	}

	resp, err := client.ListExecutions(context.Background(), &sfn.ListExecutionsInput{
		StateMachineArn: aws.String(arn),
		MaxResults:      1,
	})
	if err != nil {
		if op := ClassifySkippable(err, "stepfunctions", "ListExecutions", region); op != nil {
			s.skipReport.Record(*op)
			return nil
		}
		logTimestampFailure(slog.LevelWarn, err, "stepfunctions", "ListExecutions", region, r)
		return nil
	}

	if len(resp.Executions) > 0 {
		newest := resp.Executions[0]
		if newest.StartDate == nil {
			return fmt.Errorf("ListExecutions returned execution %s of %s without StartDate", aws.ToString(newest.ExecutionArn), arn)
		}
		latest := *newest.StartDate
		if newest.StopDate != nil && newest.StopDate.After(latest) {
			latest = *newest.StopDate
		}
		r.LastModified = &latest
		return nil
	}

	created, err := creationDate(r)
	if err != nil {
		return err
	}
	r.LastModified = created
	return nil
}

// listCreationDates returns nil when ListStateMachines fails. A nil map value
// marks a state machine AWS returned without CreationDate.
func (s *sfnStateMachineLastModified) listCreationDates(region string) map[string]*time.Time {
	client, err := s.client(region)
	if err != nil {
		logTimestampFailure(slog.LevelWarn, err, "stepfunctions", "ListStateMachines", region, nil)
		return nil
	}

	creationDates := make(map[string]*time.Time)
	paginator := sfn.NewListStateMachinesPaginator(client, &sfn.ListStateMachinesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "stepfunctions", "ListStateMachines", region); op != nil {
				s.skipReport.Record(*op)
				return nil
			}
			logTimestampFailure(slog.LevelWarn, err, "stepfunctions", "ListStateMachines", region, nil)
			return nil
		}
		for _, sm := range page.StateMachines {
			creationDates[aws.ToString(sm.StateMachineArn)] = sm.CreationDate
		}
	}
	return creationDates
}

func (s *sfnStateMachineLastModified) describeCreationDate(region string, r *output.AWSResource) (*time.Time, error) {
	arn := r.ResourceID
	client, err := s.client(region)
	if err != nil {
		logTimestampFailure(slog.LevelWarn, err, "stepfunctions", "DescribeStateMachine", region, r)
		return nil, nil
	}
	resp, err := client.DescribeStateMachine(context.Background(), &sfn.DescribeStateMachineInput{StateMachineArn: aws.String(arn)})
	if err != nil {
		if op := ClassifySkippable(err, "stepfunctions", "DescribeStateMachine", region); op != nil {
			s.skipReport.Record(*op)
			return nil, nil
		}
		logTimestampFailure(slog.LevelWarn, err, "stepfunctions", "DescribeStateMachine", region, r)
		return nil, nil
	}
	if resp.CreationDate == nil {
		return nil, fmt.Errorf("DescribeStateMachine returned %s in %s without CreationDate", arn, region)
	}
	return resp.CreationDate, nil
}

func (s *sfnStateMachineLastModified) client(region string) (*sfn.Client, error) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return nil, err
	}
	return sfn.NewFromConfig(*cfg), nil
}
