package enumeration

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// SSMDocumentEnumerator enumerates SSM documents owned by the account using the
// native SSM SDK, filtering to Owner=Self to exclude AWS-managed and third-party
// documents.
type SSMDocumentEnumerator struct {
	plugin.AWSCommonRecon
	provider *AWSConfigProvider
}

func NewSSMDocumentEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider) *SSMDocumentEnumerator {
	return &SSMDocumentEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
	}
}

func (e *SSMDocumentEnumerator) ResourceType() string {
	return "AWS::SSM::Document"
}

func (e *SSMDocumentEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(e.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := e.provider.GetAccountID(e.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(e.Concurrency)
	return actor.ActInRegions(e.Regions, func(region string) error {
		return e.listDocumentsInRegion(region, accountID, out)
	})
}

func (e *SSMDocumentEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}

	docName, ok := strings.CutPrefix(parsed.Resource, "document/")
	if !ok {
		return fmt.Errorf("invalid SSM document ARN resource: %q", parsed.Resource)
	}

	if parsed.Region == "" {
		return fmt.Errorf("SSM document ARN missing region: %q", arn)
	}

	cfg, err := e.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create SSM client for %s: %w", parsed.Region, err)
	}
	client := ssm.NewFromConfig(*cfg)

	result, err := client.DescribeDocument(context.Background(), &ssm.DescribeDocumentInput{
		Name: aws.String(docName),
	})
	if err != nil {
		return fmt.Errorf("describe document %s: %w", docName, err)
	}

	doc := result.Document
	out.Send(output.AWSResource{
		ResourceType: "AWS::SSM::Document",
		ResourceID:   aws.ToString(doc.Name),
		ARN:          fmt.Sprintf("arn:aws:ssm:%s:%s:document/%s", parsed.Region, parsed.AccountID, aws.ToString(doc.Name)),
		AccountRef:   parsed.AccountID,
		Region:       parsed.Region,
		DisplayName:  aws.ToString(doc.Name),
		Properties: map[string]any{
			"Name":            aws.ToString(doc.Name),
			"Owner":           aws.ToString(doc.Owner),
			"DocumentVersion": aws.ToString(doc.DocumentVersion),
			"DocumentType":    string(doc.DocumentType),
		},
	})
	return nil
}

func (e *SSMDocumentEnumerator) listDocumentsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := e.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create SSM client for %s: %w", region, err)
	}
	client := ssm.NewFromConfig(*cfg)

	paginator := ssm.NewListDocumentsPaginator(client, &ssm.ListDocumentsInput{
		Filters: []ssmtypes.DocumentKeyValuesFilter{
			{
				Key:    aws.String("Owner"),
				Values: []string{"Self"},
			},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if handled := handleListError(err, "AWS::SSM::Document", region); handled == nil {
				return nil
			}
			return fmt.Errorf("list documents in %s: %w", region, err)
		}

		for _, doc := range page.DocumentIdentifiers {
			name := aws.ToString(doc.Name)
			out.Send(output.AWSResource{
				ResourceType: "AWS::SSM::Document",
				ResourceID:   name,
				ARN:          fmt.Sprintf("arn:aws:ssm:%s:%s:document/%s", region, accountID, name),
				AccountRef:   accountID,
				Region:       region,
				DisplayName:  name,
				Properties: map[string]any{
					"Name":            name,
					"Owner":           aws.ToString(doc.Owner),
					"DocumentVersion": aws.ToString(doc.DocumentVersion),
					"DocumentType":    string(doc.DocumentType),
				},
			})
		}
	}

	return nil
}
