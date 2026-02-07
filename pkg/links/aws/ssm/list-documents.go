package ssm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSListSSMDocuments struct {
	*base.NativeAWSLink
}

func NewAWSListSSMDocuments(args map[string]any) *AWSListSSMDocuments {
	return &AWSListSSMDocuments{
		NativeAWSLink: base.NewNativeAWSLink("ssm-list-documents", args),
	}
}

func (a *AWSListSSMDocuments) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}

	config, err := a.GetConfig(ctx, resource.Region)
	if err != nil {
		return nil, err
	}

	ssmClient := ssm.NewFromConfig(config)

	// Use ListDocuments with Owner=Self filter to only get customer-owned documents
	listInput := &ssm.ListDocumentsInput{
		Filters: []ssmtypes.DocumentKeyValuesFilter{
			{
				Key:    aws.String("Owner"),
				Values: []string{"Self"},
			},
		},
	}

	results := []types.EnrichedResourceDescription{}
	paginator := ssm.NewListDocumentsPaginator(ssmClient, listInput)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			slog.Debug("Failed to list SSM documents", "error", err)
			break
		}

		for _, doc := range page.DocumentIdentifiers {
			erd, err := a.parseDocument(ctx, ssmClient, doc, resource)
			if err != nil {
				slog.Debug("Failed to parse document", "name", aws.ToString(doc.Name), "error", err)
				continue
			}

			results = append(results, erd)
		}
	}

	outputs := make([]any, len(results))
	for i, erd := range results {
		outputs[i] = erd
	}

	return outputs, nil
}

func (a *AWSListSSMDocuments) parseDocument(ctx context.Context, ssmClient *ssm.Client, doc ssmtypes.DocumentIdentifier, resource *types.EnrichedResourceDescription) (types.EnrichedResourceDescription, error) {
	// Get document content
	getDocInput := &ssm.GetDocumentInput{
		Name: doc.Name,
	}

	docOutput, err := ssmClient.GetDocument(ctx, getDocInput)
	if err != nil {
		return types.EnrichedResourceDescription{}, fmt.Errorf("failed to get document %s: %w", aws.ToString(doc.Name), err)
	}

	// Build properties map with document metadata and content
	propertiesMap := map[string]interface{}{
		"Name":          doc.Name,
		"DocumentType":  doc.DocumentType,
		"DocumentFormat": doc.DocumentFormat,
		"Owner":         doc.Owner,
		"Content":       docOutput.Content,
		"Status":        docOutput.Status,
		"DocumentVersion": docOutput.DocumentVersion,
	}

	// Add optional fields if present
	if doc.DocumentVersion != nil {
		propertiesMap["LatestVersion"] = doc.DocumentVersion
	}
	if doc.PlatformTypes != nil && len(doc.PlatformTypes) > 0 {
		propertiesMap["PlatformTypes"] = doc.PlatformTypes
	}
	if doc.Tags != nil && len(doc.Tags) > 0 {
		propertiesMap["Tags"] = doc.Tags
	}

	properties, err := json.Marshal(propertiesMap)
	if err != nil {
		return types.EnrichedResourceDescription{}, fmt.Errorf("failed to marshal document properties: %w", err)
	}

	erd := types.EnrichedResourceDescription{
		Identifier: aws.ToString(doc.Name),
		TypeName:   resource.TypeName,
		Region:     resource.Region,
		Properties: string(properties),
		AccountId:  resource.AccountId,
	}

	erd.Arn = erd.ToArn()

	return erd, nil
}
