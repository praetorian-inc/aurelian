package dispatcher

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	RegisterAWSSecretProcessor("AWS::Lambda::Function", ProcessLambdaFunction)
}

// ProcessLambdaFunction downloads Lambda function code and extracts all files for scanning.
// Lambda code often contains secrets like API keys, database credentials, or configuration.
func ProcessLambdaFunction(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
	resultCh chan<- types.NpInput,
) error {
	zipReader, err := downloadLambdaCode(ctx, resource, opts)
	if err != nil {
		return fmt.Errorf("failed to download code: %w", err)
	}

	// Process each file in the Lambda ZIP archive
	for _, file := range zipReader.File {
		if err := processLambdaFile(ctx, resource, file, resultCh); err != nil {
			return fmt.Errorf("failed to process file %s: %w", file.Name, err)
		}
	}

	return nil
}

// downloadLambdaCode retrieves the Lambda function code ZIP from AWS
func downloadLambdaCode(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
) (*zip.Reader, error) {
	config, err := GetAWSConfigFromOptions(ctx, resource.Region, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	lambdaClient := lambda.NewFromConfig(config)

	getFuncInput := &lambda.GetFunctionInput{
		FunctionName: aws.String(resource.Identifier),
	}

	funcOutput, err := lambdaClient.GetFunction(ctx, getFuncInput)
	if err != nil {
		return nil, fmt.Errorf("failed to get function %s: %w", resource.Identifier, err)
	}

	if funcOutput.Code == nil || funcOutput.Code.Location == nil {
		return nil, fmt.Errorf("no code found for function %s", resource.Identifier)
	}

	// Download code from presigned URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *funcOutput.Code.Location, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for function %s: %w", resource.Identifier, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download code for function %s: %w", resource.Identifier, err)
	}
	defer resp.Body.Close()

	zipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read code for function %s: %w", resource.Identifier, err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip for function %s: %w", resource.Identifier, err)
	}

	return zipReader, nil
}

// processLambdaFile extracts and sends a single file from the Lambda ZIP archive
func processLambdaFile(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	file *zip.File,
	resultCh chan<- types.NpInput,
) error {
	// Skip directories
	if file.FileInfo().IsDir() {
		return nil
	}

	rc, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", file.Name, err)
	}
	defer rc.Close()

	content, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", file.Name, err)
	}

	// Skip empty files
	if len(content) == 0 {
		return nil
	}

	// Send result to channel
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resultCh <- types.NpInput{
		ContentBase64: base64.StdEncoding.EncodeToString(content),
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::Code::%s", resource.TypeName, file.Name),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	}:
	}

	return nil
}
