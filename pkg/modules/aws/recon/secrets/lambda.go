package secrets

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// LambdaGetFunctionClient is the subset of the Lambda API needed by the Lambda extractor.
type LambdaGetFunctionClient interface {
	GetFunction(
		ctx context.Context,
		input *lambda.GetFunctionInput,
		opts ...func(*lambda.Options),
	) (*lambda.GetFunctionOutput, error)
}

// HTTPClient abstracts HTTP GET for downloading Lambda code zips.
type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

// maxLambdaZipSize is the maximum zip size we'll download (250 MB, AWS Lambda limit).
const maxLambdaZipSize = 250 * 1024 * 1024

// extractLambda downloads a Lambda function's code and emits each file as a ScanInput.
func extractLambda(cfg ExtractorConfig, r output.AWSResource, out *pipeline.P[ScanInput]) error {
	awsCfg, err := cfg.AWSConfigFactory(r.Region)
	if err != nil {
		return fmt.Errorf("failed to create AWS config: %w", err)
	}
	client := lambda.NewFromConfig(awsCfg)
	return extractLambdaWithClient(client, http.DefaultClient, r, out)
}

// extractLambdaWithClient is the testable core of the Lambda extractor.
func extractLambdaWithClient(client LambdaGetFunctionClient, httpClient HTTPClient, r output.AWSResource, out *pipeline.P[ScanInput]) error {
	functionName := r.ResourceID
	if name, ok := r.Properties["FunctionName"].(string); ok && name != "" {
		functionName = name
	}

	resp, err := client.GetFunction(context.Background(), &lambda.GetFunctionInput{
		FunctionName: &functionName,
	})
	if err != nil {
		return fmt.Errorf("GetFunction failed for %s: %w", functionName, err)
	}

	if resp.Code == nil || resp.Code.Location == nil || *resp.Code.Location == "" {
		return nil
	}

	// Download the zip archive
	httpResp, err := httpClient.Get(*resp.Code.Location)
	if err != nil {
		return fmt.Errorf("failed to download Lambda code for %s: %w", functionName, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxLambdaZipSize))
	if err != nil {
		return fmt.Errorf("failed to read Lambda code zip for %s: %w", functionName, err)
	}

	// Open as zip archive
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("failed to open Lambda code zip for %s: %w", functionName, err)
	}

	// Emit each file in the archive
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue // skip files we can't open
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue // skip files we can't read
		}

		if len(content) == 0 {
			continue
		}

		out.Send(ScanInput{
			Content:      content,
			ResourceID:   r.ResourceID,
			ResourceType: r.ResourceType,
			Region:       r.Region,
			AccountID:    r.AccountRef,
			Label:        f.Name,
		})
	}

	return nil
}
