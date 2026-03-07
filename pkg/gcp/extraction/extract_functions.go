package extraction

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/api/cloudfunctions/v1"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

const maxFunctionZipSize = 250 * 1024 * 1024

var httpClient = &http.Client{Timeout: 10 * time.Minute}

func init() {
	mustRegister("cloudfunctions.googleapis.com/Function", "source", extractFunctionSource)
}

// extractFunctionSource downloads the function's source archive, extracts each file,
// and emits individual files for scanning.
func extractFunctionSource(ctx extractContext, r output.GCPResource, out *pipeline.P[output.ScanInput]) error {
	svc, err := cloudfunctions.NewService(ctx.Context, ctx.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating cloudfunctions client: %w", err)
	}

	resp, err := svc.Projects.Locations.Functions.GenerateDownloadUrl(r.ResourceID, &cloudfunctions.GenerateDownloadUrlRequest{}).Context(ctx.Context).Do()
	if err != nil {
		return fmt.Errorf("generating download URL for %s: %w", r.ResourceID, err)
	}

	if resp.DownloadUrl == "" {
		return nil
	}

	httpResp, err := httpClient.Get(resp.DownloadUrl)
	if err != nil {
		return fmt.Errorf("downloading source for %s: %w", r.ResourceID, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxFunctionZipSize))
	if err != nil {
		return fmt.Errorf("reading source for %s: %w", r.ResourceID, err)
	}

	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("opening source zip for %s: %w", r.ResourceID, err)
	}

	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || len(content) == 0 {
			continue
		}

		out.Send(output.ScanInputFromGCPResource(r, f.Name, content))
	}
	return nil
}
