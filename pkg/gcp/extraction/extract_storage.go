package extraction

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"

	gcsapi "google.golang.org/api/storage/v1"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

const (
	// maxObjectSize is the maximum object size to download for scanning (1 MB).
	maxObjectSize = 1 << 20
	// maxObjectsPerBucket limits how many objects we scan per bucket.
	maxObjectsPerBucket = 100
)

// binaryContentTypes are content types to skip when scanning bucket objects.
var binaryContentTypes = []string{
	"image/",
	"video/",
	"audio/",
	"application/octet-stream",
	"application/zip",
	"application/gzip",
	"application/x-tar",
	"application/pdf",
	"application/wasm",
}

func init() {
	mustRegister("storage.googleapis.com/Bucket", "objects", extractBucketObjects)
}

// extractBucketObjects lists and downloads objects from a GCS bucket for secret scanning.
func extractBucketObjects(ctx extractContext, r output.GCPResource, out *pipeline.P[output.ScanInput]) error {
	svc, err := gcsapi.NewService(ctx.Context, ctx.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating storage client: %w", err)
	}

	bucketName := r.DisplayName
	if bucketName == "" {
		bucketName = r.ResourceID
	}

	paginator := ratelimit.NewGCPPaginator()
	var pageToken string
	count := 0

	err = paginator.Paginate(func() (bool, error) {
		call := svc.Objects.List(bucketName).Context(ctx.Context).PageToken(pageToken)
		resp, err := call.Do()
		if err != nil {
			return false, err
		}
		for _, obj := range resp.Items {
			if count >= maxObjectsPerBucket {
				return false, nil
			}

			if isBinaryContentType(obj.ContentType) {
				slog.Debug("skipping binary object", "bucket", bucketName, "object", obj.Name, "contentType", obj.ContentType)
				continue
			}

			if obj.Size > maxObjectSize {
				slog.Debug("skipping large object", "bucket", bucketName, "object", obj.Name, "size", obj.Size)
				continue
			}

			content, dlErr := downloadObject(svc, bucketName, obj.Name)
			if dlErr != nil {
				slog.Warn("failed to download object", "bucket", bucketName, "object", obj.Name, "error", dlErr)
				continue
			}
			if len(content) == 0 {
				continue
			}

			out.Send(output.ScanInputFromGCPResource(r, obj.Name, content))
			count++
		}
		pageToken = resp.NextPageToken
		return pageToken != "", nil
	})
	if err != nil {
		return fmt.Errorf("listing objects in bucket %s: %w", bucketName, err)
	}
	return nil
}

func downloadObject(svc *gcsapi.Service, bucket, object string) ([]byte, error) {
	resp, err := svc.Objects.Get(bucket, object).Download()
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, io.LimitReader(resp.Body, maxObjectSize))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func isBinaryContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, prefix := range binaryContentTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}
