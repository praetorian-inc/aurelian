package extraction

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

const (
	// maxBlobSize is the maximum blob size to download for scanning (1 MB).
	maxBlobSize = 1 << 20
	// maxBlobsPerContainer limits how many blobs we scan per container.
	maxBlobsPerContainer = 100
)

func init() {
	mustRegister("microsoft.storage/storageaccounts", "storage-blobs", extractStorageBlobs)
}

func extractStorageBlobs(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, _, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse storage account resource ID: %w", err)
	}

	accountName := segments["storageAccounts"]
	if accountName == "" {
		return fmt.Errorf("no storageAccounts segment in resource ID %s", r.ResourceID)
	}

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net", accountName)
	client, err := azblob.NewClient(serviceURL, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create blob client: %w", err)
	}

	containerPager := client.NewListContainersPager(nil)
	paginator := newAzurePaginator()
	return paginator.Paginate(func() (bool, error) {
		page, err := containerPager.NextPage(ctx.Context)
		if err != nil {
			return true, err
		}

		for _, container := range page.ContainerItems {
			if container.Name == nil {
				continue
			}
			if err := extractBlobsFromContainer(ctx, client, r, *container.Name, out); err != nil {
				slog.Warn("failed to extract blobs from container", "container", *container.Name, "error", err)
			}
		}
		return containerPager.More(), nil
	})
}

func extractBlobsFromContainer(ctx extractContext, client *azblob.Client, r output.AzureResource, containerName string, out *pipeline.P[output.ScanInput]) error {
	blobPager := client.NewListBlobsFlatPager(containerName, nil)
	count := 0
	paginator := newAzurePaginator()

	return paginator.Paginate(func() (bool, error) {
		page, err := blobPager.NextPage(ctx.Context)
		if err != nil {
			return true, err
		}

		for _, blob := range page.Segment.BlobItems {
			if count >= maxBlobsPerContainer {
				return false, nil
			}
			if blob.Name == nil {
				continue
			}

			blobTooLarge := blob.Properties != nil && blob.Properties.ContentLength != nil && *blob.Properties.ContentLength > maxBlobSize
			if blobTooLarge {
				slog.Debug("skipping large blob", "blob", *blob.Name, "size", *blob.Properties.ContentLength)
				continue
			}

			content, err := downloadBlob(ctx, client, containerName, *blob.Name)
			if err != nil {
				slog.Warn("failed to download blob", "blob", *blob.Name, "error", err)
				continue
			}
			if len(content) == 0 {
				continue
			}

			label := fmt.Sprintf("Blob: %s/%s", containerName, *blob.Name)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
			count++
		}
		return blobPager.More() && count < maxBlobsPerContainer, nil
	})
}

func downloadBlob(ctx extractContext, client *azblob.Client, containerName, blobName string) ([]byte, error) {
	resp, err := client.DownloadStream(ctx.Context, containerName, blobName, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, io.LimitReader(resp.Body, maxBlobSize))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
