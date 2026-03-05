package extraction

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("Microsoft.Storage/storageAccounts", "storage-blobs", extractStorageBlobs)
}

// scannedAccounts prevents duplicate scans when account appears in multiple regions.
var scannedAccounts sync.Map

const maxBlobSize int64 = 100 * 1024 * 1024 // 100MB

var skipExtensions = map[string]bool{
	".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true, ".bz2": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".jar": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".tiff": true, ".webp": true,
	".mp4": true, ".mkv": true, ".avi": true, ".mov": true, ".flv": true, ".wmv": true,
	".mp3": true, ".flac": true, ".wav": true, ".ogg": true, ".aac": true,
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true,
	".lock": true,
}

var excludePatterns = []string{
	"/node_modules/", "/vendor/", "/.git/", "/test-data/", "/tmp/", "/__pycache__/",
}

func parseStorageAccountResourceID(resourceID string) (resourceGroup, accountName string, err error) {
	rg, name, err := parseResourceID(resourceID, "resourceGroups", "storageAccounts")
	if err != nil {
		return "", "", fmt.Errorf("invalid storage account resource ID %q: %w", resourceID, err)
	}
	return rg, name, nil
}

func shouldSkipExtension(ext string) bool {
	return skipExtensions[strings.ToLower(ext)]
}

func matchesCriticalPattern(key string) bool {
	lowerKey := strings.ToLower(key)
	criticalPatterns := []string{
		"terraform.tfstate", ".tfstate", ".tfvars",
		".env",
		"credentials.json", "credentials.csv", "credentials",
		"service-account.json", "gcp-keyfile",
		"aws-config", "azure-credentials",
		"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
		".pem", ".key", "private-key",
		"secret.json", "secret.yml", "secrets.yaml",
		"password", "token",
		".vault.yml", "vault.yml",
		"config.json", "config.yml", "config.yaml",
		"appsettings.json",
		"database.yml", "database.json", "db.config",
		"settings.json", "settings.yml",
		"application.properties",
		"docker-compose.yml", "docker-compose.yaml",
		".dockercfg", "kubeconfig",
		".gitlab-ci.yml", "buildspec.yml", "jenkinsfile",
		".pgpass", ".my.cnf",
		".npmrc", ".pypirc", "settings.xml",
	}

	for _, pattern := range criticalPatterns {
		if strings.Contains(lowerKey, pattern) {
			return true
		}
	}
	return false
}

func shouldScanBlob(name string, size int64, scanMode string) bool {
	if matchesCriticalPattern(name) {
		return true
	}
	if scanMode != "all" {
		return false
	}

	if size > maxBlobSize || size == 0 {
		return false
	}
	if shouldSkipExtension(filepath.Ext(name)) {
		return false
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(name, pattern) {
			return false
		}
	}
	if strings.HasSuffix(name, "/") {
		return false
	}
	return true
}

func isBinaryContent(header []byte) bool {
	for _, b := range header {
		if b == 0x00 {
			return true
		}
	}
	magicNumbers := [][]byte{
		{0xFF, 0xD8, 0xFF},
		{0x50, 0x4B, 0x03, 0x04},
		{0x7F, 0x45, 0x4C, 0x46},
		{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
		{0x47, 0x49, 0x46, 0x38},
		{0x25, 0x50, 0x44, 0x46},
		{0x1F, 0x8B, 0x08},
	}
	for _, magic := range magicNumbers {
		if len(header) >= len(magic) && bytes.HasPrefix(header, magic) {
			return true
		}
	}
	return false
}

func extractStorageBlobs(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, accountName, err := parseStorageAccountResourceID(r.ResourceID)
	if err != nil {
		return err
	}

	// Deduplicate
	if _, alreadyScanned := scannedAccounts.LoadOrStore(accountName, true); alreadyScanned {
		slog.Info("skipping already-scanned storage account", "account", accountName)
		return nil
	}

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)
	client, err := azblob.NewClient(serviceURL, ctx.Cred, nil)
	if err != nil {
		slog.Warn("failed to create blob client", "account", accountName, "error", err)
		return nil
	}

	pager := client.NewListContainersPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			slog.Warn("failed to list containers", "account", accountName, "error", err)
			return nil
		}
		for _, c := range page.ContainerItems {
			if c.Name == nil {
				continue
			}
			processContainer(ctx, client, r, accountName, *c.Name, out)
		}
	}

	return nil
}

func processContainer(ctx extractContext, client *azblob.Client, r output.AzureResource, accountName, containerName string, out *pipeline.P[output.ScanInput]) {
	pager := client.NewListBlobsFlatPager(containerName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			if isAccessDenied(err) {
				slog.Warn("container access denied, skipping", "container", containerName, "account", accountName)
				return
			}
			slog.Warn("failed to list blobs", "container", containerName, "error", err)
			return
		}
		for _, blob := range page.Segment.BlobItems {
			if blob.Name == nil || blob.Properties == nil {
				continue
			}
			size := int64(0)
			if blob.Properties.ContentLength != nil {
				size = *blob.Properties.ContentLength
			}
			if !shouldScanBlob(*blob.Name, size, ctx.ScanMode) {
				continue
			}
			processBlob(ctx, client, r, accountName, containerName, *blob.Name, out)
		}
	}
}

func processBlob(ctx extractContext, client *azblob.Client, r output.AzureResource, accountName, containerName, blobName string, out *pipeline.P[output.ScanInput]) {
	resp, err := client.DownloadStream(ctx.Context, containerName, blobName, &azblob.DownloadStreamOptions{
		Range: azblob.HTTPRange{Offset: 0, Count: 512},
	})
	if err != nil {
		slog.Debug("failed to check blob header", "blob", blobName, "error", err)
		return
	}
	header := make([]byte, 512)
	n, _ := io.ReadFull(resp.Body, header)
	resp.Body.Close()
	if n > 0 && isBinaryContent(header[:n]) {
		return
	}

	fullResp, err := client.DownloadStream(ctx.Context, containerName, blobName, nil)
	if err != nil {
		slog.Debug("failed to download blob", "blob", blobName, "error", err)
		return
	}
	defer fullResp.Body.Close()
	content, err := io.ReadAll(fullResp.Body)
	if err != nil {
		slog.Debug("failed to read blob", "blob", blobName, "error", err)
		return
	}

	label := fmt.Sprintf("Blob:%s/%s", containerName, blobName)
	out.Send(output.ScanInputFromAzureResource(r, label, content))
}

func isAccessDenied(err error) bool {
	s := err.Error()
	return strings.Contains(s, "AuthorizationPermissionMismatch") ||
		strings.Contains(s, "AuthorizationFailure") ||
		strings.Contains(s, "AuthenticationFailed") ||
		strings.Contains(s, "PublicAccessNotPermitted") ||
		strings.Contains(s, "403")
}

// ResetScannedAccounts clears the dedup cache (for testing).
func ResetScannedAccounts() {
	scannedAccounts = sync.Map{}
}
