package storage

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"slices"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"google.golang.org/api/storage/v1"
)

// FILE INFO:
// GcpStorageBucketInfoLink - get info of a single storage bucket, Process(bucketName string); needs project
// GcpStorageBucketListLink - list all storage buckets in a project, Process(resource *output.CloudResource); needs project
// GcpStorageObjectListLink - list all objects in a storage bucket, Process(resource *output.CloudResource); needs project
// GcpStorageObjectSecretsLink - extract and scan objects for secrets, Process(object *GcpStorageObjectRef); needs project

const (
	gcpStorageBucketInfoName    = "gcp-storage-bucket-info"
	gcpStorageBucketListName    = "gcp-storage-bucket-list"
	gcpStorageObjectListName    = "gcp-storage-object-list"
	gcpStorageObjectSecretsName = "gcp-storage-object-secrets"
)

type GcpStorageBucketInfoLink struct {
	*base.NativeGCPLink
	storageService *storage.Service
	ProjectId      string
}

// creates a link to get info of a single storage bucket
func NewGcpStorageBucketInfoLink(args map[string]any) plugin.Link {
	return &GcpStorageBucketInfoLink{
		NativeGCPLink: base.NewNativeGCPLink(gcpStorageBucketInfoName, args),
	}
}

func (g *GcpStorageBucketInfoLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
	)
	return params
}

func (g *GcpStorageBucketInfoLink) Process(ctx context.Context, input any) ([]any, error) {
	bucketName, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	// Lazy initialization
	if g.storageService == nil {
		var err error
		g.storageService, err = storage.NewService(ctx, g.ClientOptions()...)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage service: %w", err)
		}
		if projectVal, ok := g.Args()["project"].(string); ok {
			g.ProjectId = projectVal
		}
	}

	bucket, err := g.storageService.Buckets.Get(bucketName).Context(ctx).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to get bucket")
	}
	properties := linkPostProcessBucket(ctx, bucket, g.storageService)
	gcpBucket := &output.CloudResource{
		Platform:     "gcp",
		ResourceID:   bucket.Name,
		AccountRef:   g.ProjectId,
		ResourceType: "storage.googleapis.com/Bucket",
		DisplayName:  bucket.Name,
		Properties:   properties,
	}
	return []any{gcpBucket}, nil
}

type GcpStorageBucketListLink struct {
	*base.NativeGCPLink
	storageService *storage.Service
}

// creates a link to list all storage buckets in a project
func NewGcpStorageBucketListLink(args map[string]any) plugin.Link {
	return &GcpStorageBucketListLink{
		NativeGCPLink: base.NewNativeGCPLink(gcpStorageBucketListName, args),
	}
}

func (g *GcpStorageBucketListLink) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}

func (g *GcpStorageBucketListLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource input, got %T", input)
	}
	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Project" {
		return nil, nil
	}

	// Lazy initialization
	if g.storageService == nil {
		var err error
		g.storageService, err = storage.NewService(ctx, g.ClientOptions()...)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage service: %w", err)
		}
	}

	projectId := resource.ResourceID
	listReq := g.storageService.Buckets.List(projectId)
	buckets, err := listReq.Context(ctx).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list buckets in project")
	}

	var results []any
	for _, bucket := range buckets.Items {
		properties := linkPostProcessBucket(ctx, bucket, g.storageService)
		gcpBucket := &output.CloudResource{
			Platform:     "gcp",
			ResourceID:   bucket.Name,
			AccountRef:   projectId,
			ResourceType: "storage.googleapis.com/Bucket",
			DisplayName:  bucket.Name,
			Properties:   properties,
		}
		results = append(results, gcpBucket)
	}
	return results, nil
}

type GcpStorageObjectRef struct {
	BucketName string
	ObjectName string
	ProjectId  string
	Object     *storage.Object
}

type GcpStorageObjectListLink struct {
	*base.NativeGCPLink
	storageService *storage.Service
}

// creates a link to list all objects in a storage bucket
func NewGcpStorageObjectListLink(args map[string]any) plugin.Link {
	return &GcpStorageObjectListLink{
		NativeGCPLink: base.NewNativeGCPLink(gcpStorageObjectListName, args),
	}
}

func (g *GcpStorageObjectListLink) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}

func (g *GcpStorageObjectListLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource input, got %T", input)
	}
	if resource.ResourceType != "storage.googleapis.com/Bucket" {
		return nil, nil
	}

	// Lazy initialization
	if g.storageService == nil {
		var err error
		g.storageService, err = storage.NewService(ctx, g.ClientOptions()...)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage service: %w", err)
		}
	}

	bucketName := resource.ResourceID
	projectId := resource.AccountRef
	listReq := g.storageService.Objects.List(bucketName)

	var results []any
	for {
		objects, err := listReq.Context(ctx).Do()
		if err != nil {
			return nil, common.HandleGcpError(err, fmt.Sprintf("failed to list objects in bucket %s", bucketName))
		}
		for _, obj := range objects.Items {
			objRef := &GcpStorageObjectRef{
				BucketName: bucketName,
				ObjectName: obj.Name,
				ProjectId:  projectId,
				Object:     obj,
			}
			results = append(results, objRef)
		}
		if objects.NextPageToken == "" {
			break
		}
		listReq.PageToken(objects.NextPageToken)
	}
	return results, nil
}

type GcpStorageObjectSecretsLink struct {
	*base.NativeGCPLink
	storageService *storage.Service
	maxFileSize    int64
}

// creates a link to extract and scan storage objects for secrets
func NewGcpStorageObjectSecretsLink(args map[string]any) plugin.Link {
	return &GcpStorageObjectSecretsLink{
		NativeGCPLink: base.NewNativeGCPLink(gcpStorageObjectSecretsName, args),
		maxFileSize:   10 * 1024 * 1024, // 10MB default limit
	}
}

func (g *GcpStorageObjectSecretsLink) Parameters() []plugin.Parameter {
	return append(base.StandardGCPParams(),
		plugin.NewParam[int]("max-file-size", "Maximum file size to scan for secrets (bytes)",
			plugin.WithDefault(10485760)),
	)
}

func (g *GcpStorageObjectSecretsLink) Process(ctx context.Context, input any) ([]any, error) {
	objRef, ok := input.(*GcpStorageObjectRef)
	if !ok {
		return nil, fmt.Errorf("expected *GcpStorageObjectRef input, got %T", input)
	}

	// Lazy initialization
	if g.storageService == nil {
		var err error
		g.storageService, err = storage.NewService(ctx, g.ClientOptions()...)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage service: %w", err)
		}
		// Parse max-file-size from args if provided
		if maxSizeVal, ok := g.Args()["max-file-size"]; ok {
			if maxSize, ok := maxSizeVal.(int); ok {
				g.maxFileSize = int64(maxSize)
			}
		}
	}

	if objRef.Object.Size > uint64(g.maxFileSize) {
		slog.Debug("Skipping large object", "bucket", objRef.BucketName, "object", objRef.ObjectName, "size", objRef.Object.Size)
		return nil, nil
	}
	if g.isSkippableFile(objRef.ObjectName) {
		slog.Debug("Skipping binary file", "bucket", objRef.BucketName, "object", objRef.ObjectName)
		return nil, nil
	}
	getReq := g.storageService.Objects.Get(objRef.BucketName, objRef.ObjectName)
	resp, err := getReq.Context(ctx).Download()
	if err != nil {
		return nil, common.HandleGcpError(err, fmt.Sprintf("failed to download object %s from bucket %s", objRef.ObjectName, objRef.BucketName))
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object content: %w", err)
	}
	var npInput types.NpInput
	if g.isBinaryContent(content) {
		npInput = types.NpInput{
			ContentBase64: base64.StdEncoding.EncodeToString(content),
			Provenance: types.NpProvenance{
				Kind:         "file",
				Platform:     "gcp",
				ResourceType: "storage.googleapis.com/Object",
				ResourceID:   fmt.Sprintf("%s/%s", objRef.BucketName, objRef.ObjectName),
				Region:       objRef.Object.Bucket, // GCS doesn't have regional buckets like this, but we'll use bucket name
				AccountID:    objRef.ProjectId,
				RepoPath:     fmt.Sprintf("gs://%s/%s", objRef.BucketName, objRef.ObjectName),
			},
		}
	} else {
		npInput = types.NpInput{
			Content: string(content),
			Provenance: types.NpProvenance{
				Kind:         "file",
				Platform:     "gcp",
				ResourceType: "storage.googleapis.com/Object",
				ResourceID:   fmt.Sprintf("%s/%s", objRef.BucketName, objRef.ObjectName),
				Region:       objRef.Object.Bucket,
				AccountID:    objRef.ProjectId,
				RepoPath:     fmt.Sprintf("gs://%s/%s", objRef.BucketName, objRef.ObjectName),
			},
		}
	}
	return []any{npInput}, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

type AnonymousAccessInfo struct {
	HasAllUsers                bool     `json:"hasAllUsers"`
	HasAllAuthenticatedUsers   bool     `json:"hasAllAuthenticatedUsers"`
	AllUsersRoles              []string `json:"allUsersRoles"`
	AllAuthenticatedUsersRoles []string `json:"allAuthenticatedUsersRoles"`
	TotalPublicBindings        int      `json:"totalPublicBindings"`
	AccessMethods              []string `json:"accessMethods"`
}

func checkStorageAnonymousAccess(policy *storage.Policy) AnonymousAccessInfo {
	info := AnonymousAccessInfo{
		AllUsersRoles:              []string{},
		AllAuthenticatedUsersRoles: []string{},
		AccessMethods:              []string{},
	}
	if policy == nil || len(policy.Bindings) == 0 {
		return info
	}
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member == "allUsers" {
				info.HasAllUsers = true
				info.AllUsersRoles = append(info.AllUsersRoles, binding.Role)
				info.TotalPublicBindings++
			} else if member == "allAuthenticatedUsers" {
				info.HasAllAuthenticatedUsers = true
				info.AllAuthenticatedUsersRoles = append(info.AllAuthenticatedUsersRoles, binding.Role)
				info.TotalPublicBindings++
			}
		}
	}
	if info.TotalPublicBindings > 0 {
		info.AccessMethods = append(info.AccessMethods, "IAM")
	}
	return info
}

func checkStorageACLForPublicAccess(info *AnonymousAccessInfo, acl *storage.BucketAccessControls) {
	if acl == nil || len(acl.Items) == 0 {
		return
	}
	for _, aclEntry := range acl.Items {
		if aclEntry.Entity == "allUsers" {
			info.HasAllUsers = true
			// Convert ACL role to IAM-style role name for consistency
			role := fmt.Sprintf("roles/storage.%s", aclEntry.Role)
			if !slices.Contains(info.AllUsersRoles, role) {
				info.AllUsersRoles = append(info.AllUsersRoles, role)
				info.TotalPublicBindings++
			}
		} else if aclEntry.Entity == "allAuthenticatedUsers" {
			info.HasAllAuthenticatedUsers = true
			role := fmt.Sprintf("roles/storage.%s", aclEntry.Role)
			if !slices.Contains(info.AllAuthenticatedUsersRoles, role) {
				info.AllAuthenticatedUsersRoles = append(info.AllAuthenticatedUsersRoles, role)
				info.TotalPublicBindings++
			}
		}
	}
	// Update access methods if ACL access found
	if info.TotalPublicBindings > 0 && !slices.Contains(info.AccessMethods, "ACL") {
		info.AccessMethods = append(info.AccessMethods, "ACL")
	}
}

func calculateRiskLevel(info AnonymousAccessInfo) string {
	if info.HasAllUsers {
		return "critical"
	} else if info.HasAllAuthenticatedUsers {
		return "high"
	}
	return "low"
}

func linkPostProcessBucket(ctx context.Context, bucket *storage.Bucket, storageService *storage.Service) map[string]any {
	properties := map[string]any{
		"name":      bucket.Name,
		"id":        bucket.Id,
		"location":  bucket.Location,
		"selfLink":  bucket.SelfLink,
		"gsUtilURL": fmt.Sprintf("gs://%s", bucket.Name),
		"publicURL": fmt.Sprintf("https://storage.googleapis.com/%s", bucket.Name), // also <bucket-name>.storage.googleapis.com
	}

	if bucket.IamConfiguration != nil && bucket.IamConfiguration.PublicAccessPrevention == "inherited" {
		properties["publicAccessPrevention"] = "false"
	} else {
		properties["publicAccessPrevention"] = "true"
	}

	// Check IAM policy for anonymous access
	policy, policyErr := storageService.Buckets.GetIamPolicy(bucket.Name).Context(ctx).Do()
	if policyErr == nil && policy != nil {
		anonymousInfo := checkStorageAnonymousAccess(policy)
		// Also check ACL for legacy public access
		acl, aclErr := storageService.BucketAccessControls.List(bucket.Name).Context(ctx).Do()
		if aclErr == nil {
			checkStorageACLForPublicAccess(&anonymousInfo, acl)
		} else {
			slog.Debug("Failed to get ACL for bucket", "bucket", bucket.Name, "error", aclErr)
		}
		if anonymousInfo.TotalPublicBindings > 0 {
			// Convert anonymousInfo to string representation for Properties map
			properties["hasAllUsers"] = fmt.Sprintf("%v", anonymousInfo.HasAllUsers)
			properties["hasAllAuthenticatedUsers"] = fmt.Sprintf("%v", anonymousInfo.HasAllAuthenticatedUsers)
			properties["totalPublicBindings"] = fmt.Sprintf("%d", anonymousInfo.TotalPublicBindings)
			properties["riskLevel"] = calculateRiskLevel(anonymousInfo)
		}
	} else {
		slog.Debug("Failed to get IAM policy for bucket", "bucket", bucket.Name, "error", policyErr)
	}
	return properties
}

// doing this for heurestic purposes, np might already be removing
func (g *GcpStorageObjectSecretsLink) isSkippableFile(filename string) bool {
	binaryExtensions := []string{
		".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".war", ".ear",
		".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
		".mp3", ".wav", ".mp4", ".avi", ".mov", ".mkv",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".iso", ".dmg", ".img",
	}

	lowerFilename := strings.ToLower(filename)
	for _, ext := range binaryExtensions {
		if strings.HasSuffix(lowerFilename, ext) {
			return true
		}
	}
	return false
}

func (g *GcpStorageObjectSecretsLink) isBinaryContent(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	for i := 0; i < len(content) && i < 512; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

// Note: init() registration removed - native plugins register via Parameters() method
