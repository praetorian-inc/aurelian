package iam

import (
	"context"
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

// PermissionChecker tests IAM permissions on GCP projects using the
// testIamPermissions API.
type PermissionChecker struct {
	crmSvc *cloudresourcemanager.Service
}

// NewPermissionChecker creates a PermissionChecker backed by the Cloud Resource
// Manager v1 API.
func NewPermissionChecker(clientOptions []option.ClientOption) (*PermissionChecker, error) {
	svc, err := cloudresourcemanager.NewService(context.Background(), clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating cloudresourcemanager service: %w", err)
	}
	return &PermissionChecker{crmSvc: svc}, nil
}

// TestPermissions tests which of the given permissions the caller has on a
// project. Permissions are batched into groups of 100 (API limit).
func (pc *PermissionChecker) TestPermissions(projectID string, permissions []string) ([]string, error) {
	batches := batchPermissions(permissions, 100)
	var granted []string
	for _, batch := range batches {
		resp, err := pc.crmSvc.Projects.TestIamPermissions(projectID, &cloudresourcemanager.TestIamPermissionsRequest{
			Permissions: batch,
		}).Do()
		if err != nil {
			return nil, fmt.Errorf("testing permissions on project %s: %w", projectID, err)
		}
		granted = append(granted, resp.Permissions...)
	}
	return granted, nil
}

// batchPermissions splits a slice of permissions into batches of the given size.
func batchPermissions(perms []string, batchSize int) [][]string {
	if len(perms) == 0 {
		return nil
	}
	var batches [][]string
	for i := 0; i < len(perms); i += batchSize {
		end := min(i+batchSize, len(perms))
		batches = append(batches, perms[i:end])
	}
	return batches
}
