package gcloudcollectors

import (
	"context"
	"fmt"

	iamadmin "cloud.google.com/go/iam/admin/apiv1"
	iamadminpb "cloud.google.com/go/iam/admin/apiv1/adminpb"
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/option"
)

type RoleCollector struct {
	ctx           context.Context
	clientOptions []option.ClientOption
	iamClient     *iamadmin.IamClient
}

func NewRoleCollector(ctx context.Context, clientOptions ...option.ClientOption) (*RoleCollector, error) {
	collector := &RoleCollector{
		ctx:           ctx,
		clientOptions: clientOptions,
	}
	var err error
	collector.iamClient, err = iamadmin.NewIamClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM admin client: %w", err)
	}
	return collector, nil
}

func (rc *RoleCollector) Close() error {
	if rc.iamClient != nil {
		return rc.iamClient.Close()
	}
	return nil
}

func (rc *RoleCollector) CollectPredefinedRoles() ([]*gcptypes.Role, error) {
	return rc.collectRoles("", "")
}

func (rc *RoleCollector) CollectCustomRolesInOrg(orgID string) ([]*gcptypes.Role, error) {
	parent := normalizeOrgName(orgID)
	return rc.collectRoles(parent, parent)
}

func (rc *RoleCollector) CollectCustomRolesInProject(projectID string) ([]*gcptypes.Role, error) {
	parent := normalizeProjectName(projectID)
	return rc.collectRoles(parent, parent)
}

func (rc *RoleCollector) collectRoles(parent, parentURI string) ([]*gcptypes.Role, error) {
	roles := make([]*gcptypes.Role, 0)
	pageToken := ""
	for {
		req := &iamadminpb.ListRolesRequest{
			Parent:    parent,
			View:      iamadminpb.RoleView_FULL,
			PageToken: pageToken,
		}
		resp, err := rc.iamClient.ListRoles(rc.ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to list custom roles in %s: %w", parent, err)
		}
		for _, apiRole := range resp.Roles {
			role := &gcptypes.Role{
				Name:                apiRole.Name,
				Title:               apiRole.Title,
				Description:         apiRole.Description,
				Stage:               apiRole.Stage.String(),
				ParentURI:           parentURI,
				IncludedPermissions: make([]gcptypes.Permission, 0, len(apiRole.IncludedPermissions)),
			}
			for _, perm := range apiRole.IncludedPermissions {
				role.IncludedPermissions = append(role.IncludedPermissions, gcptypes.Permission(perm))
			}
			roles = append(roles, role)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return roles, nil
}

func (rc *RoleCollector) GetRole(roleName string) (*gcptypes.Role, error) {
	req := &iamadminpb.GetRoleRequest{
		Name: roleName,
	}
	resp, err := rc.iamClient.GetRole(rc.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get role %s: %w", roleName, err)
	}
	role := &gcptypes.Role{
		Name:                resp.Name,
		Title:               resp.Title,
		Description:         resp.Description,
		Stage:               resp.Stage.String(),
		IncludedPermissions: make([]gcptypes.Permission, 0, len(resp.IncludedPermissions)),
	}
	for _, perm := range resp.IncludedPermissions {
		role.IncludedPermissions = append(role.IncludedPermissions, gcptypes.Permission(perm))
	}
	return role, nil
}
