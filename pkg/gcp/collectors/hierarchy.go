package gcloudcollectors

import (
	"context"
	"fmt"
	"strings"
	"time"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	iampolicies "cloud.google.com/go/iam/apiv2"
	iampoliciespb "cloud.google.com/go/iam/apiv2/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	gcperrors "github.com/praetorian-inc/nebula/pkg/gcp/errors"
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type HierarchyCollector struct {
	ctx                 context.Context
	clientOptions       []option.ClientOption
	organizationsClient *resourcemanager.OrganizationsClient
	foldersClient       *resourcemanager.FoldersClient
	projectsClient      *resourcemanager.ProjectsClient
	iamPoliciesClient   *iampolicies.PoliciesClient
	tagBindingsClient   *resourcemanager.TagBindingsClient
	IncludeSysProjects  bool
}

func NewHierarchyCollector(ctx context.Context, clientOptions ...option.ClientOption) (*HierarchyCollector, error) {
	collector := &HierarchyCollector{
		ctx:           ctx,
		clientOptions: clientOptions,
	}
	var err error
	collector.organizationsClient, err = resourcemanager.NewOrganizationsClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create organizations client: %w", err)
	}
	collector.foldersClient, err = resourcemanager.NewFoldersClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create folders client: %w", err)
	}
	collector.projectsClient, err = resourcemanager.NewProjectsClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create projects client: %w", err)
	}
	collector.iamPoliciesClient, err = iampolicies.NewPoliciesClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create iam policies client: %w", err)
	}
	collector.tagBindingsClient, err = resourcemanager.NewTagBindingsClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create tag bindings client: %w", err)
	}
	collector.IncludeSysProjects = false // by default don't pull these
	return collector, nil
}

func (c *HierarchyCollector) SetIncludeSysProjects() {
	c.IncludeSysProjects = true
}

func (c *HierarchyCollector) Close() error {
	var errs []error
	if c.organizationsClient != nil {
		if err := c.organizationsClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.foldersClient != nil {
		if err := c.foldersClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.projectsClient != nil {
		if err := c.projectsClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.iamPoliciesClient != nil {
		if err := c.iamPoliciesClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.tagBindingsClient != nil {
		if err := c.tagBindingsClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing clients: %v", errs)
	}
	return nil
}

func (c *HierarchyCollector) CollectOrganization(orgID string, org *gcptypes.Organization) error {
	orgName := normalizeOrgName(orgID)
	req := &resourcemanagerpb.GetOrganizationRequest{
		Name: orgName,
	}
	resp, err := c.organizationsClient.GetOrganization(c.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get organization %s: %w", orgName, err)
	}
	org.URI = toFullURI(resp.Name)
	org.DisplayName = resp.DisplayName
	org.CreateTime = resp.CreateTime.AsTime().Format("2006-01-02T15:04:05Z")
	org.OrganizationNumber = extractIDFromName(resp.Name)
	org.DirectoryCustomer = resp.GetDirectoryCustomerId()
	return nil
}

func (c *HierarchyCollector) CollectFolder(folderID string, folder *gcptypes.Folder) error {
	folderName := normalizeFolderName(folderID)
	req := &resourcemanagerpb.GetFolderRequest{
		Name: folderName,
	}
	resp, err := c.foldersClient.GetFolder(c.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get folder %s: %w", folderName, err)
	}
	folder.URI = toFullURI(resp.Name)
	folder.ParentURI = toFullURI(resp.Parent)
	folder.DisplayName = resp.DisplayName
	folder.CreateTime = resp.CreateTime.AsTime().Format("2006-01-02T15:04:05Z")
	folder.FolderNumber = extractIDFromName(resp.Name)
	return nil
}

func (c *HierarchyCollector) CollectFoldersInParent(parentURI string) ([]*gcptypes.Folder, error) {
	req := &resourcemanagerpb.ListFoldersRequest{
		Parent: toShortName(parentURI),
	}
	it := c.foldersClient.ListFolders(c.ctx, req)
	var folders []*gcptypes.Folder
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate folders: %w", err)
		}
		folder := &gcptypes.Folder{
			URI:          toFullURI(resp.Name),
			ParentURI:    toFullURI(resp.Parent),
			DisplayName:  resp.DisplayName,
			CreateTime:   resp.CreateTime.AsTime().Format("2006-01-02T15:04:05Z"),
			FolderNumber: extractIDFromName(resp.Name),
		}
		folders = append(folders, folder)
	}
	return folders, nil
}

func (c *HierarchyCollector) CollectProject(projectID string, project *gcptypes.Project) error {
	projectName := normalizeProjectName(projectID)
	req := &resourcemanagerpb.GetProjectRequest{
		Name: projectName,
	}
	resp, err := c.projectsClient.GetProject(c.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get project %s: %w", projectName, err)
	}
	project.URI = toFullURI(resp.Name)
	project.ParentURI = toFullURI(resp.Parent)
	project.DisplayName = resp.DisplayName
	project.CreateTime = resp.CreateTime.AsTime().Format("2006-01-02T15:04:05Z")
	project.ProjectNumber = extractIDFromName(resp.Name)
	project.ProjectID = resp.ProjectId
	if resp.Labels != nil {
		project.Labels = resp.Labels
	}
	return nil
}

func (c *HierarchyCollector) CollectProjectsInParent(parentURI string) ([]*gcptypes.Project, error) {
	req := &resourcemanagerpb.ListProjectsRequest{
		Parent: toShortName(parentURI),
	}
	it := c.projectsClient.ListProjects(c.ctx, req)
	var projects []*gcptypes.Project
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate projects: %w", err)
		}

		if !c.IncludeSysProjects && isSysProject(resp.ProjectId, resp.DisplayName) {
			continue
		}
		project := &gcptypes.Project{
			URI:           toFullURI(resp.Name),
			ParentURI:     toFullURI(resp.Parent),
			DisplayName:   resp.DisplayName,
			CreateTime:    resp.CreateTime.AsTime().Format("2006-01-02T15:04:05Z"),
			ProjectNumber: extractIDFromName(resp.Name),
			ProjectID:     resp.ProjectId,
		}
		if resp.Labels != nil {
			project.Labels = resp.Labels
		}
		projects = append(projects, project)
	}
	return projects, nil
}

func (c *HierarchyCollector) CollectAllowPolicy(resourceURI string, policies *gcptypes.Policies) error {
	shortName := toShortName(resourceURI)
	req := &iampb.GetIamPolicyRequest{
		Resource: shortName,
		Options: &iampb.GetPolicyOptions{
			RequestedPolicyVersion: 3,
		},
	}
	var policy *iampb.Policy
	var err error
	if strings.HasPrefix(shortName, "organizations/") {
		policy, err = c.organizationsClient.GetIamPolicy(c.ctx, req)
	} else if strings.HasPrefix(shortName, "folders/") {
		policy, err = c.foldersClient.GetIamPolicy(c.ctx, req)
	} else if strings.HasPrefix(shortName, "projects/") {
		policy, err = c.projectsClient.GetIamPolicy(c.ctx, req)
	} else {
		return fmt.Errorf("unsupported resource type for IAM policy: %s", resourceURI)
	}
	if err != nil {
		return fmt.Errorf("failed to get IAM policy for %s: %w", resourceURI, err)
	}
	allowPolicy := &gcptypes.AllowPolicy{
		ResourceURI: resourceURI,
		Version:     int(policy.Version),
		Etag:        string(policy.Etag),
	}
	for _, binding := range policy.Bindings {
		allowBinding := gcptypes.AllowBinding{
			Role:    binding.Role,
			Members: binding.Members,
		}
		if binding.Condition != nil {
			allowBinding.Condition = &gcptypes.Condition{
				Title:       binding.Condition.Title,
				Description: binding.Condition.Description,
				Expression:  binding.Condition.Expression,
			}
		}
		allowPolicy.Bindings = append(allowPolicy.Bindings, allowBinding)
	}
	policies.Allow = allowPolicy
	return nil
}

func (c *HierarchyCollector) CollectDenyPolicies(parentURI string, policies *gcptypes.Policies) error {
	parent := convertURIToDenyPolicyParent(toShortName(parentURI))
	req := &iampoliciespb.ListPoliciesRequest{
		Parent: parent,
	}
	it := c.iamPoliciesClient.ListPolicies(c.ctx, req)
	var denyPolicies []gcptypes.DenyPolicy
	for {
		time.Sleep(10 * time.Second) // Rate limit deny policy requests to stay under quota
		policy, err := gcperrors.RetryIterator(it.Next)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate deny policies for %s: %w", parentURI, err)
		}
		denyPolicy := gcptypes.DenyPolicy{
			Name:      policy.Name,
			Etag:      policy.Etag,
			ParentURI: parentURI,
		}
		for _, rule := range policy.Rules {
			denyRule := gcptypes.DenyRule{
				Description: rule.Description,
			}
			if dr := rule.GetDenyRule(); dr != nil {
				denyRule.DeniedPrincipals = dr.DeniedPrincipals
				denyRule.DeniedPermissions = dr.DeniedPermissions
				denyRule.ExceptionPrincipals = dr.ExceptionPrincipals
				if dr.DenialCondition != nil {
					denyRule.Condition = &gcptypes.Condition{
						Title:       dr.DenialCondition.Title,
						Description: dr.DenialCondition.Description,
						Expression:  dr.DenialCondition.Expression,
					}
				}
			}
			denyPolicy.Rules = append(denyPolicy.Rules, denyRule)
		}
		denyPolicies = append(denyPolicies, denyPolicy)
	}
	policies.Deny = denyPolicies
	return nil
}
