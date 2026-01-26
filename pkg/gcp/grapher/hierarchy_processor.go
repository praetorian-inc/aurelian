package gcloudiam

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gcloudcollectors "github.com/praetorian-inc/nebula/pkg/gcp/collectors"
	gcperrors "github.com/praetorian-inc/nebula/pkg/gcp/errors"
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/option"
)

type OperationMode string

const (
	ModeOnline         OperationMode = "online"
	ModeOfflineCollect OperationMode = "offline-collect"
	ModeOfflineAnalyze OperationMode = "offline-analyze"
)

type PolicyBinding struct {
	Member             string
	Role               string
	TargetResourceURI  string
	Condition          *gcptypes.Condition
	IsDeny             bool
	SourceContainerURI string
}

type HierarchyProcessor struct {
	ctx                context.Context
	hierarchyCollector *gcloudcollectors.HierarchyCollector
	roleCollector      *gcloudcollectors.RoleCollector
	pabCollector       *gcloudcollectors.PABCollector
	ancestryBuilder    *AncestryBuilder
	roleExpander       *RoleExpander
	normalizer         *MemberNormalizer
	selectorEvaluator  *SelectorEvaluator
	pabEvaluator       *PABEvaluator
	hierarchy          *gcptypes.Hierarchy
	allResources       []*gcptypes.Resource
	resourcesByURI     map[string]*gcptypes.Resource
	resourcesByType    map[string][]*gcptypes.Resource
	resourcesMutex     sync.Mutex

	projectIDToNumber  map[string]string
	projectNumberToID  map[string]string
	projectIDToURI     map[string]string
	projectNumberToURI map[string]string

	emailToServiceAccount map[string]*gcptypes.Resource

	pendingBindings []*PolicyBinding

	permissionTuples []*gcptypes.PermissionTuple
	containsEdges    []*gcptypes.ContainsEdge

	projectRoleMembers map[string]map[string][]string

	serviceAccountCollector    *gcloudcollectors.ServiceAccountCollector
	computeInstanceCollector   *gcloudcollectors.ComputeInstanceCollector
	cloudFunctionCollector     *gcloudcollectors.CloudFunctionCollector
	cloudRunCollector          *gcloudcollectors.CloudRunCollector
	storageBucketCollector     *gcloudcollectors.StorageBucketCollector
	secretCollector            *gcloudcollectors.SecretCollector
	deploymentManagerCollector *gcloudcollectors.DeploymentManagerCollector

	collectPABs         bool
	collectDenyPolicies bool
	mode                OperationMode
	dataDirectory       string
}

func NewHierarchyProcessor(ctx context.Context, collectPABs bool, collectDenyPolicies bool, mode OperationMode, dataDirectory string, clientOptions ...option.ClientOption) (*HierarchyProcessor, error) {
	hp := &HierarchyProcessor{
		ctx:                   ctx,
		hierarchy:             &gcptypes.Hierarchy{},
		resourcesByURI:        make(map[string]*gcptypes.Resource),
		resourcesByType:       make(map[string][]*gcptypes.Resource),
		projectIDToNumber:     make(map[string]string),
		projectNumberToID:     make(map[string]string),
		projectIDToURI:        make(map[string]string),
		projectNumberToURI:    make(map[string]string),
		emailToServiceAccount: make(map[string]*gcptypes.Resource),
		pendingBindings:       make([]*PolicyBinding, 0),
		projectRoleMembers:    make(map[string]map[string][]string),
		collectPABs:           collectPABs,
		collectDenyPolicies:   collectDenyPolicies,
		mode:                  mode,
		dataDirectory:         dataDirectory,
	}
	var err error

	if mode != ModeOfflineAnalyze {
		hp.hierarchyCollector, err = gcloudcollectors.NewHierarchyCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create hierarchy collector: %w", err)
		}
		hp.roleCollector, err = gcloudcollectors.NewRoleCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create role collector: %w", err)
		}
		hp.pabCollector, err = gcloudcollectors.NewPABCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create PAB collector: %w", err)
		}

		hp.serviceAccountCollector, err = gcloudcollectors.NewServiceAccountCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create service account collector: %w", err)
		}
		hp.computeInstanceCollector, err = gcloudcollectors.NewComputeInstanceCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create compute instance collector: %w", err)
		}
		hp.cloudFunctionCollector, err = gcloudcollectors.NewCloudFunctionCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create cloud function collector: %w", err)
		}
		hp.cloudRunCollector, err = gcloudcollectors.NewCloudRunCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create cloud run collector: %w", err)
		}
		hp.storageBucketCollector, err = gcloudcollectors.NewStorageBucketCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage bucket collector: %w", err)
		}
		hp.secretCollector, err = gcloudcollectors.NewSecretCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create secret collector: %w", err)
		}
		hp.deploymentManagerCollector, err = gcloudcollectors.NewDeploymentManagerCollector(ctx, clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create deployment manager collector: %w", err)
		}
	}

	hp.selectorEvaluator, err = NewSelectorEvaluator()
	if err != nil {
		return nil, fmt.Errorf("failed to create selector evaluator: %w", err)
	}
	hp.ancestryBuilder = NewAncestryBuilder()
	hp.roleExpander = NewRoleExpander()
	hp.normalizer = NewMemberNormalizer()
	return hp, nil
}

func (hp *HierarchyProcessor) Close() error {
	var errs []error
	if hp.hierarchyCollector != nil {
		if err := hp.hierarchyCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.roleCollector != nil {
		if err := hp.roleCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.pabCollector != nil {
		if err := hp.pabCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.serviceAccountCollector != nil {
		if err := hp.serviceAccountCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.computeInstanceCollector != nil {
		if err := hp.computeInstanceCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.cloudFunctionCollector != nil {
		if err := hp.cloudFunctionCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.cloudRunCollector != nil {
		if err := hp.cloudRunCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.storageBucketCollector != nil {
		if err := hp.storageBucketCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.secretCollector != nil {
		if err := hp.secretCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.deploymentManagerCollector != nil {
		if err := hp.deploymentManagerCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing collectors: %v", errs)
	}
	return nil
}

func (hp *HierarchyProcessor) Process(orgID string, assetTypes []string) error {
	switch hp.mode {
	case ModeOnline:
		return hp.processOnline(orgID, assetTypes)
	case ModeOfflineCollect:
		return hp.processOfflineCollect(orgID, assetTypes)
	case ModeOfflineAnalyze:
		return hp.processOfflineAnalyze()
	default:
		return fmt.Errorf("unknown operation mode: %s", hp.mode)
	}
}

func (hp *HierarchyProcessor) processOnline(orgID string, assetTypes []string) error {
	fmt.Println("[1/7] Collecting roles...")
	if err := hp.collectRoles(orgID); err != nil {
		return fmt.Errorf("failed to collect roles: %w", err)
	}

	fmt.Println("[2/7] Collecting hierarchy...")
	if err := hp.collectHierarchy(orgID); err != nil {
		return fmt.Errorf("failed to collect hierarchy: %w", err)
	}

	fmt.Println("[3/7] Collecting PAB policies...")
	if err := hp.collectPABPolicies(orgID); err != nil {
		fmt.Printf("Warning: failed to collect PAB policies: %v\n", err)
	}

	fmt.Println("[4/7] Processing container pass (storing policy bindings)...")
	_, containsEdges, err := hp.runContainerPass()
	if err != nil {
		return fmt.Errorf("failed to run container pass: %w", err)
	}
	fmt.Printf("Generated %d container CONTAINS edges\n", len(containsEdges))
	hp.containsEdges = containsEdges

	fmt.Println("[5/7] Collecting resources...")
	if err := hp.collectResources(assetTypes); err != nil {
		return fmt.Errorf("failed to collect resources: %w", err)
	}

	fmt.Println("[6/8] Processing resource pass (adding resource contains edges)...")
	resourceContainsEdges := hp.runResourcePass()
	fmt.Printf("Generated %d resource CONTAINS edges\n", len(resourceContainsEdges))
	hp.containsEdges = append(hp.containsEdges, resourceContainsEdges...)

	fmt.Println("[7/8] Processing Google-managed service accounts from policies...")
	hp.processGoogleManagedServiceAccounts()

	fmt.Println("[8/8] Resolving principals and emitting permission tuples...")
	permissionTuples := hp.processAndEmitTuples()
	hp.permissionTuples = permissionTuples

	fmt.Printf("Total permission tuples: %d\n", len(hp.permissionTuples))
	fmt.Printf("Total CONTAINS edges: %d\n", len(hp.containsEdges))
	return nil
}

func (hp *HierarchyProcessor) processOfflineCollect(orgID string, assetTypes []string) error {
	fmt.Println("[1/5] Collecting roles...")
	if err := hp.collectRoles(orgID); err != nil {
		return fmt.Errorf("failed to collect roles: %w", err)
	}
	fmt.Println("[2/5] Collecting hierarchy...")
	if err := hp.collectHierarchy(orgID); err != nil {
		return fmt.Errorf("failed to collect hierarchy: %w", err)
	}
	fmt.Println("[3/5] Collecting PAB policies...")
	if err := hp.collectPABPolicies(orgID); err != nil {
		fmt.Printf("Warning: failed to collect PAB policies: %v\n", err)
	}
	fmt.Println("[4/5] Collecting resources...")
	if err := hp.collectResources(assetTypes); err != nil {
		return fmt.Errorf("failed to collect resources: %w", err)
	}
	fmt.Println("[5/5] Saving offline data...")
	if err := hp.SaveToDirectory(orgID, assetTypes); err != nil {
		return fmt.Errorf("failed to save offline data: %w", err)
	}
	fmt.Println("Offline collection completed successfully")
	return nil
}

func (hp *HierarchyProcessor) processOfflineAnalyze() error {
	fmt.Println("[1/4] Loading offline data...")
	if err := hp.LoadFromDirectory(); err != nil {
		return fmt.Errorf("failed to load offline data: %w", err)
	}
	fmt.Println("[2/4] Running container pass...")
	_, containsEdges, err := hp.runContainerPass()
	if err != nil {
		return fmt.Errorf("failed to run container pass: %w", err)
	}
	fmt.Printf("Generated %d container CONTAINS edges\n", len(containsEdges))
	hp.containsEdges = containsEdges
	fmt.Println("[3/5] Running resource pass...")
	resourceContainsEdges := hp.runResourcePass()
	fmt.Printf("Generated %d resource CONTAINS edges\n", len(resourceContainsEdges))
	hp.containsEdges = append(hp.containsEdges, resourceContainsEdges...)
	fmt.Println("[4/5] Processing Google-managed service accounts from policies...")
	hp.processGoogleManagedServiceAccounts()
	fmt.Println("[5/5] Resolving principals and emitting permission tuples...")
	permissionTuples := hp.processAndEmitTuples()
	hp.permissionTuples = permissionTuples
	fmt.Printf("\n[5/5] Analysis completed:")
	fmt.Printf("  - Total permission edges: %d\n", len(hp.permissionTuples))
	fmt.Printf("  - Total CONTAINS edges: %d\n", len(hp.containsEdges))
	return nil
}

func (hp *HierarchyProcessor) collectRoles(orgID string) error {
	predefinedRoles, err := hp.roleCollector.CollectPredefinedRoles()
	if err != nil {
		return err
	}
	hp.roleExpander.AddRoles(predefinedRoles)
	customOrgRoles, err := hp.roleCollector.CollectCustomRolesInOrg(orgID)
	if err != nil {
		fmt.Printf("Warning: failed to collect org custom roles: %v\n", err)
	} else {
		hp.roleExpander.AddRoles(customOrgRoles)
	}
	return nil
}

func (hp *HierarchyProcessor) collectHierarchy(orgID string) error {
	org := &gcptypes.Organization{}
	if err := hp.hierarchyCollector.CollectOrganization(orgID, org); err != nil {
		return err
	}
	if err := hp.hierarchyCollector.CollectAllowPolicy(org.URI, &org.Policies); err != nil {
		fmt.Printf("Warning: failed to collect org allow policy: %v\n", err)
	}
	if hp.collectDenyPolicies {
		if err := hp.hierarchyCollector.CollectDenyPolicies(org.URI, &org.Policies); err != nil {
			fmt.Printf("Warning: failed to collect org deny policies: %v\n", err)
		}
	}
	if err := hp.collectFoldersRecursive(org.URI, org); err != nil {
		return err
	}
	if err := hp.collectProjectsInParent(org.URI, org); err != nil {
		return err
	}
	hp.hierarchy.Organizations = append(hp.hierarchy.Organizations, org)
	hp.ancestryBuilder.AddOrganization(org)
	hp.AddResource(org.ToResource())
	return nil
}

func (hp *HierarchyProcessor) collectFoldersRecursive(parentURI string, parent any) error {
	folders, err := hp.hierarchyCollector.CollectFoldersInParent(parentURI)
	if err != nil {
		return err
	}
	for _, folder := range folders {
		if err := hp.hierarchyCollector.CollectAllowPolicy(folder.URI, &folder.Policies); err != nil {
			fmt.Printf("Warning: failed to collect folder %s allow policy: %v\n", folder.URI, err)
		}
		if hp.collectDenyPolicies {
			if err := hp.hierarchyCollector.CollectDenyPolicies(folder.URI, &folder.Policies); err != nil {
				fmt.Printf("Warning: failed to collect folder %s deny policies: %v\n", folder.URI, err)
			}
		}
		if err := hp.collectFoldersRecursive(folder.URI, folder); err != nil {
			return err
		}
		if err := hp.collectProjectsInParent(folder.URI, folder); err != nil {
			return err
		}
		hp.ancestryBuilder.AddFolder(folder)
		hp.AddResource(folder.ToResource())
		switch p := parent.(type) {
		case *gcptypes.Organization:
			p.Folders = append(p.Folders, folder)
		case *gcptypes.Folder:
			p.Folders = append(p.Folders, folder)
		}
	}
	return nil
}

func (hp *HierarchyProcessor) collectProjectsInParent(parentURI string, parent any) error {
	projects, err := hp.hierarchyCollector.CollectProjectsInParent(parentURI)
	if err != nil {
		return err
	}
	for _, project := range projects {
		if err := hp.hierarchyCollector.CollectAllowPolicy(project.URI, &project.Policies); err != nil {
			fmt.Printf("Warning: failed to collect project %s allow policy: %v\n", project.URI, err)
		}
		if hp.collectDenyPolicies {
			if err := hp.hierarchyCollector.CollectDenyPolicies(project.URI, &project.Policies); err != nil {
				fmt.Printf("Warning: failed to collect project %s deny policies: %v\n", project.URI, err)
			}
		}
		customProjectRoles, err := hp.roleCollector.CollectCustomRolesInProject(project.ProjectID)
		if err != nil {
			fmt.Printf("Warning: failed to collect project %s custom roles: %v\n", project.ProjectID, err)
		} else {
			hp.roleExpander.AddRoles(customProjectRoles)
		}

		hp.projectIDToNumber[project.ProjectID] = project.ProjectNumber
		hp.projectNumberToID[project.ProjectNumber] = project.ProjectID
		hp.projectIDToURI[project.ProjectID] = project.URI
		hp.projectNumberToURI[project.ProjectNumber] = project.URI

		hp.ancestryBuilder.AddProject(project)
		hp.AddResource(project.ToResource())
		switch p := parent.(type) {
		case *gcptypes.Organization:
			p.Projects = append(p.Projects, project)
		case *gcptypes.Folder:
			p.Projects = append(p.Projects, project)
		}
	}
	return nil
}

func (hp *HierarchyProcessor) collectPABPolicies(orgID string) error {
	if !hp.collectPABs {
		fmt.Println("Skipping PAB collection (disabled)")
		// Create empty PAB evaluator to avoid nil checks
		hp.pabEvaluator = NewPABEvaluator([]gcptypes.PABPolicy{}, []gcptypes.PABBinding{}, hp.normalizer)
		return nil
	}

	pabPolicies, err := hp.pabCollector.CollectPABPolicies(orgID)
	if err != nil {
		return err
	}
	var pabBindings []gcptypes.PABBinding
	for _, org := range hp.hierarchy.Organizations {
		bindings, err := hp.pabCollector.CollectPABBindings(org.URI)
		if err != nil {
			fmt.Printf("Warning: failed to collect PAB bindings for org: %v\n", err)
		} else {
			pabBindings = append(pabBindings, bindings...)
		}
		org.PABPolicies = pabPolicies
	}
	hp.pabEvaluator = NewPABEvaluator(pabPolicies, pabBindings, hp.normalizer)
	hp.pabEvaluator.BuildPABMasks()
	return nil
}

func (hp *HierarchyProcessor) runContainerPass() ([]*gcptypes.PermissionTuple, []*gcptypes.ContainsEdge, error) {
	containsEdges := make([]*gcptypes.ContainsEdge, 0)

	for _, org := range hp.hierarchy.Organizations {
		orgResource := org.ToResource()
		hp.AddResource(orgResource)

		projectURIs := hp.getAllProjectURIsUnder(org.URI)

		if org.Policies.Allow != nil {
			hp.storeContainerBindings(org.Policies.Allow, projectURIs, org.URI)
		}

		if len(org.Policies.Deny) > 0 {
			hp.storeDenyBindings(org.Policies.Deny, projectURIs, org.URI)
		}

		folderContains := hp.processFoldersForContains(org.Folders, orgResource)
		containsEdges = append(containsEdges, folderContains...)

		projectContains := hp.processProjectsForContains(org.Projects, orgResource)
		containsEdges = append(containsEdges, projectContains...)
	}

	return make([]*gcptypes.PermissionTuple, 0), containsEdges, nil
}

func (hp *HierarchyProcessor) collectResources(assetTypes []string) error {
	for _, org := range hp.hierarchy.Organizations {
		if err := hp.collectResourcesInContainer(org.URI, assetTypes); err != nil {
			return err
		}
	}
	return nil
}

func (hp *HierarchyProcessor) collectResourcesInContainer(containerURI string, assetTypes []string) error {
	if strings.Contains(containerURI, "/projects/") {
		projectNumber := extractProjectIDFromURI(containerURI)
		projectID := hp.projectNumberToID[projectNumber]
		if projectID == "" {
			projectID = projectNumber
		}
		if err := hp.collectResourcesInProject(projectID, projectNumber); err != nil {
			fmt.Printf("Warning: failed to collect resources in %s: %v\n", containerURI, err)
			return nil
		}
	}
	node := hp.ancestryBuilder.GetNode(containerURI)
	switch n := node.(type) {
	case *gcptypes.Organization:
		for _, folder := range n.Folders {
			if err := hp.collectResourcesInContainer(folder.URI, assetTypes); err != nil {
				return err
			}
		}
		hp.collectResourcesInProjectsParallel(n.Projects)
	case *gcptypes.Folder:
		for _, folder := range n.Folders {
			if err := hp.collectResourcesInContainer(folder.URI, assetTypes); err != nil {
				return err
			}
		}
		hp.collectResourcesInProjectsParallel(n.Projects)
	}
	return nil
}

func (hp *HierarchyProcessor) collectResourcesInProjectsParallel(projects []*gcptypes.Project) {
	if len(projects) == 0 {
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for _, project := range projects {
		wg.Add(1)
		sem <- struct{}{}
		go func(proj *gcptypes.Project) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := hp.collectResourcesInProject(proj.ProjectID, proj.ProjectNumber); err != nil {
				fmt.Printf("Warning: failed to collect resources in %s: %v\n", proj.URI, err)
			}
		}(project)
	}
	wg.Wait()
}

func (hp *HierarchyProcessor) collectResourcesInProject(projectID, projectNumber string) error {
	ctx := hp.ctx

	handleError := func(resourceType string, err error) {
		if gcperrors.IsServiceDisabled(err) {
		} else if gcperrors.IsPermissionDenied(err) {
		} else {
			fmt.Printf("  Warning: failed to collect %s: %v\n", resourceType, err)
		}
	}

	serviceAccounts, err := hp.serviceAccountCollector.CollectWithPolicies(ctx, projectID, projectNumber)
	if err != nil {
		handleError("service accounts", err)
	} else if len(serviceAccounts) > 0 {
		for _, resource := range serviceAccounts {
			hp.AddResource(resource)

			email := resource.Properties["email"]
			if email != "" {
				hp.emailToServiceAccount[email] = resource
			}

			if resource.Policies.Allow != nil {
				hp.storeResourceBindings(resource.Policies.Allow, resource.URI)
			}
		}
		fmt.Printf("  Collected %d service accounts in %s\n", len(serviceAccounts), projectID)
	}

	instances, err := hp.computeInstanceCollector.CollectWithPolicies(ctx, projectID, projectNumber)
	if err != nil {
		handleError("compute instances", err)
	} else if len(instances) > 0 {
		for _, resource := range instances {
			hp.AddResource(resource)
			if resource.Policies.Allow != nil {
				hp.storeResourceBindings(resource.Policies.Allow, resource.URI)
			}
		}
		fmt.Printf("  Collected %d compute instances in %s\n", len(instances), projectID)
	}

	functions, err := hp.cloudFunctionCollector.CollectWithPolicies(ctx, projectID, projectNumber)
	if err != nil {
		handleError("cloud functions", err)
	} else if len(functions) > 0 {
		for _, resource := range functions {
			hp.AddResource(resource)
			if resource.Policies.Allow != nil {
				hp.storeResourceBindings(resource.Policies.Allow, resource.URI)
			}
		}
		fmt.Printf("  Collected %d cloud functions in %s\n", len(functions), projectID)
	}

	cloudRunServices, err := hp.cloudRunCollector.CollectWithPolicies(ctx, projectID, projectNumber)
	if err != nil {
		handleError("cloud run services", err)
	} else if len(cloudRunServices) > 0 {
		for _, resource := range cloudRunServices {
			hp.AddResource(resource)
			if resource.Policies.Allow != nil {
				hp.storeResourceBindings(resource.Policies.Allow, resource.URI)
			}
		}
		fmt.Printf("  Collected %d cloud run services in %s\n", len(cloudRunServices), projectID)
	}

	buckets, err := hp.storageBucketCollector.CollectWithPolicies(ctx, projectID, projectNumber)
	if err != nil {
		handleError("storage buckets", err)
	} else if len(buckets) > 0 {
		for _, resource := range buckets {
			hp.AddResource(resource)
			if resource.Policies.Allow != nil {
				hp.storeResourceBindings(resource.Policies.Allow, resource.URI)
			}
		}
		fmt.Printf("  Collected %d storage buckets in %s\n", len(buckets), projectID)
	}

	secrets, err := hp.secretCollector.CollectWithPolicies(ctx, projectID, projectNumber)
	if err != nil {
		handleError("secrets", err)
	} else if len(secrets) > 0 {
		for _, resource := range secrets {
			hp.AddResource(resource)
			if resource.Policies.Allow != nil {
				hp.storeResourceBindings(resource.Policies.Allow, resource.URI)
			}
		}
		fmt.Printf("  Collected %d secrets in %s\n", len(secrets), projectID)
	}

	deployments, err := hp.deploymentManagerCollector.CollectWithPolicies(ctx, projectID, projectNumber)
	if err != nil {
		handleError("deployment manager deployments", err)
	} else if len(deployments) > 0 {
		for _, resource := range deployments {
			hp.AddResource(resource)
			if resource.Policies.Allow != nil {
				hp.storeResourceBindings(resource.Policies.Allow, resource.URI)
			}
		}
		fmt.Printf("  Collected %d deployment manager deployments in %s\n", len(deployments), projectID)
	}

	return nil
}

func (hp *HierarchyProcessor) runResourcePass() []*gcptypes.ContainsEdge {
	containsEdges := make([]*gcptypes.ContainsEdge, 0)
	for _, resource := range hp.allResources {
		if resource.ParentURI != "" {
			parentResource := hp.GetResourceByURI(resource.ParentURI)
			if parentResource != nil {
				containsEdges = append(containsEdges, &gcptypes.ContainsEdge{
					Parent: parentResource,
					Child:  resource,
				})
			}
		}
	}
	return containsEdges
}

func (hp *HierarchyProcessor) processGoogleManagedServiceAccounts() {
	processedEmails := make(map[string]bool)

	for _, binding := range hp.pendingBindings {
		if !strings.HasPrefix(binding.Member, "serviceAccount:") {
			continue
		}

		email := strings.TrimPrefix(binding.Member, "serviceAccount:")

		if processedEmails[email] {
			continue
		}

		if _, exists := hp.emailToServiceAccount[email]; exists {
			continue
		}

		isManaged, projectNumber := IsGoogleManagedServiceAccount(email)
		if !isManaged {
			continue
		}

		parentURI, exists := hp.projectNumberToURI[projectNumber]
		if !exists {
			continue
		}

		resource := &gcptypes.Resource{
			AssetType: "iam.googleapis.com/ServiceAccount",
			URI:       gcloudcollectors.BuildServiceAccountURI(email, projectNumber),
			ParentURI: parentURI,
			Name:      email,
			Properties: map[string]string{
				"email":         email,
				"projectNumber": projectNumber,
				"googleManaged": "true",
			},
		}

		hp.AddResource(resource)
		hp.emailToServiceAccount[email] = resource

		parentResource := hp.GetResourceByURI(parentURI)
		if parentResource != nil {
			hp.containsEdges = append(hp.containsEdges, &gcptypes.ContainsEdge{
				Parent: parentResource,
				Child:  resource,
			})
		}

		processedEmails[email] = true
	}

	if len(processedEmails) > 0 {
		fmt.Printf("Processed %d Google-managed service accounts from policy bindings\n", len(processedEmails))
	}
}

func (hp *HierarchyProcessor) processAndEmitTuples() []*gcptypes.PermissionTuple {
	tuples := make([]*gcptypes.PermissionTuple, 0)

	fmt.Printf("Processing %d pending policy bindings...\n", len(hp.pendingBindings))

	for _, binding := range hp.pendingBindings {
		var permissions gcptypes.PermissionSet
		var err error

		if binding.IsDeny {
			permissions = gcptypes.PermissionSet{gcptypes.Permission(binding.Role): struct{}{}}
		} else {
			permissions, err = hp.roleExpander.ExpandRole(binding.Role)
			if err != nil {
				fmt.Printf("Warning: failed to expand role %s: %v\n", binding.Role, err)
				continue
			}
		}

		sourceResources := hp.resolvePrincipalFromMember(binding.Member)

		for _, sr := range sourceResources {
			hp.AddResource(sr)
		}

		targetResource := hp.GetResourceByURI(binding.TargetResourceURI)
		if targetResource == nil {
			fmt.Printf("Warning: target resource not found: %s\n", binding.TargetResourceURI)
			continue
		}

		for _, sourceResource := range sourceResources {
			for permission := range permissions {
				if !binding.IsDeny && !IsPrivescPermission(permission) {
					continue
				}

				tuple := &gcptypes.PermissionTuple{
					Source:     sourceResource,
					Permission: permission,
					Target:     targetResource,
					Provenance: &gcptypes.Provenance{
						ViaContainers: []string{binding.SourceContainerURI},
						ViaRoles:      []string{binding.Role},
						IsConditional: binding.Condition != nil,
						Conditions:    []string{},
					},
					IsDeny: binding.IsDeny,
				}

				if binding.Condition != nil {
					tuple.Provenance.Conditions = []string{binding.Condition.Expression}
				}

				tuples = append(tuples, tuple)
			}
		}
	}

	fmt.Printf("Emitted %d permission tuples from bindings\n", len(tuples))
	return tuples
}

func (hp *HierarchyProcessor) GetTuples() []*gcptypes.PermissionTuple {
	return hp.permissionTuples
}

func (hp *HierarchyProcessor) GetPermissionTuples() []*gcptypes.PermissionTuple {
	return hp.permissionTuples
}

func (hp *HierarchyProcessor) GetContainsEdges() []*gcptypes.ContainsEdge {
	return hp.containsEdges
}

func (hp *HierarchyProcessor) GetHierarchy() *gcptypes.Hierarchy {
	return hp.hierarchy
}

func (hp *HierarchyProcessor) GetAllResources() []*gcptypes.Resource {
	hp.resourcesMutex.Lock()
	defer hp.resourcesMutex.Unlock()
	return hp.allResources
}

func (hp *HierarchyProcessor) AddResource(resource *gcptypes.Resource) {
	hp.resourcesMutex.Lock()
	defer hp.resourcesMutex.Unlock()
	hp.allResources = append(hp.allResources, resource)
	hp.resourcesByURI[resource.URI] = resource
	hp.resourcesByType[resource.AssetType] = append(hp.resourcesByType[resource.AssetType], resource)
}

func (hp *HierarchyProcessor) GetResourceByURI(uri string) *gcptypes.Resource {
	hp.resourcesMutex.Lock()
	defer hp.resourcesMutex.Unlock()
	return hp.resourcesByURI[uri]
}

func (hp *HierarchyProcessor) GetResourcesByType(assetType string) []*gcptypes.Resource {
	hp.resourcesMutex.Lock()
	defer hp.resourcesMutex.Unlock()
	return hp.resourcesByType[assetType]
}

type principalSetComponents struct {
	containerType string
	containerID   string
	principalType string
}

func (hp *HierarchyProcessor) parsePrincipalSetURI(uri string) *principalSetComponents {
	if !strings.HasPrefix(uri, "principalSet://cloudresourcemanager.googleapis.com/") {
		return nil
	}
	path := strings.TrimPrefix(uri, "principalSet://cloudresourcemanager.googleapis.com/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parts[2] != "type" {
		return nil
	}
	return &principalSetComponents{
		containerType: parts[0],
		containerID:   parts[1],
		principalType: parts[3],
	}
}

func (hp *HierarchyProcessor) matchesContainer(resource *gcptypes.Resource, containerType, containerID string) bool {
	switch containerType {
	case "projects":
		project := hp.findProjectByNumber(containerID)
		if project == nil {
			return strings.Contains(resource.ParentURI, "/projects/"+containerID)
		}
		projectIDFromProps := project.Properties["projectId"]
		return strings.Contains(resource.ParentURI, "/projects/"+projectIDFromProps) ||
			strings.Contains(resource.ParentURI, "/projects/"+containerID)
	case "folders":
		matchingProjects := hp.findProjectsInFolder(containerID)
		for _, proj := range matchingProjects {
			projID := proj.Properties["projectId"]
			if strings.Contains(resource.ParentURI, "/projects/"+projID) {
				return true
			}
		}
		return false
	case "organizations":
		matchingProjects := hp.findProjectsInOrganization(containerID)
		for _, proj := range matchingProjects {
			projID := proj.Properties["projectId"]
			if strings.Contains(resource.ParentURI, "/projects/"+projID) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (hp *HierarchyProcessor) findProjectByNumber(projectNumber string) *gcptypes.Resource {
	projects := hp.GetResourcesByType("cloudresourcemanager.googleapis.com/Project")
	for _, proj := range projects {
		if proj.Properties["projectNumber"] == projectNumber {
			return proj
		}
	}
	return nil
}

func (hp *HierarchyProcessor) findProjectsInFolder(folderID string) []*gcptypes.Resource {
	projects := hp.GetResourcesByType("cloudresourcemanager.googleapis.com/Project")
	matching := make([]*gcptypes.Resource, 0)
	folderURI := "//cloudresourcemanager.googleapis.com/folders/" + folderID
	for _, proj := range projects {
		if hp.isDescendantOf(proj, folderURI) {
			matching = append(matching, proj)
		}
	}
	return matching
}

func (hp *HierarchyProcessor) findProjectsInOrganization(orgID string) []*gcptypes.Resource {
	projects := hp.GetResourcesByType("cloudresourcemanager.googleapis.com/Project")
	matching := make([]*gcptypes.Resource, 0)
	orgURI := "//cloudresourcemanager.googleapis.com/organizations/" + orgID
	for _, proj := range projects {
		if hp.isDescendantOf(proj, orgURI) {
			matching = append(matching, proj)
		}
	}
	return matching
}

func (hp *HierarchyProcessor) isDescendantOf(resource *gcptypes.Resource, ancestorURI string) bool {
	currentURI := resource.ParentURI
	for currentURI != "" {
		if currentURI == ancestorURI {
			return true
		}
		parentResource := hp.GetResourceByURI(currentURI)
		if parentResource == nil {
			break
		}
		currentURI = parentResource.ParentURI
	}
	return false
}

func (hp *HierarchyProcessor) ResolvePrincipalSet(principalSetURI string) []*gcptypes.Resource {
	components := hp.parsePrincipalSetURI(principalSetURI)
	if components == nil {
		if strings.Contains(principalSetURI, "workloadIdentityPools") {
			return []*gcptypes.Resource{hp.createWorkloadIdentityPrincipalSet(principalSetURI)}
		}

		return []*gcptypes.Resource{
			{
				AssetType:  "iam.googleapis.com/PrincipalSet",
				URI:        principalSetURI,
				ParentURI:  "",
				Name:       principalSetURI,
				Properties: map[string]string{"principalSetUri": principalSetURI},
			},
		}
	}

	if components.principalType != "ServiceAccount" {
		return []*gcptypes.Resource{
			{
				AssetType: "iam.googleapis.com/PrincipalSet",
				URI:       principalSetURI,
				ParentURI: "",
				Name:      principalSetURI,
				Properties: map[string]string{
					"principalSetUri": principalSetURI,
					"principalType":   components.principalType,
					"unresolved":      "true",
				},
			},
		}
	}

	allServiceAccounts := hp.GetResourcesByType("iam.googleapis.com/ServiceAccount")
	matchingServiceAccounts := make([]*gcptypes.Resource, 0)
	for _, sa := range allServiceAccounts {
		if hp.matchesContainer(sa, components.containerType, components.containerID) {
			matchingServiceAccounts = append(matchingServiceAccounts, sa)
		}
	}
	return matchingServiceAccounts
}

func (hp *HierarchyProcessor) createWorkloadIdentityPrincipalSet(principalSetURI string) *gcptypes.Resource {
	parts := strings.Split(principalSetURI, "/")

	var projectID string
	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			projectID = parts[i+1]
			break
		}
	}

	parentURI := ""
	if projectNumber, ok := hp.projectIDToNumber[projectID]; ok {
		parentURI = fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", projectNumber)
	}

	lastPart := parts[len(parts)-1]

	return &gcptypes.Resource{
		AssetType: "iam.googleapis.com/WorkloadIdentityPoolPrincipalSet",
		URI:       principalSetURI,
		ParentURI: parentURI,
		Name:      lastPart,
		Properties: map[string]string{
			"principalSetUri": principalSetURI,
			"projectId":       projectID,
		},
	}
}

func (hp *HierarchyProcessor) getAllProjectURIsUnder(containerURI string) []string {
	node := hp.ancestryBuilder.GetNode(containerURI)
	switch n := node.(type) {
	case *gcptypes.Organization:
		return hp.collectProjectURIsFromOrg(n)
	case *gcptypes.Folder:
		return hp.collectProjectURIsFromFolder(n)
	case *gcptypes.Project:
		return []string{n.URI}
	default:
		return []string{}
	}
}

func (hp *HierarchyProcessor) collectProjectURIsFromOrg(org *gcptypes.Organization) []string {
	projectURIs := make([]string, 0)
	for _, project := range org.Projects {
		projectURIs = append(projectURIs, project.URI)
	}
	for _, folder := range org.Folders {
		projectURIs = append(projectURIs, hp.collectProjectURIsFromFolder(folder)...)
	}
	return projectURIs
}

func (hp *HierarchyProcessor) collectProjectURIsFromFolder(folder *gcptypes.Folder) []string {
	projectURIs := make([]string, 0)
	for _, project := range folder.Projects {
		projectURIs = append(projectURIs, project.URI)
	}
	for _, subfolder := range folder.Folders {
		projectURIs = append(projectURIs, hp.collectProjectURIsFromFolder(subfolder)...)
	}
	return projectURIs
}

func (hp *HierarchyProcessor) storeContainerBindings(
	policy *gcptypes.AllowPolicy,
	targetProjectURIs []string,
	sourceContainerURI string,
) {
	if policy == nil {
		return
	}
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			hp.trackBasicRoleAssignment(binding.Role, member, targetProjectURIs)

			for _, projectURI := range targetProjectURIs {
				hp.pendingBindings = append(hp.pendingBindings, &PolicyBinding{
					Member:             member,
					Role:               binding.Role,
					TargetResourceURI:  projectURI,
					Condition:          binding.Condition,
					IsDeny:             false,
					SourceContainerURI: sourceContainerURI,
				})
			}
		}
	}
}

func (hp *HierarchyProcessor) storeDenyBindings(
	denyPolicies []gcptypes.DenyPolicy,
	targetProjectURIs []string,
	sourceContainerURI string,
) {
	for _, denyPolicy := range denyPolicies {
		for _, rule := range denyPolicy.Rules {
			for _, deniedMember := range rule.DeniedPrincipals {
				for _, permissionStr := range rule.DeniedPermissions {
					for _, projectURI := range targetProjectURIs {
						hp.pendingBindings = append(hp.pendingBindings, &PolicyBinding{
							Member:             deniedMember,
							Role:               permissionStr,
							TargetResourceURI:  projectURI,
							Condition:          rule.Condition,
							IsDeny:             true,
							SourceContainerURI: sourceContainerURI,
						})
					}
				}
			}
		}
	}
}

func (hp *HierarchyProcessor) storeResourceBindings(
	policy *gcptypes.AllowPolicy,
	targetResourceURI string,
) {
	if policy == nil {
		return
	}
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			hp.pendingBindings = append(hp.pendingBindings, &PolicyBinding{
				Member:             member,
				Role:               binding.Role,
				TargetResourceURI:  targetResourceURI,
				Condition:          binding.Condition,
				IsDeny:             false,
				SourceContainerURI: "",
			})
		}
	}
}

func (hp *HierarchyProcessor) processFoldersForContains(
	folders []*gcptypes.Folder,
	parentResource *gcptypes.Resource,
) []*gcptypes.ContainsEdge {
	containsEdges := make([]*gcptypes.ContainsEdge, 0)
	for _, folder := range folders {
		folderResource := folder.ToResource()
		hp.AddResource(folderResource)

		containsEdges = append(containsEdges, &gcptypes.ContainsEdge{
			Parent: parentResource,
			Child:  folderResource,
		})

		projectURIs := hp.getAllProjectURIsUnder(folder.URI)
		if folder.Policies.Allow != nil {
			hp.storeContainerBindings(folder.Policies.Allow, projectURIs, folder.URI)
		}
		if len(folder.Policies.Deny) > 0 {
			hp.storeDenyBindings(folder.Policies.Deny, projectURIs, folder.URI)
		}

		subfolderContains := hp.processFoldersForContains(folder.Folders, folderResource)
		containsEdges = append(containsEdges, subfolderContains...)

		subprojectContains := hp.processProjectsForContains(folder.Projects, folderResource)
		containsEdges = append(containsEdges, subprojectContains...)
	}
	return containsEdges
}

func (hp *HierarchyProcessor) processProjectsForContains(
	projects []*gcptypes.Project,
	parentResource *gcptypes.Resource,
) []*gcptypes.ContainsEdge {
	containsEdges := make([]*gcptypes.ContainsEdge, 0)
	for _, project := range projects {
		projectResource := project.ToResource()
		hp.AddResource(projectResource)

		containsEdges = append(containsEdges, &gcptypes.ContainsEdge{
			Parent: parentResource,
			Child:  projectResource,
		})

		projectURIs := []string{project.URI}
		if project.Policies.Allow != nil {
			hp.storeContainerBindings(project.Policies.Allow, projectURIs, project.URI)
		}
		if len(project.Policies.Deny) > 0 {
			hp.storeDenyBindings(project.Policies.Deny, projectURIs, project.URI)
		}
	}
	return containsEdges
}

func (hp *HierarchyProcessor) trackBasicRoleAssignment(role string, member string, targetProjectURIs []string) {
	var roleType string
	switch role {
	case "roles/owner":
		roleType = "owner"
	case "roles/editor":
		roleType = "editor"
	case "roles/viewer":
		roleType = "viewer"
	default:
		return
	}

	var sourceResources []*gcptypes.Resource
	if strings.HasPrefix(member, "principalSet://") {
		sourceResources = hp.ResolvePrincipalSet(member)
	} else {
		sourceResource := hp.normalizer.NormalizeMember(member)
		sourceResources = []*gcptypes.Resource{sourceResource}
	}

	for _, projectURI := range targetProjectURIs {
		projectID := strings.TrimPrefix(projectURI, "//cloudresourcemanager.googleapis.com/projects/")
		if hp.projectRoleMembers[projectID] == nil {
			hp.projectRoleMembers[projectID] = make(map[string][]string)
		}
		for _, sourceResource := range sourceResources {
			hp.AddResource(sourceResource)
			hp.projectRoleMembers[projectID][roleType] = append(
				hp.projectRoleMembers[projectID][roleType],
				sourceResource.URI,
			)
		}
	}
}

func (hp *HierarchyProcessor) resolvePrincipalFromMember(member string) []*gcptypes.Resource {
	if strings.HasPrefix(member, "principalSet://") {
		return hp.ResolvePrincipalSet(member)
	}

	if strings.HasPrefix(member, "projectOwner:") ||
		strings.HasPrefix(member, "projectEditor:") ||
		strings.HasPrefix(member, "projectViewer:") {
		return hp.expandProjectRoleConvenience(member)
	}

	isDeleted := false
	originalMember := member
	if strings.HasPrefix(member, "deleted:") {
		isDeleted = true
		member = strings.TrimPrefix(member, "deleted:")
	}

	if strings.HasPrefix(member, "serviceAccount:") {
		email := strings.TrimPrefix(member, "serviceAccount:")

		if strings.HasSuffix(email, ".svc.id.goog") {
			return hp.createWorkloadIdentityFromKSA(email, isDeleted)
		}

		if isDeleted {
			return []*gcptypes.Resource{hp.createDeletedServiceAccountStub(email, originalMember)}
		}

		if sa, found := hp.emailToServiceAccount[email]; found {
			return []*gcptypes.Resource{sa}
		}

		return []*gcptypes.Resource{hp.createStubServiceAccount(email)}
	}

	if strings.HasPrefix(member, "user:") {
		email := strings.TrimPrefix(member, "user:")
		return []*gcptypes.Resource{
			{
				AssetType:  "iam.googleapis.com/User",
				URI:        member,
				ParentURI:  "",
				Name:       email,
				Properties: map[string]string{"email": email},
			},
		}
	}

	if strings.HasPrefix(member, "group:") {
		email := strings.TrimPrefix(member, "group:")
		return []*gcptypes.Resource{
			{
				AssetType:  "iam.googleapis.com/Group",
				URI:        member,
				ParentURI:  "",
				Name:       email,
				Properties: map[string]string{"email": email},
			},
		}
	}

	if strings.HasPrefix(member, "domain:") {
		domain := strings.TrimPrefix(member, "domain:")
		return []*gcptypes.Resource{
			{
				AssetType:  "iam.googleapis.com/Domain",
				URI:        member,
				ParentURI:  "",
				Name:       domain,
				Properties: map[string]string{"domain": domain},
			},
		}
	}

	if member == "allUsers" {
		return []*gcptypes.Resource{
			{
				AssetType:  "iam.googleapis.com/AllUsers",
				URI:        "allUsers",
				ParentURI:  "",
				Name:       "allUsers",
				Properties: map[string]string{},
			},
		}
	}

	if member == "allAuthenticatedUsers" {
		return []*gcptypes.Resource{
			{
				AssetType:  "iam.googleapis.com/AllAuthenticatedUsers",
				URI:        "allAuthenticatedUsers",
				ParentURI:  "",
				Name:       "allAuthenticatedUsers",
				Properties: map[string]string{},
			},
		}
	}

	if strings.HasPrefix(member, "principal://iam.googleapis.com/") {
		if strings.Contains(member, "workloadIdentityPools") {
			return []*gcptypes.Resource{hp.createWorkloadIdentityPrincipal(member)}
		}
		if strings.Contains(member, "workforcePools") {
			return []*gcptypes.Resource{hp.createWorkforceIdentityPrincipal(member)}
		}
	}

	fmt.Printf("Warning: Unknown member type: %s\n", member)
	return []*gcptypes.Resource{
		{
			AssetType:  "iam.googleapis.com/Unknown",
			URI:        member,
			ParentURI:  "",
			Name:       member,
			Properties: map[string]string{"originalMember": member},
		},
	}
}

func (hp *HierarchyProcessor) createStubServiceAccount(email string) *gcptypes.Resource {
	projectID := gcloudcollectors.ExtractProjectIDFromEmail(email)

	return &gcptypes.Resource{
		AssetType: "iam.googleapis.com/ServiceAccount",
		URI:       fmt.Sprintf("//iam.googleapis.com/projects/UNKNOWN/serviceAccounts/%s", email),
		ParentURI: "",
		Name:      email,
		Properties: map[string]string{
			"email":     email,
			"external":  "true",
			"projectId": projectID,
		},
	}
}

func (hp *HierarchyProcessor) createDeletedServiceAccountStub(email string, originalMember string) *gcptypes.Resource {
	projectID := gcloudcollectors.ExtractProjectIDFromEmail(email)

	return &gcptypes.Resource{
		AssetType: "iam.googleapis.com/ServiceAccount",
		URI:       originalMember,
		ParentURI: "",
		Name:      fmt.Sprintf("(deleted) %s", email),
		Properties: map[string]string{
			"email":         email,
			"deleted":       "true",
			"originalEmail": originalMember,
			"projectId":     projectID,
		},
	}
}

func (hp *HierarchyProcessor) createWorkloadIdentityPrincipal(principalURI string) *gcptypes.Resource {
	parts := strings.Split(principalURI, "/")

	var projectID, location, poolName, subject string
	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			projectID = parts[i+1]
		}
		if part == "locations" && i+1 < len(parts) {
			location = parts[i+1]
		}
		if part == "workloadIdentityPools" && i+1 < len(parts) {
			poolName = parts[i+1]
		}
		if part == "subject" && i+1 < len(parts) {
			subject = strings.Join(parts[i+1:], "/")
			break
		}
	}

	parentURI := ""
	if projectNumber, ok := hp.projectIDToNumber[projectID]; ok {
		parentURI = fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", projectNumber)
	}

	return &gcptypes.Resource{
		AssetType: "iam.googleapis.com/WorkloadIdentity",
		URI:       principalURI,
		ParentURI: parentURI,
		Name:      subject,
		Properties: map[string]string{
			"projectId":       projectID,
			"location":        location,
			"poolName":        poolName,
			"workloadSubject": subject,
			"principalUri":    principalURI,
		},
	}
}

func (hp *HierarchyProcessor) createWorkforceIdentityPrincipal(principalURI string) *gcptypes.Resource {
	parts := strings.Split(principalURI, "/")

	var location, poolName, subject string
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			location = parts[i+1]
		}
		if part == "workforcePools" && i+1 < len(parts) {
			poolName = parts[i+1]
		}
		if part == "subject" && i+1 < len(parts) {
			subject = strings.Join(parts[i+1:], "/")
			break
		}
	}

	return &gcptypes.Resource{
		AssetType: "iam.googleapis.com/WorkforceIdentity",
		URI:       principalURI,
		ParentURI: "",
		Name:      subject,
		Properties: map[string]string{
			"location":         location,
			"poolName":         poolName,
			"workforceSubject": subject,
			"principalUri":     principalURI,
		},
	}
}

func (hp *HierarchyProcessor) createWorkloadIdentityFromKSA(ksaEmail string, isDeleted bool) []*gcptypes.Resource {
	resource := &gcptypes.Resource{
		AssetType: "iam.googleapis.com/WorkloadIdentity",
		URI:       fmt.Sprintf("serviceAccount:%s", ksaEmail),
		ParentURI: "",
		Name:      ksaEmail,
		Properties: map[string]string{
			"ksaEmail": ksaEmail,
		},
	}

	if isDeleted {
		resource.Properties["deleted"] = "true"
		resource.Name = "(deleted) " + resource.Name
	}

	return []*gcptypes.Resource{resource}
}

func (hp *HierarchyProcessor) expandProjectRoleConvenience(member string) []*gcptypes.Resource {
	var roleType, projectID string
	switch {
	case strings.HasPrefix(member, "projectOwner:"):
		roleType = "owner"
		projectID = strings.TrimPrefix(member, "projectOwner:")
	case strings.HasPrefix(member, "projectEditor:"):
		roleType = "editor"
		projectID = strings.TrimPrefix(member, "projectEditor:")
	case strings.HasPrefix(member, "projectViewer:"):
		roleType = "viewer"
		projectID = strings.TrimPrefix(member, "projectViewer:")
	default:
		return []*gcptypes.Resource{}
	}

	projectNumber, ok := hp.projectIDToNumber[projectID]
	if !ok {
		projectNumber = projectID
	}

	if projectRoles, ok := hp.projectRoleMembers[projectNumber]; ok {
		if memberStrings, ok := projectRoles[roleType]; ok && len(memberStrings) > 0 {
			principals := make([]*gcptypes.Resource, 0)
			for _, memberStr := range memberStrings {
				resolved := hp.resolvePrincipalFromMember(memberStr)
				principals = append(principals, resolved...)
			}
			return principals
		}
	}

	return []*gcptypes.Resource{}
}

func extractProjectIDFromURI(uri string) string {
	parts := strings.Split(uri, "/")
	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return uri
}

func IsGoogleManagedServiceAccount(email string) (isManaged bool, projectNumber string) {
	if email == "" {
		return false, ""
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false, ""
	}

	username := parts[0]
	domain := parts[1]

	if domain == "cloudbuild.gserviceaccount.com" {
		if isNumeric(username) {
			return true, username
		}
	}

	if domain == "cloudservices.gserviceaccount.com" {
		if isNumeric(username) {
			return true, username
		}
	}

	if strings.HasSuffix(domain, ".iam.gserviceaccount.com") && strings.HasPrefix(username, "service-") {
		projectNum := strings.TrimPrefix(username, "service-")
		if isNumeric(projectNum) {
			return true, projectNum
		}
	}

	return false, ""
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
