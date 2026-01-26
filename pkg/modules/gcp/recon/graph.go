package recon

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	gcloudiam "github.com/praetorian-inc/nebula/pkg/gcp/grapher"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

func init() {
	registry.Register("gcp", "recon", GcpGraph.Metadata().Properties()["id"].(string), *GcpGraph)
}

var GcpGraph = chain.NewModule(
	cfg.NewMetadata(
		"GCP Graph",
		"Build GCP IAM graph using the hierarchy processor.",
	).WithProperties(map[string]any{
		"id":          "graph",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}),
).WithLinks(
	NewGcpGrapherLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithAutoRun()

// GcpGrapherLink is an inline link that calls the GCP grapher
type GcpGrapherLink struct {
	*chain.Base
	orgID               string
	neo4jURI            string
	neo4jUser           string
	neo4jPass           string
	collectPABs         bool
	collectDenyPolicies bool
	mode                string
	dataDirectory       string
}

func NewGcpGrapherLink(configs ...cfg.Config) chain.Link {
	g := &GcpGrapherLink{
		// Hardcoded values
		orgID:               "1053837431852",
		neo4jURI:            "neo4j://localhost:7687",
		neo4jUser:           "neo4j",
		neo4jPass:           "Tanishq16@",
		collectPABs:         true,
		collectDenyPolicies: true,
		mode:                "online",
		dataDirectory:       "./gcp-grapher-data",
	}
	g.Base = chain.NewBase(g, configs...)
	return g
}

func (g *GcpGrapherLink) Initialize() error {
	if err := g.Base.Initialize(); err != nil {
		return err
	}
	return nil
}

func (g *GcpGrapherLink) Process(input string) error {
	ctx := context.Background()

	// Prompt user for configuration options
	if err := g.promptUserOptions(); err != nil {
		return fmt.Errorf("failed to get user options: %w", err)
	}

	// Parse mode
	var opMode gcloudiam.OperationMode
	switch g.mode {
	case "offline-collect":
		opMode = gcloudiam.ModeOfflineCollect
	case "offline-analyze":
		opMode = gcloudiam.ModeOfflineAnalyze
	default:
		opMode = gcloudiam.ModeOnline
	}

	// Create hierarchy processor with new parameters
	hp, err := gcloudiam.NewHierarchyProcessor(
		ctx,
		g.collectPABs,
		g.collectDenyPolicies,
		opMode,
		g.dataDirectory,
	)
	if err != nil {
		return fmt.Errorf("failed to create hierarchy processor: %w", err)
	}
	defer hp.Close()

	// Process based on mode
	fmt.Printf("Processing GCP organization: %s (mode: %s)\n", g.orgID, g.mode)
	if err := hp.Process(g.orgID, []string{}); err != nil {
		return fmt.Errorf("failed to process hierarchy: %w", err)
	}

	// Only write to Neo4j in online and offline-analyze modes
	if opMode == gcloudiam.ModeOnline || opMode == gcloudiam.ModeOfflineAnalyze {
		// Connect to Neo4j
		fmt.Println("Connecting to Neo4j...")
		driver, err := neo4j.NewDriverWithContext(g.neo4jURI, neo4j.BasicAuth(g.neo4jUser, g.neo4jPass, ""))
		if err != nil {
			return fmt.Errorf("failed to create Neo4j driver: %w", err)
		}
		defer driver.Close(ctx)

		// Verify connectivity
		if err := driver.VerifyConnectivity(ctx); err != nil {
			return fmt.Errorf("failed to verify Neo4j connectivity: %w", err)
		}
		fmt.Println("Connected to Neo4j successfully")

		// Extract data from hierarchy processor
		hierarchy := hp.GetHierarchy()
		allResources := hp.GetAllResources()
		tuples := hp.GetTuples()
		containsEdges := hp.GetContainsEdges()

		fmt.Printf("Extracted %d resources from hierarchy\n", len(allResources))
		fmt.Printf("Extracted %d permission tuples from hierarchy\n", len(tuples))
		fmt.Printf("Extracted %d CONTAINS edges from hierarchy\n", len(containsEdges))

		// Write to Neo4j
		fmt.Println("Writing data to Neo4j...")
		if err := g.writeToNeo4j(ctx, driver, hierarchy, allResources, tuples, containsEdges); err != nil {
			return fmt.Errorf("failed to write to Neo4j: %w", err)
		}
	}

	fmt.Println("GCP graph processing completed successfully")
	return nil
}

func (g *GcpGrapherLink) promptUserOptions() error {
	reader := bufio.NewReader(os.Stdin)

	// Prompt for operation mode
	fmt.Println("\nSelect operation mode:")
	fmt.Println("1) online - Collect and analyze in one pass (default)")
	fmt.Println("2) offline-collect - Collect data and save to files")
	fmt.Println("3) offline-analyze - Load data from files and analyze")
	fmt.Print("Enter choice (1-3) [1]: ")
	modeChoice, _ := reader.ReadString('\n')
	modeChoice = strings.TrimSpace(modeChoice)
	if modeChoice == "" {
		modeChoice = "1"
	}
	switch modeChoice {
	case "2":
		g.mode = "offline-collect"
	case "3":
		g.mode = "offline-analyze"
	default:
		g.mode = "online"
	}

	// Only prompt for collection options if not in offline-analyze mode
	if g.mode != "offline-analyze" {
		// Prompt for PAB collection
		fmt.Print("\nCollect PAB (Principal Access Boundary) policies? (y/n) [y]: ")
		pabChoice, _ := reader.ReadString('\n')
		pabChoice = strings.TrimSpace(strings.ToLower(pabChoice))
		g.collectPABs = pabChoice == "" || pabChoice == "y" || pabChoice == "yes"

		// Prompt for Deny policy collection
		fmt.Print("Collect Deny policies? (y/n) [y]: ")
		denyChoice, _ := reader.ReadString('\n')
		denyChoice = strings.TrimSpace(strings.ToLower(denyChoice))
		g.collectDenyPolicies = denyChoice == "" || denyChoice == "y" || denyChoice == "yes"
	}

	fmt.Println()
	return nil
}

func (g *GcpGrapherLink) writeToNeo4j(ctx context.Context, driver neo4j.DriverWithContext, hierarchy *gcptypes.Hierarchy, allResources []*gcptypes.Resource, tuples []*gcptypes.PermissionTuple, containsEdges []*gcptypes.ContainsEdge) error {
	session := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close(ctx)

	fmt.Println("Clearing existing GCP data from Neo4j...")
	if _, err := session.Run(ctx, "MATCH (n:GCPOrganization)-[r*0..]->(m) DETACH DELETE n, m", nil); err != nil {
		return fmt.Errorf("failed to clear database: %w", err)
	}

	fmt.Println("Inserting hierarchy...")
	if err := g.insertHierarchy(ctx, session, hierarchy); err != nil {
		return fmt.Errorf("failed to insert hierarchy: %w", err)
	}

	fmt.Printf("Inserting %d resource nodes...\n", len(allResources))
	if err := g.insertAllResources(ctx, session, allResources); err != nil {
		return fmt.Errorf("failed to insert resources: %w", err)
	}

	fmt.Printf("Inserting %d CONTAINS edges...\n", len(containsEdges))
	if err := g.insertContainsEdges(ctx, session, containsEdges); err != nil {
		return fmt.Errorf("failed to insert CONTAINS edges: %w", err)
	}

	fmt.Printf("Inserting %d permission tuples...\n", len(tuples))
	if err := g.insertPermissionTuples(ctx, session, tuples); err != nil {
		return fmt.Errorf("failed to insert permission tuples: %w", err)
	}

	fmt.Println("Data successfully written to Neo4j")
	return nil
}

func (g *GcpGrapherLink) insertHierarchy(ctx context.Context, session neo4j.SessionWithContext, hierarchy *gcptypes.Hierarchy) error {
	for _, org := range hierarchy.Organizations {
		// Create organization node
		_, err := session.Run(ctx, `
			MERGE (o:GCPResource:GCPOrganization {uri: $uri})
			SET o.name = $name,
				o.displayName = $displayName,
				o.orgNumber = $orgNumber,
				o.createTime = $createTime,
				o.assetType = $assetType
		`, map[string]any{
			"uri":         org.URI,
			"name":        org.DisplayName,
			"displayName": org.DisplayName,
			"orgNumber":   org.OrganizationNumber,
			"createTime":  org.CreateTime,
			"assetType":   "cloudresourcemanager.googleapis.com/Organization",
		})
		if err != nil {
			return fmt.Errorf("failed to create organization: %w", err)
		}

		// Insert folders recursively
		if err := g.insertFolders(ctx, session, org.URI, org.Folders); err != nil {
			return err
		}

		// Insert projects
		if err := g.insertProjects(ctx, session, org.URI, org.Projects); err != nil {
			return err
		}
	}
	return nil
}

func (g *GcpGrapherLink) insertFolders(ctx context.Context, session neo4j.SessionWithContext, parentURI string, folders []*gcptypes.Folder) error {
	for _, folder := range folders {
		// Create folder node
		_, err := session.Run(ctx, `
			MERGE (f:GCPResource:GCPFolder {uri: $uri})
			SET f.name = $name,
				f.displayName = $displayName,
				f.folderNumber = $folderNumber,
				f.createTime = $createTime,
				f.assetType = $assetType,
				f.parentUri = $parentUri
		`, map[string]any{
			"uri":          folder.URI,
			"name":         folder.DisplayName,
			"displayName":  folder.DisplayName,
			"folderNumber": folder.FolderNumber,
			"createTime":   folder.CreateTime,
			"assetType":    "cloudresourcemanager.googleapis.com/Folder",
			"parentUri":    folder.ParentURI,
		})
		if err != nil {
			return fmt.Errorf("failed to create folder: %w", err)
		}

		// Create relationship to parent
		_, err = session.Run(ctx, `
			MATCH (parent {uri: $parentURI})
			MATCH (child:GCPFolder {uri: $childURI})
			MERGE (parent)-[:CONTAINS]->(child)
		`, map[string]any{
			"parentURI": parentURI,
			"childURI":  folder.URI,
		})
		if err != nil {
			return fmt.Errorf("failed to create folder relationship: %w", err)
		}

		// Recursively insert subfolders
		if err := g.insertFolders(ctx, session, folder.URI, folder.Folders); err != nil {
			return err
		}

		// Insert projects in this folder
		if err := g.insertProjects(ctx, session, folder.URI, folder.Projects); err != nil {
			return err
		}
	}
	return nil
}

func (g *GcpGrapherLink) insertProjects(ctx context.Context, session neo4j.SessionWithContext, parentURI string, projects []*gcptypes.Project) error {
	for _, project := range projects {
		// Create project node
		_, err := session.Run(ctx, `
			MERGE (p:GCPResource:GCPProject {uri: $uri})
			SET p.name = $name,
				p.displayName = $displayName,
				p.projectNumber = $projectNumber,
				p.projectId = $projectId,
				p.createTime = $createTime,
				p.assetType = $assetType,
				p.parentUri = $parentUri
		`, map[string]any{
			"uri":           project.URI,
			"name":          project.DisplayName,
			"displayName":   project.DisplayName,
			"projectNumber": project.ProjectNumber,
			"projectId":     project.ProjectID,
			"createTime":    project.CreateTime,
			"assetType":     "cloudresourcemanager.googleapis.com/Project",
			"parentUri":     project.ParentURI,
		})
		if err != nil {
			return fmt.Errorf("failed to create project: %w", err)
		}

		// Create relationship to parent
		_, err = session.Run(ctx, `
			MATCH (parent {uri: $parentURI})
			MATCH (child:GCPProject {uri: $childURI})
			MERGE (parent)-[:CONTAINS]->(child)
		`, map[string]any{
			"parentURI": parentURI,
			"childURI":  project.URI,
		})
		if err != nil {
			return fmt.Errorf("failed to create project relationship: %w", err)
		}
	}
	return nil
}

func (g *GcpGrapherLink) insertAllResources(ctx context.Context, session neo4j.SessionWithContext, resources []*gcptypes.Resource) error {
	resourcesByLabels := make(map[string][]map[string]any)

	for _, resource := range resources {
		labels := getResourceLabels(resource.AssetType)
		if isPrincipal(resource.AssetType) {
			labels = getPrincipalLabels(resource.AssetType)
		}
		labelKey := labelsKey(labels)

		resourceProps := map[string]any{
			"uri":       resource.URI,
			"assetType": resource.AssetType,
			"name":      resource.Name,
			"parentUri": resource.ParentURI,
			"location":  resource.Location,
		}
		for k, v := range resource.Properties {
			resourceProps[k] = v
		}
		resourcesByLabels[labelKey] = append(resourcesByLabels[labelKey], resourceProps)
	}

	batchSize := 1000
	for labelKey, resources := range resourcesByLabels {
		labels := strings.Split(labelKey, "|")
		labelString := formatLabels(labels)

		totalBatches := (len(resources) + batchSize - 1) / batchSize
		for batchNum := 0; batchNum < totalBatches; batchNum++ {
			start := batchNum * batchSize
			end := start + batchSize
			if end > len(resources) {
				end = len(resources)
			}
			batch := resources[start:end]

			query := fmt.Sprintf(`
				UNWIND $batch AS row
				MERGE (r%s {uri: row.uri})
				SET r += row
			`, labelString)
			_, err := session.Run(ctx, query, map[string]any{"batch": batch})
			if err != nil {
				return fmt.Errorf("failed to batch insert resources with labels %s: %w", labelKey, err)
			}
		}
	}

	return nil
}

func isPrincipal(assetType string) bool {
	principalTypes := []string{
		"iam.googleapis.com/ServiceAccount",
		"iam.googleapis.com/User",
		"iam.googleapis.com/Group",
		"iam.googleapis.com/Domain",
		"iam.googleapis.com/AllUsers",
		"iam.googleapis.com/AllAuthenticatedUsers",
		"iam.googleapis.com/WorkloadIdentity",
		"iam.googleapis.com/WorkforceIdentity",
		"iam.googleapis.com/WorkloadIdentityPoolPrincipalSet",
	}
	for _, pt := range principalTypes {
		if assetType == pt {
			return true
		}
	}
	return false
}

func (g *GcpGrapherLink) insertPermissionTuples(ctx context.Context, session neo4j.SessionWithContext, tuples []*gcptypes.PermissionTuple) error {
	batchSize := 1000
	totalBatches := (len(tuples) + batchSize - 1) / batchSize

	for batchNum := 0; batchNum < totalBatches; batchNum++ {
		start := batchNum * batchSize
		end := start + batchSize
		if end > len(tuples) {
			end = len(tuples)
		}
		batch := tuples[start:end]

		fmt.Printf("Processing batch %d/%d (%d-%d of %d tuples)...\n",
			batchNum+1, totalBatches, start+1, end, len(tuples))

		if err := g.insertPermissionBatch(ctx, session, batch); err != nil {
			return fmt.Errorf("failed to insert batch %d: %w", batchNum+1, err)
		}
	}
	return nil
}

func (g *GcpGrapherLink) insertPermissionBatch(ctx context.Context, session neo4j.SessionWithContext, batch []*gcptypes.PermissionTuple) error {
	// Group principals by their label combinations
	principalsByLabels := make(map[string][]map[string]any)
	resourcesByLabels := make(map[string][]map[string]any)
	relationshipBatch := make([]map[string]any, 0, len(batch))

	for _, tuple := range batch {
		principalLabels := getPrincipalLabels(tuple.Source.AssetType)
		principalKey := labelsKey(principalLabels)
		principalProps := map[string]any{
			"uri":       tuple.Source.URI,
			"assetType": tuple.Source.AssetType,
			"name":      tuple.Source.Name,
			"parentUri": tuple.Source.ParentURI,
			"location":  tuple.Source.Location,
		}
		for k, v := range tuple.Source.Properties {
			principalProps[k] = v
		}
		principalsByLabels[principalKey] = append(principalsByLabels[principalKey], principalProps)

		resourceLabels := getResourceLabels(tuple.Target.AssetType)
		resourceKey := labelsKey(resourceLabels)
		resourceProps := map[string]any{
			"uri":       tuple.Target.URI,
			"assetType": tuple.Target.AssetType,
			"name":      tuple.Target.Name,
			"parentUri": tuple.Target.ParentURI,
			"location":  tuple.Target.Location,
		}
		for k, v := range tuple.Target.Properties {
			resourceProps[k] = v
		}
		resourcesByLabels[resourceKey] = append(resourcesByLabels[resourceKey], resourceProps)

		relationshipBatch = append(relationshipBatch, map[string]any{
			"sourceUri":     tuple.Source.URI,
			"targetUri":     tuple.Target.URI,
			"permission":    string(tuple.Permission),
			"isConditional": tuple.Provenance.IsConditional,
			"viaRoles":      tuple.Provenance.ViaRoles,
			"viaContainers": tuple.Provenance.ViaContainers,
			"isDeny":        tuple.IsDeny,
		})
	}

	// Batch insert principals grouped by labels
	for labelKey, principals := range principalsByLabels {
		labels := strings.Split(labelKey, "|")
		labelString := formatLabels(labels)
		query := fmt.Sprintf(`
			UNWIND $batch AS row
			MERGE (p%s {uri: row.uri})
			SET p += row
		`, labelString)
		_, err := session.Run(ctx, query, map[string]any{"batch": principals})
		if err != nil {
			return fmt.Errorf("failed to batch insert principals with labels %s: %w", labelKey, err)
		}
	}

	// Batch insert resources grouped by labels
	for labelKey, resources := range resourcesByLabels {
		labels := strings.Split(labelKey, "|")
		labelString := formatLabels(labels)
		query := fmt.Sprintf(`
			UNWIND $batch AS row
			MERGE (r%s {uri: row.uri})
			SET r += row
		`, labelString)
		_, err := session.Run(ctx, query, map[string]any{"batch": resources})
		if err != nil {
			return fmt.Errorf("failed to batch insert resources with labels %s: %w", labelKey, err)
		}
	}

	// Batch insert relationships
	_, err := session.Run(ctx, `
		UNWIND $batch AS row
		MATCH (source:GCPResource {uri: row.sourceUri})
		MATCH (target:GCPResource {uri: row.targetUri})
		MERGE (source)-[rel:HAS_PERMISSION {permission: row.permission}]->(target)
		SET rel.isConditional = row.isConditional,
			rel.viaRoles = row.viaRoles,
			rel.viaContainers = row.viaContainers,
			rel.isDeny = row.isDeny
	`, map[string]any{"batch": relationshipBatch})
	if err != nil {
		return fmt.Errorf("failed to batch insert relationships: %w", err)
	}

	return nil
}

func (g *GcpGrapherLink) insertContainsEdges(ctx context.Context, session neo4j.SessionWithContext, edges []*gcptypes.ContainsEdge) error {
	batchSize := 1000
	totalBatches := (len(edges) + batchSize - 1) / batchSize

	for batchNum := 0; batchNum < totalBatches; batchNum++ {
		start := batchNum * batchSize
		end := start + batchSize
		if end > len(edges) {
			end = len(edges)
		}
		batch := edges[start:end]

		fmt.Printf("Processing CONTAINS edge batch %d/%d (%d-%d of %d edges)...\n",
			batchNum+1, totalBatches, start+1, end, len(edges))

		edgeBatch := make([]map[string]any, 0, len(batch))
		for _, edge := range batch {
			edgeBatch = append(edgeBatch, map[string]any{
				"parentUri": edge.Parent.URI,
				"childUri":  edge.Child.URI,
			})
		}

		_, err := session.Run(ctx, `
			UNWIND $batch AS row
			MATCH (parent:GCPResource {uri: row.parentUri})
			MATCH (child:GCPResource {uri: row.childUri})
			MERGE (parent)-[:CONTAINS]->(child)
		`, map[string]any{"batch": edgeBatch})
		if err != nil {
			return fmt.Errorf("failed to insert CONTAINS edges batch %d: %w", batchNum+1, err)
		}
	}
	return nil
}

func (g *GcpGrapherLink) getResourceID(r *gcptypes.Resource) string {
	return r.URI
}

func getResourceLabels(assetType string) []string {
	labels := []string{"GCPResource"}

	switch assetType {
	case "cloudresourcemanager.googleapis.com/Organization":
		labels = append(labels, "GCPOrganization")
	case "cloudresourcemanager.googleapis.com/Folder":
		labels = append(labels, "GCPFolder")
	case "cloudresourcemanager.googleapis.com/Project":
		labels = append(labels, "GCPProject")
	case "iam.googleapis.com/ServiceAccount":
		labels = append(labels, "GCPServiceAccount")
	case "run.googleapis.com/Service":
		labels = append(labels, "GCPCloudRun")
	case "cloudfunctions.googleapis.com/CloudFunction":
		labels = append(labels, "GCPCloudFunction")
	case "compute.googleapis.com/Instance":
		labels = append(labels, "GCPComputeInstance")
	case "storage.googleapis.com/Bucket":
		labels = append(labels, "GCPStorageBucket")
	case "secretmanager.googleapis.com/Secret":
		labels = append(labels, "GCPSecret")
	case "deploymentmanager.googleapis.com/Deployment":
		labels = append(labels, "GCPDeployment")
	}

	return labels
}

func getPrincipalLabels(assetType string) []string {
	labels := []string{"GCPResource", "GCPPrincipal"}

	switch assetType {
	case "iam.googleapis.com/ServiceAccount":
		labels = append(labels, "GCPServiceAccount")
	case "iam.googleapis.com/User":
		labels = append(labels, "GCPUser")
	case "iam.googleapis.com/Group":
		labels = append(labels, "GCPGroup")
	case "iam.googleapis.com/Domain":
		labels = append(labels, "GCPDomain")
	case "iam.googleapis.com/AllUsers":
		labels = append(labels, "GCPAllUsers")
	case "iam.googleapis.com/AllAuthenticatedUsers":
		labels = append(labels, "GCPAllAuthenticatedUsers")
	case "iam.googleapis.com/WorkloadIdentity":
		labels = append(labels, "GCPWorkloadIdentity")
	case "iam.googleapis.com/WorkforceIdentity":
		labels = append(labels, "GCPWorkforceIdentity")
	case "iam.googleapis.com/WorkloadIdentityPoolPrincipalSet":
		labels = append(labels, "GCPWorkloadIdentityPoolPrincipalSet")
	}

	return labels
}

func formatLabels(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	return ":" + strings.Join(labels, ":")
}

func labelsKey(labels []string) string {
	return strings.Join(labels, "|")
}
