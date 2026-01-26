package gcloudiam

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

// OfflineData represents all collected data for serialization
type OfflineData struct {
	Metadata  CollectionMetadata   `json:"metadata"`
	Hierarchy *gcptypes.Hierarchy  `json:"hierarchy"`
	Roles     []*gcptypes.Role     `json:"roles"`
	PAB       PABData              `json:"pab"`
	Resources []*gcptypes.Resource `json:"resources"`
}

type CollectionMetadata struct {
	Timestamp             time.Time `json:"timestamp"`
	OrgID                 string    `json:"org_id"`
	CollectedPABs         bool      `json:"collected_pabs"`
	CollectedDenyPolicies bool      `json:"collected_deny_policies"`
	AssetTypes            []string  `json:"asset_types,omitempty"`
}

type PABData struct {
	Policies []gcptypes.PABPolicy  `json:"policies"`
	Bindings []gcptypes.PABBinding `json:"bindings"`
}

// SaveToDirectory saves all collected data to JSON files
func (hp *HierarchyProcessor) SaveToDirectory(orgID string, assetTypes []string) error {
	if err := os.MkdirAll(hp.dataDirectory, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Collect PAB data
	var pabPolicies []gcptypes.PABPolicy
	var pabBindings []gcptypes.PABBinding
	if hp.pabEvaluator != nil {
		pabPolicies = hp.pabEvaluator.pabPolicies
		pabBindings = hp.pabEvaluator.pabBindings
	}

	// Collect all roles from RoleExpander
	roles := hp.extractRolesFromExpander()

	data := OfflineData{
		Metadata: CollectionMetadata{
			Timestamp:             time.Now(),
			OrgID:                 orgID,
			CollectedPABs:         hp.collectPABs,
			CollectedDenyPolicies: hp.collectDenyPolicies,
			AssetTypes:            assetTypes,
		},
		Hierarchy: hp.hierarchy,
		Roles:     roles,
		PAB: PABData{
			Policies: pabPolicies,
			Bindings: pabBindings,
		},
		Resources: hp.allResources,
	}

	// Save metadata
	if err := hp.saveJSON("metadata.json", data.Metadata); err != nil {
		return err
	}

	// Save hierarchy
	if err := hp.saveJSON("hierarchy.json", data.Hierarchy); err != nil {
		return err
	}

	// Save roles
	if err := hp.saveJSON("roles.json", data.Roles); err != nil {
		return err
	}

	// Save PAB data
	if err := hp.saveJSON("pab.json", data.PAB); err != nil {
		return err
	}

	// Save resources
	if err := hp.saveJSON("resources.json", data.Resources); err != nil {
		return err
	}

	fmt.Printf("Saved offline data to %s\n", hp.dataDirectory)
	return nil
}

// LoadFromDirectory loads all data from JSON files
func (hp *HierarchyProcessor) LoadFromDirectory() error {
	var metadata CollectionMetadata
	if err := hp.loadJSON("metadata.json", &metadata); err != nil {
		return err
	}
	fmt.Printf("Loading data collected at %s for org %s\n", metadata.Timestamp, metadata.OrgID)

	// Load hierarchy
	hp.hierarchy = &gcptypes.Hierarchy{}
	if err := hp.loadJSON("hierarchy.json", hp.hierarchy); err != nil {
		return err
	}

	// Load and rebuild RoleExpander
	var roles []*gcptypes.Role
	if err := hp.loadJSON("roles.json", &roles); err != nil {
		return err
	}
	hp.roleExpander = NewRoleExpander()
	hp.roleExpander.AddRoles(roles)

	// Load and rebuild AncestryBuilder
	hp.ancestryBuilder = NewAncestryBuilder()
	hp.rebuildAncestryFromHierarchy()

	// Load and rebuild PABEvaluator
	var pabData PABData
	if err := hp.loadJSON("pab.json", &pabData); err != nil {
		return err
	}
	hp.normalizer = NewMemberNormalizer()
	hp.pabEvaluator = NewPABEvaluator(pabData.Policies, pabData.Bindings, hp.normalizer)
	hp.pabEvaluator.BuildPABMasks()

	// Load resources
	if err := hp.loadJSON("resources.json", &hp.allResources); err != nil {
		return err
	}

	// Populate resource lookup maps
	for _, resource := range hp.allResources {
		hp.resourcesByURI[resource.URI] = resource
		hp.resourcesByType[resource.AssetType] = append(hp.resourcesByType[resource.AssetType], resource)
	}

	fmt.Printf("Loaded %d roles, %d resources from offline data\n", len(roles), len(hp.allResources))
	return nil
}

func (hp *HierarchyProcessor) saveJSON(filename string, data any) error {
	filepath := filepath.Join(hp.dataDirectory, filename)
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", filename, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode %s: %w", filename, err)
	}

	return nil
}

func (hp *HierarchyProcessor) loadJSON(filename string, target any) error {
	filepath := filepath.Join(hp.dataDirectory, filename)
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filename, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("failed to decode %s: %w", filename, err)
	}

	return nil
}

func (hp *HierarchyProcessor) extractRolesFromExpander() []*gcptypes.Role {
	roles := make([]*gcptypes.Role, 0, len(hp.roleExpander.rolePermsByName))
	for roleName, permSet := range hp.roleExpander.rolePermsByName {
		perms := make([]gcptypes.Permission, 0, len(permSet))
		for perm := range permSet {
			perms = append(perms, perm)
		}
		roles = append(roles, &gcptypes.Role{
			Name:                roleName,
			IncludedPermissions: perms,
		})
	}
	return roles
}

func (hp *HierarchyProcessor) rebuildAncestryFromHierarchy() {
	for _, org := range hp.hierarchy.Organizations {
		hp.ancestryBuilder.AddOrganization(org)
		hp.rebuildAncestryForFolders(org.Folders)
		hp.rebuildAncestryForProjects(org.Projects)
	}
}

func (hp *HierarchyProcessor) rebuildAncestryForFolders(folders []*gcptypes.Folder) {
	for _, folder := range folders {
		hp.ancestryBuilder.AddFolder(folder)
		hp.rebuildAncestryForFolders(folder.Folders)
		hp.rebuildAncestryForProjects(folder.Projects)
	}
}

func (hp *HierarchyProcessor) rebuildAncestryForProjects(projects []*gcptypes.Project) {
	for _, project := range projects {
		hp.ancestryBuilder.AddProject(project)
	}
}
