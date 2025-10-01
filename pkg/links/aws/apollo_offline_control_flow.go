package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/konstellation/pkg/graph"
	"github.com/praetorian-inc/konstellation/pkg/graph/adapters"
	iam "github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type AwsApolloOfflineControlFlow struct {
	*AwsApolloOfflineBaseLink
	pd  *iam.PolicyData
	db  graph.GraphDatabase
	ctx context.Context
}

func NewAwsApolloOfflineControlFlow(configs ...cfg.Config) chain.Link {
	a := &AwsApolloOfflineControlFlow{}
	a.AwsApolloOfflineBaseLink = NewAwsApolloOfflineBaseLink(a, configs...)
	return a
}

func (a *AwsApolloOfflineControlFlow) Params() []cfg.Param {
	params := []cfg.Param{}
	params = append(params, options.AwsApolloOfflineOptions()...)
	params = append(params, options.Neo4jOptions()...)
	return params
}

func (a *AwsApolloOfflineControlFlow) Initialize() error {
	if err := a.AwsApolloOfflineBaseLink.Initialize(); err != nil {
		return err
	}

	// Initialize PolicyData with empty resources slice
	resources := make([]types.EnrichedResourceDescription, 0)
	a.pd = &iam.PolicyData{
		Resources: &resources,
	}

	// Initialize Neo4j connection
	graphConfig := &graph.Config{
		URI:      a.Args()[options.Neo4jURI().Name()].(string),
		Username: a.Args()[options.Neo4jUsername().Name()].(string),
		Password: a.Args()[options.Neo4jPassword().Name()].(string),
	}

	var err error
	a.db, err = adapters.NewNeo4jDatabase(graphConfig)
	if err != nil {
		return err
	}

	a.ctx = context.Background()
	err = a.db.VerifyConnectivity(a.ctx)
	if err != nil {
		return err
	}

	return nil
}

func (a *AwsApolloOfflineControlFlow) Process(input any) error {
	// Load all data from files
	if err := a.loadDataFromFiles(); err != nil {
		return err
	}

	// Validate that we have the required data
	if a.pd.Gaad == nil {
		return fmt.Errorf("GAAD data is required but not loaded")
	}

	// Perform the same analysis as online Apollo
	analyzer := iam.NewGaadAnalyzer(a.pd)
	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return err
	}

	// Create graph relationships (reuse existing logic)
	a.graph(summary)

	// Create relationships between resources and their IAM roles
	err = a.mapResourceRoleRelationships()
	if err != nil {
		a.Logger.Error("Failed to create assume role relationships: " + err.Error())
	}

	// Send the analysis summary as output
	a.Send(outputters.NewNamedOutputData(summary, "apollo-offline-analysis"))
	a.Logger.Info("Apollo offline analysis completed successfully")

	return nil
}

func (a *AwsApolloOfflineControlFlow) loadDataFromFiles() error {
	// Load organization policies
	if err := a.loadOrgPoliciesFromFile(); err != nil {
		return err
	}

	// Load GAAD data
	if err := a.loadGaadFromFile(); err != nil {
		return err
	}

	// Load resource policies
	if err := a.loadResourcePoliciesFromFile(); err != nil {
		return err
	}

	return nil
}

func (a *AwsApolloOfflineControlFlow) loadOrgPoliciesFromFile() error {
	orgPoliciesFile, err := cfg.As[string](a.Arg("org-policies"))
	if err != nil {
		slog.Warn("No organization policies file provided, using default policies")
		a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	if orgPoliciesFile == "" {
		slog.Warn("Empty organization policies file path, using default policies")
		a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	fileBytes, err := os.ReadFile(orgPoliciesFile)
	if err != nil {
		return fmt.Errorf("failed to read org policies file '%s': %w", orgPoliciesFile, err)
	}

	// Try to unmarshal as array first (matching online module output)
	var orgPoliciesArray []*orgpolicies.OrgPolicies
	if err := json.Unmarshal(fileBytes, &orgPoliciesArray); err == nil {
		if len(orgPoliciesArray) > 0 {
			a.pd.OrgPolicies = orgPoliciesArray[0]
		} else {
			slog.Warn("Empty organization policies array, using default policies")
			a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		}
	} else {
		// Fallback to single object format
		var orgPolicies *orgpolicies.OrgPolicies
		if err := json.Unmarshal(fileBytes, &orgPolicies); err != nil {
			return fmt.Errorf("failed to unmarshal org policies from '%s': %w", orgPoliciesFile, err)
		}
		a.pd.OrgPolicies = orgPolicies
	}

	slog.Info("Successfully loaded organization policies", "file", orgPoliciesFile)
	return nil
}

func (a *AwsApolloOfflineControlFlow) loadGaadFromFile() error {
	gaadFile, err := cfg.As[string](a.Arg("gaad-file"))
	if err != nil {
		return fmt.Errorf("gaad-file parameter is required for offline Apollo analysis: %w", err)
	}

	if gaadFile == "" {
		return fmt.Errorf("gaad-file parameter cannot be empty")
	}

	fileBytes, err := os.ReadFile(gaadFile)
	if err != nil {
		return fmt.Errorf("failed to read GAAD file '%s': %w", gaadFile, err)
	}

	// Try to unmarshal as array first (matching account-auth-details module output)
	var gaadArray []types.Gaad
	if err := json.Unmarshal(fileBytes, &gaadArray); err == nil {
		if len(gaadArray) > 0 {
			a.pd.Gaad = &gaadArray[0]
		} else {
			return fmt.Errorf("GAAD file '%s' contains empty array", gaadFile)
		}
	} else {
		// Fallback to single object format
		var gaad types.Gaad
		if err := json.Unmarshal(fileBytes, &gaad); err != nil {
			return fmt.Errorf("failed to unmarshal GAAD data from '%s': %w", gaadFile, err)
		}
		a.pd.Gaad = &gaad
	}

	slog.Info("Successfully loaded GAAD data", "file", gaadFile)
	return nil
}

func (a *AwsApolloOfflineControlFlow) loadResourcePoliciesFromFile() error {
	resourcePoliciesFile, err := cfg.As[string](a.Arg("resource-policies-file"))
	if err != nil {
		slog.Warn("No resource policies file provided, proceeding without resource policies")
		a.pd.ResourcePolicies = make(map[string]*types.Policy)
		return nil
	}

	if resourcePoliciesFile == "" {
		slog.Warn("Empty resource policies file path, proceeding without resource policies")
		a.pd.ResourcePolicies = make(map[string]*types.Policy)
		return nil
	}

	fileBytes, err := os.ReadFile(resourcePoliciesFile)
	if err != nil {
		return fmt.Errorf("failed to read resource policies file '%s': %w", resourcePoliciesFile, err)
	}

	// Try to unmarshal as array first (in case the module output was wrapped in an array)
	var resourcePoliciesArray []map[string]*types.Policy
	if err := json.Unmarshal(fileBytes, &resourcePoliciesArray); err == nil {
		if len(resourcePoliciesArray) > 0 {
			a.pd.ResourcePolicies = resourcePoliciesArray[0]
		} else {
			slog.Warn("Empty resource policies array, proceeding without resource policies")
			a.pd.ResourcePolicies = make(map[string]*types.Policy)
		}
	} else {
		// Parse as map[string]*types.Policy directly (expected format)
		if err := json.Unmarshal(fileBytes, &a.pd.ResourcePolicies); err != nil {
			return fmt.Errorf("failed to unmarshal resource policies from '%s': %w", resourcePoliciesFile, err)
		}
	}

	if a.pd.ResourcePolicies == nil {
		a.pd.ResourcePolicies = make(map[string]*types.Policy)
	}

	slog.Info("Successfully loaded resource policies", "file", resourcePoliciesFile, "count", len(a.pd.ResourcePolicies))
	return nil
}

// Reuse the existing graph method from apollo_control_flow.go
func (a *AwsApolloOfflineControlFlow) graph(summary *iam.PermissionsSummary) {
	// Create Neo4j outputter manually and initialize it
	neo4jOutputter := outputters.NewNeo4jGraphOutputter(cfg.WithArgs(a.Args()))

	// Initialize the outputter manually
	err := neo4jOutputter.Initialize()
	if err != nil {
		a.Logger.Error("Failed to initialize Neo4j outputter: " + err.Error())
		return
	}
	a.Logger.Info("Neo4j outputter initialized successfully")

	// Transform and send IAM permission relationships directly to Neo4j outputter
	fullResults := summary.FullResults()
	a.Logger.Info(fmt.Sprintf("DEBUG: Found %d full results to process", len(fullResults)))

	for i, result := range fullResults {
		a.Logger.Debug(fmt.Sprintf("DEBUG: Processing result %d - Principal: %T, Resource: %v, Action: %s",
			i, result.Principal, result.Resource, result.Action))

		rel, err := TransformResultToRelationship(result)
		if err != nil {
			a.Logger.Error("Failed to transform relationship: " + err.Error())
			continue
		}
		a.Logger.Debug(fmt.Sprintf("DEBUG: Successfully transformed result %d, sending directly to Neo4j outputter", i))

		// Send directly to Neo4j outputter bypassing the chain
		if neo4jOut, ok := neo4jOutputter.(*outputters.Neo4jGraphOutputter); ok {
			err = neo4jOut.Output(rel)
			if err != nil {
				a.Logger.Error("Failed to send relationship to Neo4j outputter: " + err.Error())
			}
		}
	}

	// Create assume role relationships between resources and their IAM roles
	err = a.sendResourceRoleRelationshipsDirectly(neo4jOutputter)
	if err != nil {
		a.Logger.Error("Failed to create assume role relationships: " + err.Error())
	}

	// Process GitHub Actions relationships
	githubRelationships, err := ExtractGitHubActionsRelationships(a.pd.Gaad)
	if err != nil {
		a.Logger.Error("Failed to extract GitHub Actions relationships: " + err.Error())
	} else {
		a.Logger.Info(fmt.Sprintf("Processing %d GitHub Actions relationships", len(githubRelationships)))
		for _, rel := range githubRelationships {
			if neo4jOut, ok := neo4jOutputter.(*outputters.Neo4jGraphOutputter); ok {
				err = neo4jOut.Output(rel)
				if err != nil {
					a.Logger.Error("Failed to send GitHub relationship to Neo4j outputter: " + err.Error())
				}
			}
		}
	}

	// Complete the Neo4j outputter to write all data to Neo4j
	if neo4jOut, ok := neo4jOutputter.(*outputters.Neo4jGraphOutputter); ok {
		err = neo4jOut.Complete()
		if err != nil {
			a.Logger.Error("Failed to complete Neo4j outputter: " + err.Error())
		}
	}
}

// sendResourceRoleRelationships creates assume role relationships using the outputter chain
func (a *AwsApolloOfflineControlFlow) sendResourceRoleRelationships(outputChain chain.Chain) error {
	if a.pd.Resources == nil || len(*a.pd.Resources) == 0 {
		return nil
	}

	for _, resource := range *a.pd.Resources {
		roleArn := resource.GetRoleArn()
		if roleArn == "" {
			continue
		}

		var roleName string
		var accountId string = resource.AccountId

		// Check if we have a full ARN or just a role name
		if strings.HasPrefix(roleArn, "arn:") {
			// Parse the ARN for proper role name
			parsedArn, err := arn.Parse(roleArn)
			if err != nil {
				a.Logger.Error(fmt.Sprintf("Failed to parse role ARN %s: %s", roleArn, err.Error()))
				continue
			}

			// If we have a valid ARN, use the account ID from it
			accountId = parsedArn.AccountID

			// Extract role name from resource field
			roleName = parsedArn.Resource
			// Handle the case where the resource includes a path like "role/rolename"
			if strings.Contains(roleName, "/") {
				parts := strings.Split(roleName, "/")
				roleName = parts[len(parts)-1]
			}
		} else {
			// If no ARN format, assume it's a direct role name
			roleName = roleArn
			// Use the resource's account ID for constructing the role ARN
			roleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)
		}

		// Create the resource node using Tabularium transformers
		resourceNode, err := TransformERDToAWSResource(&resource)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to transform resource %s: %s", resource.Arn.String(), err.Error()))
			continue
		}

		// Create the role node using Tabularium types
		roleProperties := map[string]any{
			"roleName": roleName,
		}
		roleNode, err := model.NewAWSResource(
			roleArn,
			accountId,
			model.AWSRole,
			roleProperties,
		)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to create role resource %s: %s", roleArn, err.Error()))
			continue
		}

		// Create the assume role relationship
		assumeRoleRel := model.NewBaseRelationship(resourceNode, &roleNode, "sts:AssumeRole")
		assumeRoleRel.Capability = "apollo-resource-role-mapping"

		// Send to outputter
		outputChain.Send(assumeRoleRel)
	}

	return nil
}

// sendResourceRoleRelationshipsDirectly creates assume role relationships using the outputter directly
func (a *AwsApolloOfflineControlFlow) sendResourceRoleRelationshipsDirectly(outputter chain.Outputter) error {
	if a.pd.Resources == nil || len(*a.pd.Resources) == 0 {
		return nil
	}

	for _, resource := range *a.pd.Resources {
		roleArn := resource.GetRoleArn()
		if roleArn == "" {
			continue
		}

		var roleName string
		var accountId string = resource.AccountId

		// Check if we have a full ARN or just a role name
		if strings.HasPrefix(roleArn, "arn:") {
			// Parse the ARN for proper role name
			parsedArn, err := arn.Parse(roleArn)
			if err != nil {
				a.Logger.Error(fmt.Sprintf("Failed to parse role ARN %s: %s", roleArn, err.Error()))
				continue
			}

			// If we have a valid ARN, use the account ID from it
			accountId = parsedArn.AccountID

			// Extract role name from resource field
			roleName = parsedArn.Resource
			// Handle the case where the resource includes a path like "role/rolename"
			if strings.Contains(roleName, "/") {
				parts := strings.Split(roleName, "/")
				roleName = parts[len(parts)-1]
			}
		} else {
			// If no ARN format, assume it's a direct role name
			roleName = roleArn
			// Use the resource's account ID for constructing the role ARN
			roleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)
		}

		// Create the resource node using Tabularium transformers
		resourceNode, err := TransformERDToAWSResource(&resource)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to transform resource %s: %s", resource.Arn.String(), err.Error()))
			continue
		}

		// Create the role node using Tabularium types
		roleProperties := map[string]any{
			"roleName": roleName,
		}
		roleNode, err := model.NewAWSResource(
			roleArn,
			accountId,
			model.AWSRole,
			roleProperties,
		)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to create role resource %s: %s", roleArn, err.Error()))
			continue
		}

		// Create the assume role relationship
		assumeRoleRel := model.NewBaseRelationship(resourceNode, &roleNode, "sts:AssumeRole")
		assumeRoleRel.Capability = "apollo-resource-role-mapping"

		// Send directly to outputter
		if neo4jOut, ok := outputter.(*outputters.Neo4jGraphOutputter); ok {
			err = neo4jOut.Output(assumeRoleRel)
			if err != nil {
				a.Logger.Error(fmt.Sprintf("Failed to send assume role relationship to outputter: %s", err.Error()))
			}
		}
	}

	return nil
}

// Reuse the existing enrichAccountDetails method from apollo_control_flow.go
func (a *AwsApolloOfflineControlFlow) enrichAccountDetails() {
	// Query for all Account nodes
	query := `
		MATCH (a:Account)
		RETURN a.accountId as accountId
	`

	results, err := a.db.Query(a.ctx, query, nil)
	if err != nil {
		a.Logger.Error("Failed to query Account nodes: " + err.Error())
		return
	}

	for _, record := range results.Records {
		accountID, ok := record["accountId"]
		if !ok || accountID == nil {
			continue
		}

		accountIDStr, ok := accountID.(string)
		if !ok {
			continue
		}

		// Build properties to update
		props := make(map[string]interface{})

		// Try org policy lookup first
		orgAccount := a.pd.OrgPolicies.GetAccount(accountIDStr)
		if orgAccount != nil {
			// Use org policy data
			props["name"] = orgAccount.Name
			props["email"] = orgAccount.Email
			props["status"] = orgAccount.Status
			props["source"] = "OrgPolicies"
			props["memberoforg"] = true
		} else {
			// If no org policy data, try known account
			knownAccountChain := chain.NewChain(
				NewKnownAccountID(cfg.WithArgs(a.Args())),
			)
			knownAccountChain.WithConfigs(cfg.WithArgs(a.Args()))
			knownAccountChain.Send(accountIDStr)
			knownAccountChain.Close()

			var knownAccount *AwsKnownAccount
			knownAccountData, ok := chain.RecvAs[AwsKnownAccount](knownAccountChain)
			if ok {
				knownAccount = &knownAccountData
				props["name"] = knownAccount.Owner
				props["owner"] = knownAccount.Owner
				if knownAccount.Description != "" {
					props["description"] = knownAccount.Description
				}
				props["thirdparty"] = true
				props["source"] = "KnownAccountID"
			}
		}

		// Only update if we have properties to set
		if len(props) > 0 {
			updateQuery := `
				MATCH (a:Account {accountId: $accountId})
				SET a += $props
				RETURN a
			`

			params := map[string]any{
				"accountId": accountIDStr,
				"props":     props,
			}

			_, err := a.db.Query(a.ctx, updateQuery, params)
			if err != nil {
				a.Logger.Error(fmt.Sprintf("Failed to update Account node for %s: %s", accountIDStr, err.Error()))
			}
		}
	}
}

// Since we're not gathering resources dynamically, we don't need mapResourceRoleRelationships
// for the offline version, but we'll stub it out for consistency
func (a *AwsApolloOfflineControlFlow) mapResourceRoleRelationships() error {
	// For offline mode, we don't have dynamic resource discovery
	// This would only be useful if the resource policies file contained resource metadata
	a.Logger.Debug("Skipping resource role relationship mapping in offline mode")
	return nil
}

func (a *AwsApolloOfflineControlFlow) Close() {
	if a.db != nil {
		a.db.Close()
	}
}
