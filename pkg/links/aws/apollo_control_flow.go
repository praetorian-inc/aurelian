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
	"github.com/praetorian-inc/konstellation/pkg/graph/queries"
	transformers "github.com/praetorian-inc/konstellation/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/konstellation/pkg/graph/utils"
	iam "github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type AwsApolloControlFlow struct {
	*base.AwsReconLink
	pd  *iam.PolicyData
	db  graph.GraphDatabase
	ctx context.Context
}

func (a *AwsApolloControlFlow) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.AWSRole,
		model.AWSUser,
		model.AWSGroup,
		model.AWSLambdaFunction,
		model.AWSEC2Instance,
		model.AWSCloudFormationStack,
		"AWS::Glue::DevEndpoint", // Add Glue DevEndpoint as a CloudResourceType
	}
}

func NewAwsApolloControlFlow(configs ...cfg.Config) chain.Link {
	a := &AwsApolloControlFlow{}
	a.AwsReconLink = base.NewAwsReconLink(a, configs...)
	return a
}

func (a *AwsApolloControlFlow) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	params = append(params, options.AwsOrgPolicies())
	params = append(params, options.Neo4jOptions()...)
	return params
}

func (a *AwsApolloControlFlow) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		return err
	}
	// Initialize PolicyData with an empty slice of resources
	resources := make([]types.EnrichedResourceDescription, 0)
	a.pd = &iam.PolicyData{
		Resources: &resources,
	}
	a.loadOrgPolicies()

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

func (a *AwsApolloControlFlow) loadOrgPolicies() error {
	orgPol, ok := a.Args()[options.AwsOrgPolicies().Name()]
	if !ok || orgPol == nil {
		slog.Warn("No organization policies file provided, assuming p-FullAWSAccess.")
		a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	orgPolFile := orgPol.(string)
	if orgPolFile != "" {
		fileBytes, err := os.ReadFile(orgPolFile)
		if err != nil {
			return fmt.Errorf("failed to read org policies file: %w", err)
		}

		// Try to unmarshal as array first (current format)
		var orgPoliciesArray []*orgpolicies.OrgPolicies
		if err := json.Unmarshal(fileBytes, &orgPoliciesArray); err == nil {
			if len(orgPoliciesArray) > 0 {
				a.pd.OrgPolicies = orgPoliciesArray[0]
			} else {
				slog.Warn("Empty organization policies array, assuming p-FullAWSAccess.")
				a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
			}
		} else {
			// Fallback to single object format
			var orgPolicies *orgpolicies.OrgPolicies
			if err := json.Unmarshal(fileBytes, &orgPolicies); err != nil {
				return fmt.Errorf("failed to unmarshal org policies: %w", err)
			}
			a.pd.OrgPolicies = orgPolicies
		}
	} else {
		slog.Warn("Empty organization policies file path provided, assuming p-FullAWSAccess.")
		a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
	}

	return nil
}

func (a *AwsApolloControlFlow) Process(resourceType string) error {
	err := a.gatherResources(resourceType)
	if err != nil {
		return err
	}

	err = a.gatherResourcePolicies()
	if err != nil {
		return err
	}

	err = a.gatherGaadDetails()
	if err != nil {
		return err
	}

	analyzer := iam.NewGaadAnalyzer(a.pd)
	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return err
	}

	a.graph(summary)

	// Create relationships between resources and their IAM roles
	err = a.mapResourceRoleRelationships()
	if err != nil {
		a.Logger.Error("Failed to create assume role relationships: " + err.Error())
	}

	return nil
}

func (a *AwsApolloControlFlow) gatherResources(resourceType string) error {
	resourceChain := chain.NewChain(
		general.NewResourceTypePreprocessor(a)(),
		cloudcontrol.NewAWSCloudControl(cfg.WithArgs(a.Args())),
	)

	resourceChain.WithConfigs(cfg.WithArgs(a.Args()))
	resourceChain.Send(resourceType)
	resourceChain.Close()

	// Collect resources from the resource chain
	var resource *types.EnrichedResourceDescription
	var ok bool

	for {
		resource, ok = chain.RecvAs[*types.EnrichedResourceDescription](resourceChain)
		if !ok {
			break
		}
		*a.pd.Resources = append(*a.pd.Resources, *resource)
	}

	return nil
}

func (a *AwsApolloControlFlow) gatherResourcePolicies() error {
	// Create policy fetcher chain
	policyChain := chain.NewChain(
		NewAwsResourcePolicyFetcher(cfg.WithArgs(a.Args())),
	)
	policyChain.WithConfigs(cfg.WithArgs(a.Args()))

	// Initialize map if nil
	if a.pd.ResourcePolicies == nil {
		a.pd.ResourcePolicies = make(map[string]*types.Policy)
	}

	// Send resources to policy fetcher and collect policies
	for _, resource := range *a.pd.Resources {
		policyChain.Send(resource)
		policyChain.Close()

		for {
			policy, ok := chain.RecvAs[*types.Policy](policyChain)
			if !ok {
				break
			}
			a.pd.ResourcePolicies[resource.Arn.String()] = policy
		}
	}

	return nil
}

func (a *AwsApolloControlFlow) gatherGaadDetails() error {
	gaadChain := chain.NewChain(
		NewJanusAWSAuthorizationDetails(cfg.WithArgs(a.Args())),
	)
	gaadChain.WithConfigs(cfg.WithArgs(a.Args()))
	gaadChain.Send("") // GAAD doesn't need a resource type
	gaadChain.Close()

	// Collect GAAD output
	var gaadOutput outputters.NamedOutputData
	var ok bool
	for {
		gaadOutput, ok = chain.RecvAs[outputters.NamedOutputData](gaadChain)
		if !ok {
			break
		}
		// Convert GAAD output to PolicyData.Gaad
		// First marshal the map to JSON bytes
		jsonBytes, err := json.Marshal(gaadOutput.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal GAAD data: %w", err)
		}
		// Then unmarshal into the Gaad struct
		if err := json.Unmarshal(jsonBytes, &a.pd.Gaad); err != nil {
			return fmt.Errorf("failed to unmarshal GAAD data: %w", err)
		}
	}

	return nil
}

func (a *AwsApolloControlFlow) graph(summary *iam.PermissionsSummary) {

	rels := make([]*graph.Relationship, 0)
	for _, result := range summary.FullResults() {
		rel, err := resultToRelationship(result)
		if err != nil {
			a.Logger.Error("Failed to create relationship: " + err.Error())
			continue
		}
		rels = append(rels, rel)
	}

	res, err := a.db.CreateRelationships(a.ctx, rels)
	if err != nil {
		a.Logger.Error("Failed to create relationships: " + err.Error())
	}

	res.PrintSummary()

	// Enrich data
	eResults, err := queries.EnrichAWS(a.db)
	if err != nil {
		a.Logger.Error("Failed to enrich data: " + err.Error())
	}

	// Enrich data with org policies and known account IDs
	a.enrichAccountDetails()

	a.Logger.Debug("Enriched results: ", eResults)
}

// enrichAccountDetails enriches Account nodes with information from org policies and known account IDs
func (a *AwsApolloControlFlow) enrichAccountDetails() {
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

func resultToRelationship(result iam.FullResult) (*graph.Relationship, error) {
	rel := graph.Relationship{}
	rel.Type = result.Action

	// Handle Principal (StartNode)
	switch p := result.Principal.(type) {
	case *types.UserDL:
		rel.StartNode = transformers.NodeFromUserDL(p)
	case *types.RoleDL:
		rel.StartNode = transformers.NodeFromRoleDL(p)
	case *types.GroupDL:
		rel.StartNode = transformers.NodeFromGroupDL(p)
	case string:
		// Handle service principals
		if strings.Contains(p, "amazonaws.com") || strings.Contains(p, "aws:service") {
			serviceName := p

			// Extract service name from ARN format if needed
			if strings.HasPrefix(p, "arn:aws:iam::aws:service/") {
				serviceName = strings.TrimPrefix(p, "arn:aws:iam::aws:service/")
			}

			rel.StartNode = &graph.Node{
				Labels: []string{"Service", "Principal", "Resource"},
				Properties: map[string]interface{}{
					"name":     serviceName,
					"arn":      p,
					"fullName": p,
				},
				UniqueKey: []string{"name"},
			}
		} else {
			// Handle other string principal types (ARNs, etc.)
			principalName := p

			// Try to extract a short name from ARN
			if strings.HasPrefix(p, "arn:") {
				parts := strings.Split(p, "/")
				if len(parts) > 1 {
					principalName = parts[len(parts)-1]
				}
			}

			rel.StartNode = &graph.Node{
				Labels: []string{"Principal"},
				Properties: map[string]interface{}{
					"arn":  p,
					"name": principalName,
				},
				UniqueKey: []string{"arn"},
			}
		}
	default:
		return nil, fmt.Errorf("unknown principal type: %T", p)
	}

	// Ensure StartNode is not nil
	if rel.StartNode == nil {
		return nil, fmt.Errorf("could not create start node for principal: %v", result.Principal)
	}

	// Handle Resource (EndNode)
	if result.Resource == nil {
		return nil, fmt.Errorf("nil resource")
	}

	var err error
	rel.EndNode, err = transformers.NodeFromEnrichedResourceDescription(result.Resource)
	if err != nil {
		return nil, fmt.Errorf("failed to create node from resource: %w", err)
	}

	// Process Result
	if result.Result != nil {
		flattenedResult, err := utils.ConvertAndFlatten(result.Result, "PolicyResult")
		if err != nil {
			rel.Properties = map[string]any{
				"allowed": result.Result.Allowed,
				"details": result.Result.EvaluationDetails,
			}
		} else {
			rel.Properties = flattenedResult
		}
	}

	return &rel, nil
}

// mapResourceRoleRelationships creates sts:AssumeRole relationships between resources and their IAM roles
func (a *AwsApolloControlFlow) mapResourceRoleRelationships() error {
	if a.pd.Resources == nil || len(*a.pd.Resources) == 0 {
		return nil
	}

	rels := make([]*graph.Relationship, 0)

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

		// Create the resource node
		resourceNode, err := transformers.NodeFromEnrichedResourceDescription(&resource)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to create node from resource %s: %s", resource.Arn.String(), err.Error()))
			continue
		}

		// Create the role node
		roleNode := &graph.Node{
			Labels: []string{"Role", "Principal", "Resource"},
			Properties: map[string]interface{}{
				"name": roleName,
				"arn":  roleArn,
			},
			UniqueKey: []string{"arn"},
		}

		// Create the relationship
		rel := &graph.Relationship{
			StartNode:  resourceNode,
			EndNode:    roleNode,
			Type:       "sts:AssumeRole",
			Properties: map[string]any{"allowed": true},
		}

		rels = append(rels, rel)
	}

	if len(rels) == 0 {
		return nil
	}

	// Create relationships in the graph database
	if _, err := a.db.CreateRelationships(a.ctx, rels); err != nil {
		return fmt.Errorf("failed to create assume role relationships: %w", err)
	}

	a.Logger.Info(fmt.Sprintf("Created %d assume role relationships", len(rels)))
	return nil
}

func (a *AwsApolloControlFlow) Close() {
	a.db.Close()
}
