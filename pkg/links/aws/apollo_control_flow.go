package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/konstellation/pkg/graph"
	"github.com/praetorian-inc/konstellation/pkg/graph/adapters"
	"github.com/praetorian-inc/konstellation/pkg/graph/queries"
	transformers "github.com/praetorian-inc/konstellation/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/konstellation/pkg/graph/utils"
	iam "github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsApolloControlFlow struct {
	*base.AwsReconLink
	pd *iam.PolicyData
}

func (a *AwsApolloControlFlow) SupportedResourceTypes() []string {
	return []string{
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::IAM::Group",
		"AWS::Lambda::Function",
		"AWS::EC2::Instance",
		"AWS::CloudFormation::Stack",
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
		var orgPolicies *orgpolicies.OrgPolicies
		if err := json.Unmarshal(fileBytes, &orgPolicies); err != nil {
			return fmt.Errorf("failed to unmarshal org policies: %w", err)
		}
		a.pd.OrgPolicies = orgPolicies
	} else {
		slog.Warn("Empty organization policies file path provided, assuming p-FullAWSAccess.")
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

	return nil
}

func (a *AwsApolloControlFlow) gatherResources(resourceType string) error {
	resourceChain := chain.NewChain(
		general.NewResourceTypePreprocessor(a)(),
		NewAWSCloudControl(cfg.WithArgs(a.Args())),
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

	graphConfig := &graph.Config{
		URI:      "bolt://localhost:7687",
		Username: "neo4j",
		Password: "konstellation",
	}

	ctx := context.Background()
	driver, err := adapters.NewNeo4jDatabase(graphConfig)
	if err != nil {
		a.Logger.Error("Failed to create Neo4j driver: " + err.Error())
		os.Exit(1)
	}

	res, err := driver.CreateRelationships(ctx, rels)
	if err != nil {
		a.Logger.Error("Failed to create relationships: " + err.Error())
	}

	res.PrintSummary()

	// Enrich data
	eResults, err := queries.EnrichAWS(driver)
	if err != nil {
		a.Logger.Error("Failed to enrich data: " + err.Error())
	}

	fmt.Println("Enriched results: ", eResults)
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
		flattenedResult, err := utils.ConvertAndFlatten(result.Result, "EvaluationDetails")
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
