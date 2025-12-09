package aws

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
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
	pd *iam.PolicyData
}

func (a *AwsApolloControlFlow) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.AWSRole,
		model.AWSUser,
		model.AWSGroup,
		model.AWSLambdaFunction,
		model.AWSEC2Instance,
		model.AWSCloudFormationStack,
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

	// Transform and send IAM permission relationships
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
		a.Logger.Debug(fmt.Sprintf("DEBUG: Successfully transformed result %d, sending to outputter", i))
		a.Send(rel)
	}

	// Create assume role relationships between resources and their IAM roles
	err = a.sendResourceRoleRelationships()
	if err != nil {
		a.Logger.Error("Failed to create assume role relationships: " + err.Error())
	}

	// Process GitHub Actions federated identity relationships
	err = a.processGitHubActionsFederation()
	if err != nil {
		a.Logger.Error("Failed to process GitHub Actions federation: " + err.Error())
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
	}

	policyChain.Close()

	for {
		policy, ok := chain.RecvAs[*types.Policy](policyChain)
		if !ok {
			break
		}
		a.pd.ResourcePolicies[policy.ResourceARN] = policy
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

	if a.pd.Gaad == nil {
		return fmt.Errorf("failed to collect GAAD (GetAccountAuthorizationDetails) data - the IAM authorization details chain did not produce output")
	}

	return nil
}

// sendResourceRoleRelationships creates assume role relationships using the outputter chain
func (a *AwsApolloControlFlow) sendResourceRoleRelationships() error {
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
		assumeRoleRel := model.NewIAMRelationship(resourceNode, &roleNode, "sts:AssumeRole")
		assumeRoleRel.Capability = "apollo-resource-role-mapping"

		// Send to outputter
		a.Send(assumeRoleRel)
	}

	return nil
}

// processGitHubActionsFederation processes GitHub Actions federated identity relationships
func (a *AwsApolloControlFlow) processGitHubActionsFederation() error {
	if a.pd == nil || a.pd.Gaad == nil {
		return nil
	}

	// Extract all GitHub Actions Repository→Role relationships from GAAD data
	relationships, err := ExtractGitHubActionsRelationships(a.pd.Gaad)
	if err != nil {
		return fmt.Errorf("failed to extract GitHub Actions relationships: %w", err)
	}

	// Send all relationships to the outputter chain
	for _, rel := range relationships {
		a.Send(rel)
	}

	return nil
}

func (a *AwsApolloControlFlow) Close() {
	// No database connection to close - handled by outputter
}
