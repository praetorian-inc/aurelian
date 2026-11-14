package escalation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// TerraformPlanOptions supplies the stable account values that cannot be
// learned from an apply-free plan when provider-computed ARNs are unknown.
type TerraformPlanOptions struct {
	AccountID string
	Region    string
	Partition string
	Attacker  string
}

type terraformPlan struct {
	FormatVersion string `json:"format_version"`
	PlannedValues struct {
		RootModule terraformModule `json:"root_module"`
	} `json:"planned_values"`
	Configuration struct {
		RootModule terraformConfigModule `json:"root_module"`
	} `json:"configuration"`
}

type terraformModule struct {
	Resources    []terraformResource `json:"resources"`
	ChildModules []terraformModule   `json:"child_modules"`
}

type terraformResource struct {
	Address string         `json:"address"`
	Type    string         `json:"type"`
	Values  map[string]any `json:"values"`
}

type terraformConfigModule struct {
	Resources   []terraformConfigResource `json:"resources"`
	ModuleCalls map[string]struct {
		Module terraformConfigModule `json:"module"`
	} `json:"module_calls"`
}

type terraformConfigResource struct {
	Address     string                         `json:"address"`
	Expressions map[string]terraformExpression `json:"expressions"`
	ModulePath  string                         `json:"-"`
}

type terraformExpression struct {
	References []string `json:"references"`
}

type roleResourceMapping struct {
	TerraformType   string
	AWSResourceType string
	NameField       string
	RoleField       string
	RoleProperty    string
	ARNResource     string
	Coverage        func(*CollectionCoverage)
}

var terraformRoleResources = []roleResourceMapping{
	{"aws_lambda_function", "AWS::Lambda::Function", "function_name", "role", "Role", "function:", func(c *CollectionCoverage) { c.LambdaExecutionRoles, c.LambdaResourcePolicies = true, true }},
	{"aws_codebuild_project", "AWS::CodeBuild::Project", "name", "service_role", "ServiceRole", "project/", func(c *CollectionCoverage) { c.CodeBuildServiceRoles = true }},
	{"aws_glue_dev_endpoint", "AWS::Glue::DevEndpoint", "name", "role_arn", "RoleArn", "devEndpoint/", func(c *CollectionCoverage) {}},
	{"aws_sagemaker_notebook_instance", "AWS::SageMaker::NotebookInstance", "name", "role_arn", "RoleArn", "notebook-instance/", func(c *CollectionCoverage) {}},
}

// CollectionSnapshotFromTerraformPlan converts Terraform's machine-readable
// planned values into the same collector-shaped snapshot consumed by Assemble.
// The first version intentionally supports a narrow, explicit resource set and
// records unsupported resources instead of silently inventing AWS state.
func CollectionSnapshotFromTerraformPlan(data []byte, opts TerraformPlanOptions) (*CollectionSnapshot, error) {
	if opts.AccountID == "" || opts.Region == "" {
		return nil, fmt.Errorf("terraform plan snapshot requires account ID and region")
	}
	if opts.Partition == "" {
		opts.Partition = "aws"
	}
	var plan terraformPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("decode terraform plan: %w", err)
	}
	if plan.FormatVersion == "" {
		return nil, fmt.Errorf("terraform plan is missing format_version")
	}

	planned := flattenTerraformResources(plan.PlannedValues.RootModule)
	configured := flattenTerraformConfigResources(plan.Configuration.RootModule, "")
	gaad := types.NewAuthorizationAccountDetails(opts.AccountID, nil, nil, nil, nil)
	snapshot := &CollectionSnapshot{
		Version:  CollectionSnapshotVersion,
		GAAD:     gaad,
		Attacker: opts.Attacker,
		CollectionCoverage: map[string]*CollectionCoverage{
			opts.AccountID: {IAMGAAD: true},
		},
	}

	arnsByAddress := make(map[string]string)
	for _, resource := range planned {
		switch resource.Type {
		case "aws_iam_user":
			name := stringValue(resource.Values, "name")
			path := normalizedIAMPath(stringValue(resource.Values, "path"))
			arn := terraformIAMARN(opts.Partition, opts.AccountID, "user", path, name)
			arnsByAddress[resource.Address] = arn
			gaad.Users.Set(arn, types.UserDetail{Arn: arn, UserName: name, Path: path})
		case "aws_iam_role":
			name := stringValue(resource.Values, "name")
			path := normalizedIAMPath(stringValue(resource.Values, "path"))
			arn := terraformIAMARN(opts.Partition, opts.AccountID, "role", path, name)
			arnsByAddress[resource.Address] = arn
			role := types.RoleDetail{Arn: arn, RoleName: name, Path: path}
			if raw := stringValue(resource.Values, "assume_role_policy"); raw != "" {
				if err := json.Unmarshal([]byte(raw), &role.AssumeRolePolicyDocument); err != nil {
					return nil, fmt.Errorf("%s.assume_role_policy: %w", resource.Address, err)
				}
			}
			gaad.Roles.Set(arn, role)
		case "aws_iam_group":
			name := stringValue(resource.Values, "name")
			path := normalizedIAMPath(stringValue(resource.Values, "path"))
			arn := terraformIAMARN(opts.Partition, opts.AccountID, "group", path, name)
			arnsByAddress[resource.Address] = arn
			gaad.Groups.Set(arn, types.GroupDetail{Arn: arn, GroupName: name, Path: path})
		case "aws_iam_policy":
			name := stringValue(resource.Values, "name")
			path := normalizedIAMPath(stringValue(resource.Values, "path"))
			arn := terraformIAMARN(opts.Partition, opts.AccountID, "policy", path, name)
			arnsByAddress[resource.Address] = arn
			var policy types.Policy
			if raw := stringValue(resource.Values, "policy"); raw != "" {
				if err := json.Unmarshal([]byte(raw), &policy); err != nil {
					return nil, fmt.Errorf("%s.policy: %w", resource.Address, err)
				}
			}
			gaad.Policies.Set(arn, types.ManagedPolicyDetail{
				PolicyName: name, Arn: arn, DefaultVersionId: "v1", IsAttachable: true,
				PolicyVersionList: []types.PolicyVersion{{VersionId: "v1", IsDefaultVersion: true, Document: policy}},
			})
		}
	}

	for _, resource := range planned {
		switch resource.Type {
		case "aws_iam_user_policy":
			if err := appendTerraformInlinePolicy(gaad, resource, "user"); err != nil {
				return nil, err
			}
		case "aws_iam_role_policy":
			if err := appendTerraformInlinePolicy(gaad, resource, "role"); err != nil {
				return nil, err
			}
		case "aws_iam_group_policy":
			if err := appendTerraformInlinePolicy(gaad, resource, "group"); err != nil {
				return nil, err
			}
		}
		for _, mapping := range terraformRoleResources {
			if resource.Type != mapping.TerraformType {
				continue
			}
			name := stringValue(resource.Values, mapping.NameField)
			resourceARN := stringValue(resource.Values, "arn")
			if resourceARN == "" && name != "" {
				service := strings.SplitN(strings.TrimPrefix(mapping.AWSResourceType, "AWS::"), "::", 2)[0]
				service = strings.ToLower(service)
				resourceARN = fmt.Sprintf("arn:%s:%s:%s:%s:%s%s", opts.Partition, service, opts.Region, opts.AccountID, mapping.ARNResource, name)
			}
			roleARN, ok := resolveTerraformReference(resource, configured[resource.Address], mapping.RoleField, arnsByAddress)
			if !ok {
				snapshot.Unknowns = append(snapshot.Unknowns, CollectionUnknown{Address: resource.Address, Field: mapping.RoleField, Reason: "role value and referenced ARN are unknown after plan", SecurityCritical: true})
				continue
			}
			snapshot.Resources = append(snapshot.Resources, output.AWSResource{ResourceType: mapping.AWSResourceType, ResourceID: name, ARN: resourceARN, AccountRef: opts.AccountID, Region: opts.Region, Properties: map[string]any{mapping.RoleProperty: roleARN}})
			mapping.Coverage(snapshot.CollectionCoverage[opts.AccountID])
		}
	}

	return snapshot, nil
}

func flattenTerraformResources(module terraformModule) []terraformResource {
	result := append([]terraformResource(nil), module.Resources...)
	for _, child := range module.ChildModules {
		result = append(result, flattenTerraformResources(child)...)
	}
	return result
}

func flattenTerraformConfigResources(module terraformConfigModule, modulePath string) map[string]terraformConfigResource {
	result := make(map[string]terraformConfigResource)
	for _, resource := range module.Resources {
		resource.ModulePath = modulePath
		result[modulePath+resource.Address] = resource
	}
	for name, call := range module.ModuleCalls {
		childPath := modulePath + "module." + name + "."
		for address, resource := range flattenTerraformConfigResources(call.Module, childPath) {
			result[address] = resource
		}
	}
	return result
}

func appendTerraformInlinePolicy(gaad *types.AuthorizationAccountDetails, resource terraformResource, principalType string) error {
	name := stringValue(resource.Values, "name")
	principalName := stringValue(resource.Values, principalType)
	var policy types.Policy
	if err := json.Unmarshal([]byte(stringValue(resource.Values, "policy")), &policy); err != nil {
		return fmt.Errorf("%s.policy: %w", resource.Address, err)
	}
	inline := types.InlinePolicy{PolicyName: name, PolicyDocument: policy}
	switch principalType {
	case "user":
		var found string
		gaad.Users.Range(func(key string, value types.UserDetail) bool {
			if value.UserName == principalName {
				found = key
				value.UserPolicyList = append(value.UserPolicyList, inline)
				gaad.Users.Set(key, value)
				return false
			}
			return true
		})
		if found == "" {
			return fmt.Errorf("%s references missing IAM user %q", resource.Address, principalName)
		}
	case "role":
		var found string
		gaad.Roles.Range(func(key string, value types.RoleDetail) bool {
			if value.RoleName == principalName {
				found = key
				value.RolePolicyList = append(value.RolePolicyList, inline)
				gaad.Roles.Set(key, value)
				return false
			}
			return true
		})
		if found == "" {
			return fmt.Errorf("%s references missing IAM role %q", resource.Address, principalName)
		}
	case "group":
		var found string
		gaad.Groups.Range(func(key string, value types.GroupDetail) bool {
			if value.GroupName == principalName {
				found = key
				value.GroupPolicyList = append(value.GroupPolicyList, inline)
				gaad.Groups.Set(key, value)
				return false
			}
			return true
		})
		if found == "" {
			return fmt.Errorf("%s references missing IAM group %q", resource.Address, principalName)
		}
	}
	return nil
}

func resolveTerraformReference(resource terraformResource, config terraformConfigResource, field string, arns map[string]string) (string, bool) {
	if value := stringValue(resource.Values, field); value != "" {
		return value, true
	}
	for _, reference := range config.Expressions[field].References {
		address := strings.TrimSuffix(reference, ".arn")
		if value := arns[address]; value != "" {
			return value, true
		}
		if value := arns[config.ModulePath+address]; value != "" {
			return value, true
		}
	}
	return "", false
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func normalizedIAMPath(path string) string {
	path = strings.Trim(path, "/")
	if path == "" {
		return "/"
	}
	return "/" + path + "/"
}

func terraformIAMARN(partition, account, kind, path, name string) string {
	return fmt.Sprintf("arn:%s:iam::%s:%s/%s%s", partition, account, kind, strings.Trim(path, "/")+map[bool]string{true: "/", false: ""}[strings.Trim(path, "/") != ""], name)
}
