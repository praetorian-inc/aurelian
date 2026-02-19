package gaad

import (
	"log/slog"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ---------------------------------------------------------------------------
// Resource cache lookups
// ---------------------------------------------------------------------------

func (ctx *analyzerContext) getResourcesByAction(action iam.Action) []*output.AWSResource {
	var resources []*output.AWSResource
	patterns := iam.GetResourcePatternsFromAction(action)
	for _, pattern := range patterns {
		resources = append(resources, ctx.getResources(pattern)...)
	}
	return resources
}

func (ctx *analyzerContext) getResources(pattern *regexp.Regexp) []*output.AWSResource {
	var resources []*output.AWSResource
	for key, r := range ctx.resourceCache {
		if pattern.MatchString(key) {
			resources = append(resources, r)
		}
	}
	return resources
}

// resourceIdentifier returns the key to use in evaluation requests.
// Services use their identifier (e.g. "s3.amazonaws.com"); everything else uses ARN.
func resourceIdentifier(r *output.AWSResource) string {
	if r.ResourceType == "AWS::Service" {
		return r.ResourceID
	}
	return r.ARN
}

// extractResourceTags extracts tags from an AWSResource's Properties map.
// CloudControl resources store tags as Properties["Tags"] = []{Key:..., Value:...}.
// IAM resources created from GAAD have no Properties, so this returns empty.
func extractResourceTags(r *output.AWSResource) map[string]string {
	if r == nil || r.Properties == nil {
		return map[string]string{}
	}
	tags, ok := r.Properties["Tags"]
	if !ok {
		return map[string]string{}
	}
	tagList, ok := tags.([]any)
	if !ok {
		return map[string]string{}
	}
	result := make(map[string]string, len(tagList))
	for _, t := range tagList {
		tag, ok := t.(map[string]any)
		if !ok {
			continue
		}
		key, _ := tag["Key"].(string)
		value, _ := tag["Value"].(string)
		if key != "" {
			result[key] = value
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Action expansion
// ---------------------------------------------------------------------------

func (ctx *analyzerContext) extractActions(stmts *types.PolicyStatementList) []string {
	if stmts == nil {
		return nil
	}
	var actions []string
	for _, stmt := range *stmts {
		if stmt.Action != nil {
			actions = append(actions, ctx.expandActions(*stmt.Action)...)
		}
	}
	return actions
}

func (ctx *analyzerContext) expandActions(actions types.DynaString) []string {
	var expanded []string
	for _, action := range actions {
		if strings.Contains(action, "*") {
			result, err := ctx.actionExpander.Expand(action)
			if err != nil {
				slog.Error("Error expanding action", "action", action, "error", err)
				continue
			}
			expanded = append(expanded, result...)
		} else {
			expanded = append(expanded, action)
		}
	}
	return expanded
}

// ---------------------------------------------------------------------------
// IAM entity → output.AWSResource converters
// ---------------------------------------------------------------------------

var commonServicePrincipals = []string{
	"s3.amazonaws.com", "lambda.amazonaws.com", "ec2.amazonaws.com",
	"iam.amazonaws.com", "dynamodb.amazonaws.com", "sns.amazonaws.com",
	"sqs.amazonaws.com", "cloudformation.amazonaws.com", "cloudtrail.amazonaws.com",
	"rds.amazonaws.com", "ssm.amazonaws.com", "kms.amazonaws.com",
	"secretsmanager.amazonaws.com", "codebuild.amazonaws.com",
	"codepipeline.amazonaws.com", "ecs.amazonaws.com", "eks.amazonaws.com",
	"glue.amazonaws.com", "sagemaker.amazonaws.com", "apigateway.amazonaws.com",
	"autoscaling.amazonaws.com",
}

func newAWSResourceFromRole(role types.RoleDetail) *output.AWSResource {
	a, _ := arn.Parse(role.Arn)
	return &output.AWSResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::Role",
		ResourceID:   role.Arn,
		ARN:          role.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  role.RoleName,
	}
}

func newAWSResourceFromUser(user types.UserDetail) *output.AWSResource {
	a, _ := arn.Parse(user.Arn)
	return &output.AWSResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::User",
		ResourceID:   user.Arn,
		ARN:          user.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  user.UserName,
	}
}

func newAWSResourceFromGroup(group types.GroupDetail) *output.AWSResource {
	a, _ := arn.Parse(group.Arn)
	return &output.AWSResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::Group",
		ResourceID:   group.Arn,
		ARN:          group.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  group.GroupName,
	}
}

func newAWSResourceFromPolicy(policy types.ManagedPolicyDetail) *output.AWSResource {
	a, _ := arn.Parse(policy.Arn)
	return &output.AWSResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::ManagedPolicy",
		ResourceID:   policy.Arn,
		ARN:          policy.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  policy.PolicyName,
	}
}

func newAWSResourceFromService(service string) *output.AWSResource {
	svc := strings.Split(service, ".")[0]
	return &output.AWSResource{
		Platform:     "aws",
		ResourceType: "AWS::Service",
		ResourceID:   service,
		ARN:          service,
		Region:       "*",
		AccountRef:   "*",
		DisplayName:  svc,
	}
}
