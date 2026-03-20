package publicaccess

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
)

// EvaluationContext pairs an action with a request context for public access evaluation.
type EvaluationContext struct {
	Action  string
	Context *iam.RequestContext
}

// GetEvaluationContexts returns the evaluation contexts to test for a given resource type.
// Each context simulates a different type of anonymous/public access attempt.
func GetEvaluationContexts(resourceType, resourceARN, accountID string) ([]EvaluationContext, error) {
	switch resourceType {
	case "AWS::S3::Bucket":
		return s3Contexts(resourceARN, accountID), nil
	case "AWS::SNS::Topic":
		return snsContexts(resourceARN, accountID), nil
	case "AWS::SQS::Queue":
		return sqsContexts(resourceARN, accountID), nil
	case "AWS::Lambda::Function":
		return lambdaContexts(resourceARN, accountID), nil
	case "AWS::EFS::FileSystem":
		return efsContexts(resourceARN, accountID), nil
	case "AWS::OpenSearchService::Domain":
		return openSearchContexts(resourceARN, accountID), nil
	case "AWS::Elasticsearch::Domain":
		return elasticsearchContexts(resourceARN, accountID), nil
	default:
		return nil, fmt.Errorf("unsupported resource type for public access evaluation: %s", resourceType)
	}
}

// anonymousContext creates a request context simulating an anonymous (unauthenticated) caller.
func anonymousContext(accountID string) *iam.RequestContext {
	ctx := iam.NewRequestContext()
	ctx.PrincipalArn = "arn:aws:iam::anonymous"
	ctx.ResourceAccount = accountID
	ctx.SecureTransport = iam.Bool(true)
	return ctx
}

// crossAccountContext creates a request context simulating an authenticated caller from a different account.
func crossAccountContext(accountID string) *iam.RequestContext {
	ctx := iam.NewRequestContext()
	ctx.PrincipalArn = "arn:aws:iam::999999999999:root"
	ctx.PrincipalAccount = "999999999999"
	ctx.ResourceAccount = accountID
	ctx.SecureTransport = iam.Bool(true)
	return ctx
}

func s3Contexts(resourceARN, accountID string) []EvaluationContext {
	actions := []string{
		"s3:GetObject",
		"s3:PutObject",
		"s3:ListBucket",
		"s3:DeleteObject",
		"s3:GetBucketAcl",
	}

	var contexts []EvaluationContext
	for _, action := range actions {
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: anonymousContext(accountID),
		})
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: crossAccountContext(accountID),
		})
	}
	return contexts
}

func snsContexts(resourceARN, accountID string) []EvaluationContext {
	actions := []string{
		"sns:Publish",
		"sns:Subscribe",
		"sns:GetTopicAttributes",
	}

	var contexts []EvaluationContext
	for _, action := range actions {
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: anonymousContext(accountID),
		})
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: crossAccountContext(accountID),
		})
	}
	return contexts
}

func sqsContexts(resourceARN, accountID string) []EvaluationContext {
	actions := []string{
		"sqs:SendMessage",
		"sqs:ReceiveMessage",
		"sqs:GetQueueAttributes",
	}

	var contexts []EvaluationContext
	for _, action := range actions {
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: anonymousContext(accountID),
		})
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: crossAccountContext(accountID),
		})
	}
	return contexts
}

func lambdaContexts(resourceARN, accountID string) []EvaluationContext {
	actions := []string{
		"lambda:InvokeFunction",
		"lambda:GetFunction",
	}

	var contexts []EvaluationContext
	for _, action := range actions {
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: anonymousContext(accountID),
		})
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: crossAccountContext(accountID),
		})
	}
	return contexts
}

func efsContexts(resourceARN, accountID string) []EvaluationContext {
	actions := []string{
		"elasticfilesystem:ClientMount",
		"elasticfilesystem:ClientWrite",
		"elasticfilesystem:ClientRootAccess",
	}

	var contexts []EvaluationContext
	for _, action := range actions {
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: anonymousContext(accountID),
		})
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: crossAccountContext(accountID),
		})
	}
	return contexts
}

func openSearchContexts(resourceARN, accountID string) []EvaluationContext {
	actions := []string{
		"es:ESHttpGet",
		"es:ESHttpPut",
		"es:ESHttpPost",
	}

	var contexts []EvaluationContext
	for _, action := range actions {
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: anonymousContext(accountID),
		})
		contexts = append(contexts, EvaluationContext{
			Action:  action,
			Context: crossAccountContext(accountID),
		})
	}
	return contexts
}

func elasticsearchContexts(resourceARN, accountID string) []EvaluationContext {
	return openSearchContexts(resourceARN, accountID)
}
