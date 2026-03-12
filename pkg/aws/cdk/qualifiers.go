package cdk

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func discoverQualifiers(ctx context.Context, ssmClient *ssm.Client, iamClient *iam.Client, accountID, region string) []string {
	slog.Debug("scanning SSM parameters for qualifiers", "region", region)
	qualifiers, err := discoverQualifiersFromSSM(ctx, ssmClient)
	if err == nil && len(qualifiers) > 0 {
		slog.Debug("qualifiers discovered from SSM", "region", region, "qualifiers", qualifiers)
		return qualifiers
	}

	slog.Debug("scanning IAM roles for qualifiers", "region", region)
	qualifiers, err = discoverQualifiersFromIAMRoles(ctx, iamClient, accountID, region)
	if err == nil && len(qualifiers) > 0 {
		slog.Debug("qualifiers discovered from IAM roles", "region", region, "qualifiers", qualifiers)
		return qualifiers
	}

	return nil
}

func discoverQualifiersFromSSM(ctx context.Context, client *ssm.Client) ([]string, error) {
	var qualifiers []string
	var nextToken *string

	for {
		result, err := client.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:       aws.String("/cdk-bootstrap/"),
			Recursive:  aws.Bool(true),
			NextToken:  nextToken,
			MaxResults: aws.Int32(10),
		})
		if err != nil {
			return qualifiers, fmt.Errorf("discover qualifiers from SSM: %w", err)
		}

		for _, param := range result.Parameters {
			if param.Name != nil {
				if q := extractQualifierFromParameterName(*param.Name); q != "" {
					if !slices.Contains(qualifiers, q) {
						qualifiers = append(qualifiers, q)
					}
				}
			}
		}

		nextToken = result.NextToken
		if nextToken == nil {
			break
		}
	}

	return qualifiers, nil
}

func discoverQualifiersFromIAMRoles(ctx context.Context, client *iam.Client, accountID, region string) ([]string, error) {
	cdkRolePattern := regexp.MustCompile(fmt.Sprintf(
		`^cdk-([a-z0-9]+)-(?:file-publishing-role|cfn-exec-role|image-publishing-role|lookup-role|deploy-role)-%s-%s$`,
		regexp.QuoteMeta(accountID), regexp.QuoteMeta(region),
	))

	var qualifiers []string
	var marker *string

	for {
		result, err := client.ListRoles(ctx, &iam.ListRolesInput{
			MaxItems: aws.Int32(1000),
			Marker:   marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM roles: %w", err)
		}

		for _, role := range result.Roles {
			if role.RoleName != nil {
				matches := cdkRolePattern.FindStringSubmatch(*role.RoleName)
				if len(matches) == 2 {
					if !slices.Contains(qualifiers, matches[1]) {
						qualifiers = append(qualifiers, matches[1])
					}
				}
			}
		}

		if !result.IsTruncated {
			break
		}
		marker = result.Marker
	}

	return qualifiers, nil
}

func extractQualifierFromParameterName(name string) string {
	rest, ok := strings.CutPrefix(name, "/cdk-bootstrap/")
	if !ok {
		return ""
	}
	parts := strings.Split(rest, "/")
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}
	return ""
}
