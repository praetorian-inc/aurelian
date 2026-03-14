package cdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

func checkBootstrapVersion(ctx context.Context, client *ssm.Client, accountID, region, qualifier string) BootstrapInfo {
	parameterName := fmt.Sprintf("/cdk-bootstrap/%s/version", qualifier)

	slog.Debug("checking bootstrap version", "qualifier", qualifier, "region", region)

	info := BootstrapInfo{
		AccountID: accountID,
		Region:    region,
		Qualifier: qualifier,
	}

	result, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name: &parameterName,
	})
	if err != nil {
		var paramNotFound *ssmtypes.ParameterNotFound
		if errors.As(err, &paramNotFound) {
			return info // HasVersion stays false, which is what we want
		}
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && (apiErr.ErrorCode() == "AccessDeniedException" || apiErr.ErrorCode() == "AccessDenied") {
			slog.Debug("access denied on bootstrap version check", "qualifier", qualifier, "region", region)
			info.AccessDenied = true
		}
		return info
	}

	if result.Parameter != nil && result.Parameter.Value != nil {
		if version, err := strconv.Atoi(*result.Parameter.Value); err == nil {
			slog.Debug("bootstrap version found", "qualifier", qualifier, "region", region, "version", version)
			info.Version = version
			info.HasVersion = true
		}
	}

	return info
}

func generateBootstrapRisk(role RoleInfo, info BootstrapInfo) *output.Risk {
	if info.AccessDenied {
		return nil
	}
	if info.HasVersion && info.Version >= 21 {
		return nil
	}

	accountArn := fmt.Sprintf("arn:aws:iam::%s:root", role.AccountID)
	target := &output.AWSResource{
		ResourceType: "AWS::IAM::Root",
		ResourceID:   accountArn,
		AccountRef:   role.AccountID,
		Region:       role.Region,
		Properties: map[string]any{
			"Qualifier":        role.Qualifier,
			"BootstrapVersion": info.Version,
			"HasVersion":       info.HasVersion,
		},
	}

	var name, description, status string
	if !info.HasVersion {
		name = "cdk-bootstrap-missing"
		status = "TM"
		description = fmt.Sprintf(
			"AWS CDK bootstrap parameter '/cdk-bootstrap/%s/version' not found in region %s. "+
				"CDK was never properly bootstrapped or bootstrap artifacts were deleted.",
			role.Qualifier, role.Region,
		)
	} else {
		name = "cdk-bootstrap-outdated"
		status = "TH"
		description = fmt.Sprintf(
			"AWS CDK bootstrap version %d is outdated in region %s (< v21). "+
				"Versions before v21 lack security protections against S3 bucket takeover attacks.",
			info.Version, role.Region,
		)
	}

	var comment string
	if info.HasVersion {
		comment = fmt.Sprintf("Bootstrap Version: %d, Qualifier: %s, Region: %s", info.Version, role.Qualifier, role.Region)
	} else {
		comment = fmt.Sprintf("Bootstrap Version: Missing, Qualifier: %s, Region: %s", role.Qualifier, role.Region)
	}

	return &output.Risk{
		Target:         target,
		Name:           name,
		DNS:            role.AccountID,
		Status:         status,
		Source:         "aurelian-cdk-scanner",
		Description:    description,
		Impact:         "CDK deployments may be vulnerable to S3 bucket takeover attacks, potentially allowing attackers to inject malicious CloudFormation templates and gain account access.",
		Recommendation: fmt.Sprintf("Upgrade to CDK v2.149.0+ and re-run 'cdk bootstrap --qualifier %s' in region %s to apply security patches.", role.Qualifier, role.Region),
		References:     "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/\nhttps://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html",
		Comment:        comment,
	}
}
