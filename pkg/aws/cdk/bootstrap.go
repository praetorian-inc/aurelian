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
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
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

func generateBootstrapRisk(role RoleInfo, info BootstrapInfo) *capmodel.Risk {
	if info.AccessDenied {
		return nil
	}
	if info.HasVersion && info.Version >= 21 {
		return nil
	}

	risk, err := NewBootstrapRisk(role, info)
	if err != nil {
		slog.Warn("build cdk bootstrap risk", "role", role.RoleName, "error", err)
		return nil
	}
	return &risk
}
