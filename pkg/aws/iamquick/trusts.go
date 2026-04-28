package iamquick

import (
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// analyzeTrusts scans all roles for trust relationships and emits findings.
func (a *Analyzer) analyzeTrusts(out *pipeline.P[model.AurelianModel]) {
	a.gaad.Roles.Range(func(_ string, role types.RoleDetail) bool {
		if role.AssumeRolePolicyDocument.Statement == nil {
			return true
		}
		for _, stmt := range *role.AssumeRolePolicyDocument.Statement {
			if stmt.Effect != "Allow" {
				continue
			}
			conditions := formatConditions(stmt.Condition)
			a.emitRootTrusts(role, stmt, conditions, out)
			a.emitFederatedTrusts(role, stmt, conditions, out)
			a.emitServiceTrusts(role, stmt, conditions, out)
			a.emitPrincipalTrusts(role, stmt, conditions, out)
		}
		return true
	})
}

func (a *Analyzer) emitRootTrusts(
	role types.RoleDetail,
	stmt types.PolicyStatement,
	conditions string,
	out *pipeline.P[model.AurelianModel],
) {
	if stmt.Principal != nil && stmt.Principal.AWS != nil {
		for _, principal := range *stmt.Principal.AWS {
			if isRootPrincipal(principal) {
				a.emitTrustFinding(role.Arn, "root-trust", extractAccount(principal), conditions, out)
			}
		}
	}
	// NotPrincipal with Allow: if root is not excluded, it's implicitly allowed
	if stmt.NotPrincipal != nil && stmt.NotPrincipal.AWS != nil {
		rootExcluded := false
		for _, principal := range *stmt.NotPrincipal.AWS {
			if isRootPrincipal(principal) {
				rootExcluded = true
				break
			}
		}
		if !rootExcluded {
			a.emitTrustFinding(role.Arn, "root-trust", "Any Account (via NotPrincipal)", conditions, out)
		}
	}
}

func (a *Analyzer) emitFederatedTrusts(
	role types.RoleDetail,
	stmt types.PolicyStatement,
	conditions string,
	out *pipeline.P[model.AurelianModel],
) {
	if stmt.Principal != nil && stmt.Principal.Federated != nil {
		for _, provider := range *stmt.Principal.Federated {
			a.emitTrustFinding(role.Arn, "federated-trust", provider, conditions, out)
		}
	}
	if stmt.NotPrincipal != nil && stmt.NotPrincipal.Federated != nil {
		for _, provider := range *stmt.NotPrincipal.Federated {
			a.emitTrustFinding(role.Arn, "federated-trust", "All except: "+provider, conditions, out)
		}
	}
}

func (a *Analyzer) emitServiceTrusts(
	role types.RoleDetail,
	stmt types.PolicyStatement,
	conditions string,
	out *pipeline.P[model.AurelianModel],
) {
	if stmt.Principal != nil {
		if stmt.Principal.Service != nil {
			for _, service := range *stmt.Principal.Service {
				a.emitTrustFinding(role.Arn, "service-trust", cleanServiceName(service), conditions, out)
			}
		}
		// AWS principals that are service-linked roles
		if stmt.Principal.AWS != nil {
			for _, principal := range *stmt.Principal.AWS {
				if strings.Contains(principal, ":aws-service-role/") {
					a.emitTrustFinding(role.Arn, "service-trust", extractServiceFromARN(principal), conditions, out)
				}
			}
		}
	}
	if stmt.NotPrincipal != nil && stmt.NotPrincipal.Service != nil {
		allServices := "All services except: " + strings.Join(*stmt.NotPrincipal.Service, ", ")
		a.emitTrustFinding(role.Arn, "service-trust", allServices, conditions, out)
	}
}

func (a *Analyzer) emitPrincipalTrusts(
	role types.RoleDetail,
	stmt types.PolicyStatement,
	conditions string,
	out *pipeline.P[model.AurelianModel],
) {
	if stmt.Principal != nil && stmt.Principal.AWS != nil {
		for _, principal := range *stmt.Principal.AWS {
			if strings.Contains(principal, ":aws-service-role/") || strings.Contains(principal, ".amazonaws.com") {
				continue
			}
			if isRootPrincipal(principal) {
				continue
			}
			pType := getPrincipalType(principal)
			if pType != "" {
				a.emitTrustFinding(role.Arn, "principal-trust:"+pType, principal, conditions, out)
			}
		}
	}
	if stmt.NotPrincipal != nil && stmt.NotPrincipal.AWS != nil {
		for _, pa := range analyzePotentialAccess(*stmt.NotPrincipal.AWS) {
			a.emitTrustFinding(role.Arn, "principal-trust:NotPrincipal", pa, conditions, out)
		}
	}
}

func (a *Analyzer) emitTrustFinding(
	roleARN, trustType, trusted, conditions string,
	out *pipeline.P[model.AurelianModel],
) {
	out.Send(output.AWSResource{
		ResourceType: "AWS::IAM::Role",
		ResourceID:   roleARN,
		ARN:          roleARN,
		AccountRef:   a.gaad.AccountID,
		Properties: map[string]any{
			"finding_type": "trust",
			"trust_type":   trustType,
			"trusted":      trusted,
			"conditions":   conditions,
		},
	})
}

// isRootPrincipal checks if a principal represents a root account.
func isRootPrincipal(principal string) bool {
	return strings.HasSuffix(principal, ":root") || strings.Count(principal, ":") == 1
}

// extractAccount extracts the account identifier from a principal ARN.
func extractAccount(principal string) string {
	parts := strings.Split(principal, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return principal
}

// cleanServiceName removes .amazonaws.com suffix and regional prefixes.
func cleanServiceName(service string) string {
	service = strings.TrimSuffix(service, ".amazonaws.com")
	if parts := strings.Split(service, "."); len(parts) > 1 {
		service = parts[len(parts)-1]
	}
	if parts := strings.Split(service, ":"); len(parts) > 1 {
		service = parts[len(parts)-1]
	}
	return service
}

// extractServiceFromARN extracts the service name from an aws-service-role ARN.
func extractServiceFromARN(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[1]
	}
	return arn
}

// getPrincipalType determines the IAM principal type from its ARN.
func getPrincipalType(principal string) string {
	parts := strings.Split(principal, ":")
	if len(parts) != 6 {
		return ""
	}
	resourceParts := strings.SplitN(parts[5], "/", 2)
	if len(resourceParts) < 2 {
		return ""
	}
	switch resourceParts[0] {
	case "user":
		return "IAM User"
	case "role":
		return "IAM Role"
	case "group":
		return "IAM Group"
	}
	return ""
}

// analyzePotentialAccess checks what access is implicitly allowed via NotPrincipal.
func analyzePotentialAccess(notPrincipals types.DynaString) []string {
	var potential []string
	rootDenied := false
	userDenied := false
	roleDenied := false
	for _, p := range notPrincipals {
		if isRootPrincipal(p) {
			rootDenied = true
		}
		if strings.Contains(p, ":user/*") {
			userDenied = true
		}
		if strings.Contains(p, ":role/*") {
			roleDenied = true
		}
	}
	if !rootDenied {
		potential = append(potential, "*:root")
	}
	if !userDenied {
		potential = append(potential, "*:user/*")
	}
	if !roleDenied {
		potential = append(potential, "*:role/*")
	}
	return potential
}

// formatConditions converts policy conditions to a human-readable string.
func formatConditions(cond *types.Condition) string {
	if cond == nil {
		return "None"
	}
	return cond.ToHumanReadable()
}
