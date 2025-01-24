package utils

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/serverlessapplicationrepository/types"
)

func CheckServerlessRepoAppResourceAccessPolicy(statements []types.ApplicationPolicyStatement) string {
	outString := "\"AccessPolicy\":{\"Statement\":["

	for _, statement := range statements {
		statementBytes, err := json.Marshal(statement)
		if err != nil {
			slog.Error("Could not marshal serverless repo application")
			continue
		}

		statementStr := string(statementBytes)
		lastBracketIndex := strings.LastIndex(statementStr, "}")
		newStatementStr := statementStr[:lastBracketIndex] + ",\"Effect\":\"Allow\"}"

		if len(statement.PrincipalOrgIDs) > 0 {
			outString = outString + string(newStatementStr) + ","
			continue
		}

		for _, principal := range statement.Principals {
			if strings.Contains(principal, "*") || strings.Contains(principal, "root") {
				outString = outString + string(newStatementStr) + ","
				break
			}
		}
	}

	if outString == "\"AccessPolicy\":{\"Statement\":[" {
		outString = "\"AccessPolicy\":null"
	} else {
		outString = strings.TrimSuffix(outString, ",")
		outString = outString + "]}"
	}
	return outString
}
