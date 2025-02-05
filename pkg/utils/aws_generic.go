package utils

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// TODO migrate to a stage
func CheckResourceAccessPolicy(policyOutput string) string {

	outString := "\"AccessPolicy\":{\"Statement\":["

	policyDocument, err := url.QueryUnescape(policyOutput)
	if err != nil {
		slog.Error("Could not URL decode policy document, error: " + err.Error())
		outString = "\"AccessPolicy\":null"
		return outString
	}

	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(policyDocument), &policyDoc); err != nil {
		slog.Error("Could not parse access policy," + policyOutput + ", error: " + err.Error())
	} else {
		statements, ok := policyDoc["Statement"].([]interface{})
		if ok {
			for _, stmt := range statements {
				statement, ok := stmt.(map[string]interface{})
				if !ok {
					continue
				}

				principal, ok := statement["Principal"]
				if !ok {
					slog.Error("Could not find Principal")
					continue
				}

				effect, ok := statement["Effect"]
				if !ok {
					slog.Error("Could not find Effect")
					continue
				}

				action, ok := statement["Action"]
				if !ok {
					slog.Error("Could not find Action")
					continue
				}
				var actionStr string
				switch actionValue := action.(type) {
				case string:
					actionStr = "\"" + actionValue + "\""
				case []interface{}:
					actionStr = "["
					for _, arn := range actionValue {
						if arnStr, ok := arn.(string); ok {
							actionStr = actionStr + fmt.Sprintf("\"%s\",", arnStr)
						}
					}
					actionStr = strings.TrimSuffix(actionStr, ",")
					actionStr = actionStr + "]"
				}

				var resourceStr string
				resource, ok := statement["Resource"]
				if !ok {
					slog.Debug("Could not find Resource, policy: " + policyDocument)
					resourceStr = "null"
				} else {
					switch resourceValue := resource.(type) {
					case string:
						resourceStr = "\"" + resourceValue + "\""
					case []interface{}:
						resourceStr = "["
						for _, arn := range resourceValue {
							if arnStr, ok := arn.(string); ok {
								resourceStr = resourceStr + fmt.Sprintf("\"%s\",", arnStr)
							}
						}
						resourceStr = strings.TrimSuffix(resourceStr, ",")
						resourceStr = resourceStr + "]"
					}
				}

				var conditionStr string
				condition, ok := statement["Condition"]
				if !ok {
					conditionStr = "null"
				}
				conditionVal, err := json.Marshal(condition)
				if err != nil {
					slog.Error(err.Error())
					conditionStr = "null"
				}
				conditionStr = string(conditionVal)

				switch principalValue := principal.(type) {
				case string:
					if (strings.Contains(principalValue, "*") || strings.Contains(principalValue, "root")) || strings.Contains(principalValue, "CloudFront Origin Access Identity") {
						if effectStr, ok := effect.(string); ok && effectStr == "Allow" {
							outString = outString + fmt.Sprintf("{\"Effect\":\"%s\",\"Principal\":\"%s\",\"Action\":%s,\"Resource\":%s,\"Condition\":%s},", effectStr, principalValue, actionStr, resourceStr, conditionStr)
						}
					}

				case map[string]interface{}:
					for _, p := range principalValue {
						switch pValue := p.(type) {
						// Principal is a direct string
						case string:
							if (strings.Contains(pValue, "*") || strings.Contains(pValue, "root")) || strings.Contains(pValue, "CloudFront Origin Access Identity") {
								if effectStr, ok := effect.(string); ok && effectStr == "Allow" {
									outString = outString + fmt.Sprintf("{\"Effect\":\"%s\",\"Principal\":\"%s\",\"Action\":%s,\"Resource\":%s,\"Condition\":%s},", effectStr, pValue, actionStr, resourceStr, conditionStr)
								}
							}
						// Principal is an array of ARNs
						case []interface{}:
							principalStr := "["
							for _, arn := range pValue {
								if arnStr, ok := arn.(string); ok {
									principalStr = principalStr + fmt.Sprintf("\"%s\",", arnStr)
								}
							}
							principalStr = strings.TrimSuffix(principalStr, ",")
							principalStr = principalStr + "]"

							if strings.Contains(principalStr, "*") || strings.Contains(principalStr, "root") || strings.Contains(principalStr, "CloudFront Origin Access Identity") {
								if effectStr, ok := effect.(string); ok && effectStr == "Allow" {
									outString = outString + fmt.Sprintf("{\"Effect\":\"%s\",\"Principal\":%s,\"Action\":%s,\"Resource\":%s,\"Condition\":%s},", effectStr, principalStr, actionStr, resourceStr, conditionStr)
								}
							}
						}
					}
				}
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
