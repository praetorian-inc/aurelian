package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html
type Policy struct {
	Id          string               `json:"Id,omitempty"`
	Version     string               `json:"Version"`
	Statement   *PolicyStatementList `json:"Statement"`
	ResourceARN string               `json:"ResourceARN,omitempty"`
}

func NewPolicyFromJSON(data []byte) (*Policy, error) {
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, err
	}

	if policy.Version == "" {
		return nil, fmt.Errorf("missing version in policy")
	}

	if policy.Statement == nil || len(*policy.Statement) == 0 {
		return nil, fmt.Errorf("empty statements in policy")
	}

	return &policy, nil
}

type PolicyStatementList []PolicyStatement

func (pol *PolicyStatementList) UnmarshalJSON(rawData []byte) error {
	var retSingle PolicyStatement
	var retSlice []PolicyStatement
	if err := json.Unmarshal(rawData, &retSingle); err == nil {
		*pol = append(*pol, retSingle)
		return nil
	} else if err := json.Unmarshal(rawData, &retSlice); err == nil {
		*pol = retSlice
		return nil
	} else {
		return fmt.Errorf("- Unmarshall error for DynaString type. %v", rawData)
	}
}

type PolicyStatement struct {
	Sid          string      `json:"Sid,omitempty"`
	Effect       string      `json:"Effect"`
	Principal    *Principal  `json:"Principal,omitempty"`
	Action       *DynaString `json:"Action,omitempty"`
	NotAction    *DynaString `json:"NotAction,omitempty"`
	NotPrincipal *Principal  `json:"NotPrincipal,omitempty"`
	Resource     *DynaString `json:"Resource,omitempty"`
	NotResource  *DynaString `json:"NotResource,omitempty"`
	Condition    *Condition  `json:"Condition,omitempty"`
	OriginArn    string      `json:"OriginArn,omitempty"` // Used for tracking the origin of the statement throughout evaluation
}

// Helper function to extract all principals from a statement
func (stmt *PolicyStatement) ExtractPrincipals() []string {
	principals := []string{}

	if stmt == nil || stmt.Principal == nil {
		return principals
	}

	// Extract AWS principals
	if stmt.Principal.AWS != nil {
		for _, p := range *stmt.Principal.AWS {
			if p != "" {
				principals = append(principals, p)
			}
		}
	}

	// Extract Service principals
	if stmt.Principal.Service != nil {
		for _, p := range *stmt.Principal.Service {
			if p != "" {
				principals = append(principals, p)
			}
		}
	}

	// Extract Federated principals
	if stmt.Principal.Federated != nil {
		for _, p := range *stmt.Principal.Federated {
			if p != "" {
				principals = append(principals, p)
			}
		}
	}

	// Extract CanonicalUser principals
	if stmt.Principal.CanonicalUser != nil {
		for _, p := range *stmt.Principal.CanonicalUser {
			if p != "" {
				principals = append(principals, p)
			}
		}
	}

	return principals
}

type Principal struct {
	AWS           *DynaString `json:"AWS,omitempty"`
	Service       *DynaString `json:"Service,omitempty"`
	Federated     *DynaString `json:"Federated,omitempty"`
	CanonicalUser *DynaString `json:"CanonicalUser,omitempty"`
}

func (p *Principal) UnmarshalJSON(rawData []byte) error {
	if string(rawData) == `"*"` {
		star := DynaString{"*"}

		*p = Principal{
			AWS:           &star,
			Service:       &star,
			Federated:     &star,
			CanonicalUser: &star,
		}

		return nil
	} else {
		type tmpPrincipal Principal
		var retPrincipal tmpPrincipal
		if err := json.Unmarshal(rawData, &retPrincipal); err == nil {
			*p = Principal(retPrincipal)
			return nil
		} else {
			return fmt.Errorf("- Unmarshall error for principal type. %v", rawData)
		}
	}
}

func (p *Principal) String() string {
	if p == nil {
		return "nil"
	}

	if p.AWS != nil {
		return fmt.Sprintf("AWS: %s", p.AWS.ToHumanReadable())
	}
	if p.Service != nil {
		return fmt.Sprintf("Service: %s", p.Service.ToHumanReadable())
	}
	if p.Federated != nil {
		return fmt.Sprintf("Federated: %s", p.Federated.ToHumanReadable())
	}
	if p.CanonicalUser != nil {
		return fmt.Sprintf("CanonicalUser: %s", p.CanonicalUser.ToHumanReadable())
	}
	return ""
}

type Condition map[string]ConditionStatement

type ConditionStatement map[string]DynaString

// Convert conditions to human readable format
func (cond Condition) ToHumanReadable() string {
	var result []string
	for key, statement := range cond {
		for operator, values := range statement {
			humanStatement := fmt.Sprintf("when %s %s %s", operator, convertAugmentedOperator(key), values.ToHumanReadable())
			result = append(result, humanStatement)
		}
	}
	return strings.Join(result, "\n AND ")
}

// Convert augmented operator to human readable format
func convertAugmentedOperator(operator string) string {
	if strings.HasPrefix(operator, "ForAllValues:") {
		baseOperator := strings.TrimPrefix(operator, "ForAllValues:")
		return fmt.Sprintf("for all values, %s", convertOperator(baseOperator))
	}
	if strings.HasPrefix(operator, "ForAnyValue:") {
		baseOperator := strings.TrimPrefix(operator, "ForAnyValue:")
		return fmt.Sprintf("for any value, %s", convertOperator(baseOperator))
	}
	if strings.HasSuffix(operator, "IfExists") {
		baseOperator := strings.TrimSuffix(operator, "IfExists")
		return fmt.Sprintf("if it exists, %s", convertOperator(baseOperator))
	}
	return convertOperator(operator)
}

// Convert operator to human readable format
func convertOperator(operator string) string {
	switch operator {
	case "StringEquals":
		return "string equals"
	case "StringNotEquals":
		return "string does not equal"
	case "StringEqualsIgnoreCase":
		return "string equals (case-insensitive)"
	case "StringNotEqualsIgnoreCase":
		return "string does not equal (case-insensitive)"
	case "StringLike":
		return "string matches (incl. * and ?)"
	case "StringNotLike":
		return "string does not match (incl. * and ?)"
	case "NumericEquals":
		return "equals number"
	case "NumericNotEquals":
		return "not equals number"
	case "NumericLessThan":
		return "less than number"
	case "NumericLessThanEquals":
		return "less than or equals number"
	case "NumericGreaterThan":
		return "greater than number"
	case "NumericGreaterThanEquals":
		return "greater than or equals number"
	case "Bool":
		return "is boolean"
	case "IpAddress":
		return "is IP or in IP range"
	case "NotIpAddress":
		return "is not IP or not in IP range"
	case "ArnEquals", "ArnLike":
		return "is same as ARN"
	case "ArnNotEquals", "ArnNotLike":
		return "is not same as ARN"
	case "DateEquals":
		return "is date"
	case "DateNotEquals":
		return "is not date"
	case "DateLessThan":
		return "happened before date"
	case "DateLessThanEquals":
		return "happened on or before date"
	case "DateGreaterThan":
		return "happened after date"
	case "DateGreaterThanEquals":
		return "happened on or after date"
	case "Null":
		return "for existence of"
	default:
		return operator
	}
}

type DynaString []string

// Convert DynaString to human readable format
func (dyna DynaString) ToHumanReadable() string {
	if len(dyna) == 0 {
		return "empty"
	}
	if len(dyna) == 1 {
		return dyna[0]
	}
	return fmt.Sprintf("[%s]", strings.Join(dyna, ", "))
}

// Custom unmarshall for DynaString (last step in all structs)
// func (dyna *DynaString) UnmarshalJSON(rawData []byte) error {
// 	var retString string
// 	var retSlice []string
// 	if string(rawData) == "true" || string(rawData) == "false" {
// 		*dyna = append(*dyna, string(rawData))
// 		return nil
// 	} else if err := json.Unmarshal(rawData, &retString); err == nil {
// 		*dyna = append(*dyna, retString)
// 		return nil
// 	} else if err := json.Unmarshal(rawData, &retSlice); err == nil {
// 		*dyna = retSlice
// 		return nil
// 	} else {
// 		return fmt.Errorf("- Unmarshall error for DynaString type. %v", rawData)
// 	}
// }

// Custom unmarshall for DynaString (last step in all structs)
func (dyna *DynaString) UnmarshalJSON(rawData []byte) error {
	// Try unmarshaling as a single string first
	var retString string
	if err := json.Unmarshal(rawData, &retString); err == nil {
		*dyna = append(*dyna, retString)
		return nil
	}

	// Try as string array
	var retSlice []string
	if err := json.Unmarshal(rawData, &retSlice); err == nil {
		*dyna = retSlice
		return nil
	}

	// Handle boolean special case (for policies that use true/false)
	var retBool bool
	if err := json.Unmarshal(rawData, &retBool); err == nil {
		*dyna = append(*dyna, strconv.FormatBool(retBool))
		return nil
	}

	return fmt.Errorf("unmarshal error for DynaString type: %v", rawData)
}

func NewDynaString(values []string) *DynaString {
	if values == nil {
		return nil
	}
	ds := DynaString(values)
	return &ds
}
