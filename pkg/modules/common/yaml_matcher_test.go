package common_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/modules/common"
	"github.com/stretchr/testify/assert"
)

func TestMatchEquals(t *testing.T) {
	properties := map[string]any{
		"AuthType": "NONE",
		"Count":    42,
	}

	// String equality
	condition := common.MatchCondition{Field: "AuthType", Equals: "NONE"}
	assert.True(t, common.EvaluateCondition(condition, properties))

	condition = common.MatchCondition{Field: "AuthType", Equals: "AWS_IAM"}
	assert.False(t, common.EvaluateCondition(condition, properties))

	// Numeric equality
	condition = common.MatchCondition{Field: "Count", Equals: 42}
	assert.True(t, common.EvaluateCondition(condition, properties))
}

func TestMatchNotEquals(t *testing.T) {
	properties := map[string]any{"Status": "ENABLED"}

	condition := common.MatchCondition{Field: "Status", NotEquals: "DISABLED"}
	assert.True(t, common.EvaluateCondition(condition, properties))

	condition = common.MatchCondition{Field: "Status", NotEquals: "ENABLED"}
	assert.False(t, common.EvaluateCondition(condition, properties))
}

func TestMatchExists(t *testing.T) {
	properties := map[string]any{
		"FunctionUrl": "https://abc123.lambda-url.us-east-1.on.aws/",
	}

	// Exists: true (property present)
	existsTrue := true
	condition := common.MatchCondition{Field: "FunctionUrl", Exists: &existsTrue}
	assert.True(t, common.EvaluateCondition(condition, properties))

	// Exists: false (property absent)
	existsFalse := false
	condition = common.MatchCondition{Field: "MissingProperty", Exists: &existsFalse}
	assert.True(t, common.EvaluateCondition(condition, properties))

	condition = common.MatchCondition{Field: "FunctionUrl", Exists: &existsFalse}
	assert.False(t, common.EvaluateCondition(condition, properties))
}

func TestMatchContains(t *testing.T) {
	properties := map[string]any{
		"Description": "This is a public bucket",
		"Tags":        []string{"production", "public", "backup"},
	}

	// Substring match
	condition := common.MatchCondition{Field: "Description", Contains: "public"}
	assert.True(t, common.EvaluateCondition(condition, properties))

	condition = common.MatchCondition{Field: "Description", Contains: "private"}
	assert.False(t, common.EvaluateCondition(condition, properties))

	// List membership (future enhancement - start with substring only)
	condition = common.MatchCondition{Field: "Tags", Contains: "public"}
	assert.True(t, common.EvaluateCondition(condition, properties))
}

func TestMatchRegex(t *testing.T) {
	properties := map[string]any{
		"CidrBlock": "0.0.0.0/0",
		"Email":     "user@example.com",
	}

	// Pattern match
	condition := common.MatchCondition{Field: "CidrBlock", Regex: `^0\.0\.0\.0`}
	assert.True(t, common.EvaluateCondition(condition, properties))

	condition = common.MatchCondition{Field: "Email", Regex: `@example\.com$`}
	assert.True(t, common.EvaluateCondition(condition, properties))

	condition = common.MatchCondition{Field: "CidrBlock", Regex: `^10\.`}
	assert.False(t, common.EvaluateCondition(condition, properties))
}

func TestMatchGreaterThan(t *testing.T) {
	properties := map[string]any{
		"MaxAge": 90,
		"Score":  95.5,
	}

	condition := common.MatchCondition{Field: "MaxAge", GreaterThan: 30}
	assert.True(t, common.EvaluateCondition(condition, properties))

	condition = common.MatchCondition{Field: "MaxAge", GreaterThan: 100}
	assert.False(t, common.EvaluateCondition(condition, properties))

	// Float comparison
	condition = common.MatchCondition{Field: "Score", GreaterThan: 90.0}
	assert.True(t, common.EvaluateCondition(condition, properties))
}

func TestMatchAll(t *testing.T) {
	properties := map[string]any{
		"FunctionUrl":         "https://abc123.lambda-url.us-east-1.on.aws/",
		"FunctionUrlAuthType": "NONE",
	}

	existsTrue := true
	conditions := []common.MatchCondition{
		{Field: "FunctionUrl", Exists: &existsTrue},
		{Field: "FunctionUrlAuthType", Equals: "NONE"},
	}

	// All conditions match
	assert.True(t, common.MatchAll(conditions, properties))

	// One condition fails
	conditions[1].Equals = "AWS_IAM"
	assert.False(t, common.MatchAll(conditions, properties))
}
