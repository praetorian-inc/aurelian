package recon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSGraphModuleRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	require.True(t, ok, "graph module should be registered")
	require.NotNil(t, mod)
}

func TestAWSGraphModuleMetadata(t *testing.T) {
	m := &AWSGraphModule{}
	assert.Equal(t, "graph", m.ID())
	assert.Equal(t, "AWS Graph Analysis", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])
}

func TestAWSGraphModuleParameters(t *testing.T) {
	m := &AWSGraphModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	// Must include Neo4j params from GraphOutputBase
	assert.True(t, paramNames["neo4j-uri"], "should have neo4j-uri param")
	assert.True(t, paramNames["neo4j-username"], "should have neo4j-username param")
	assert.True(t, paramNames["neo4j-password"], "should have neo4j-password param")

	// Must include AWS params from AWSCommonRecon
	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["regions"], "should have regions param")

	// Must include org-policies-file
	assert.True(t, paramNames["org-policies-file"], "should have org-policies-file param")

	// Must include gaad-file and offline
	assert.True(t, paramNames["gaad-file"], "should have gaad-file param")
	assert.True(t, paramNames["offline"], "should have offline param")
}

// TestEmitOutputsEmitsStructuralFacts verifies that emitOutputs emits
// StructuralFact values for collected resources that carry role references.
// This is the integration-level contract between the graph module and the
// structural facts collector: resources stored in resourcesWithPolicies
// produce structural facts in the output pipeline.
func TestEmitOutputsEmitsStructuralFacts(t *testing.T) {
	m := &AWSGraphModule{}
	m.log = plugin.NewLogger(nil, true, true)

	// Provide an empty GAAD so emitOutputs does not panic on nil.
	m.gaadData = &types.AuthorizationAccountDetails{
		AccountID: "111",
		Users:     store.NewMap[types.UserDetail](),
		Groups:    store.NewMap[types.GroupDetail](),
		Roles:     store.NewMap[types.RoleDetail](),
		Policies:  store.NewMap[types.ManagedPolicyDetail](),
	}

	// Seed the module with collected resources that carry role references.
	m.resourcesWithPolicies = store.NewMap[output.AWSResource]()
	m.resourcesWithPolicies.Set("cb", output.AWSResource{
		ResourceType: "AWS::CodeBuild::Project",
		ARN:          "arn:aws:codebuild:us-east-1:111:project/p",
		AccountRef:   "111",
		Region:       "us-east-1",
		Properties:   map[string]any{"ServiceRole": "arn:aws:iam::111:role/cb-role"},
	})
	m.resourcesWithPolicies.Set("lt", output.AWSResource{
		ResourceType: "AWS::EC2::LaunchTemplate",
		ARN:          "arn:aws:ec2:us-east-1:111:launch-template/lt-1",
		AccountRef:   "111",
		Region:       "us-east-1",
		Properties:   map[string]any{"IamInstanceProfile": "arn:aws:iam::111:instance-profile/ip"},
	})
	m.resourcesWithPolicies.Set("cfn", output.AWSResource{
		ResourceType: "AWS::CloudFormation::Stack",
		ARN:          "arn:aws:cloudformation:us-east-1:111:stack/s/g",
		AccountRef:   "111",
		Region:       "us-east-1",
		Properties:   map[string]any{"RoleARN": "arn:aws:iam::111:role/cfn-role"},
	})
	m.relationships = store.NewMap[output.AWSIAMRelationship]()

	out := pipeline.New[model.AurelianModel]()
	go func() {
		m.emitOutputs(out)
		out.Close()
	}()

	var facts []output.StructuralFact
	for result := range out.Range() {
		if f, ok := result.(output.StructuralFact); ok {
			facts = append(facts, f)
		}
	}

	require.GreaterOrEqual(t, len(facts), 3, "should emit at least 3 structural facts")

	factTypes := map[string]bool{}
	for _, f := range facts {
		factTypes[f.FactType] = true
	}
	assert.True(t, factTypes["codebuild_service_role"], "should emit codebuild_service_role fact")
	assert.True(t, factTypes["launch_template_instance_profile"], "should emit launch_template_instance_profile fact")
	assert.True(t, factTypes["cloudformation_stack_role"], "should emit cloudformation_stack_role fact")
}

func TestLoadGAADFromFile(t *testing.T) {
	gaadJSON := `{
		"accountId": "123456789012",
		"UserDetailList": [
			{"Arn": "arn:aws:iam::123456789012:user/admin", "UserName": "admin"}
		],
		"GroupDetailList": [],
		"RoleDetailList": [
			{"Arn": "arn:aws:iam::123456789012:role/test-role", "RoleName": "test-role"}
		],
		"Policies": []
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "gaad.json")
	require.NoError(t, os.WriteFile(path, []byte(gaadJSON), 0o644))

	m := &AWSGraphModule{}
	m.log = plugin.NewLogger(nil, true, true)

	err := m.loadGAADFromFile(path)
	require.NoError(t, err)
	require.NotNil(t, m.gaadData)

	assert.Equal(t, "123456789012", m.gaadData.AccountID)
	assert.Equal(t, 1, m.gaadData.Users.Len())
	assert.Equal(t, 1, m.gaadData.Roles.Len())
	assert.Equal(t, 0, m.gaadData.Groups.Len())
	assert.Equal(t, 0, m.gaadData.Policies.Len())
}

func TestLoadGAADFromFile_FileNotFound(t *testing.T) {
	m := &AWSGraphModule{}
	m.log = plugin.NewLogger(nil, true, true)

	err := m.loadGAADFromFile("/nonexistent/gaad.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading GAAD file")
}

func TestLoadGAADFromFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o644))

	m := &AWSGraphModule{}
	m.log = plugin.NewLogger(nil, true, true)

	err := m.loadGAADFromFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing GAAD file")
}

func TestCollectInputs_OfflineMode(t *testing.T) {
	gaadJSON := `{
		"accountId": "123456789012",
		"UserDetailList": [],
		"GroupDetailList": [],
		"RoleDetailList": [],
		"Policies": []
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "gaad.json")
	require.NoError(t, os.WriteFile(path, []byte(gaadJSON), 0o644))

	m := &AWSGraphModule{}
	m.log = plugin.NewLogger(nil, true, true)
	m.GraphConfig.GAADFile = path
	m.GraphConfig.Offline = true

	err := m.collectInputs()
	require.NoError(t, err)
	require.NotNil(t, m.gaadData)
	assert.Equal(t, "123456789012", m.gaadData.AccountID)
}
