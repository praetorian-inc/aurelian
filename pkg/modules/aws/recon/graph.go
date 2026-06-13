package recon

import (
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/aurelian/pkg/aws/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/aws/gaad"
	gaadpkg "github.com/praetorian-inc/aurelian/pkg/aws/iam/gaad"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcepolicies"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSGraphModule{})
}

type GraphConfig struct {
	plugin.AWSCommonRecon
	plugin.GraphOutputBase
	plugin.OrgPoliciesParam
}

// AWSGraphModule is a refactored version of AWSGraphModule.
type AWSGraphModule struct {
	GraphConfig

	log                   *plugin.Logger
	gaadData              *types.AuthorizationAccountDetails
	resourcesWithPolicies store.Map[output.AWSResource]
	ec2Instances          store.Map[output.AWSResource]
	cfnStacks             store.Map[output.AWSResource]
	batchJobDefs          store.Map[output.AWSResource]
	codeInterpreters      store.Map[output.AWSResource]
	relationships         store.Map[output.AWSIAMRelationship]
}

func (m *AWSGraphModule) ID() string                { return "graph" }
func (m *AWSGraphModule) Name() string              { return "AWS Graph Analysis" }
func (m *AWSGraphModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSGraphModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSGraphModule) OpsecLevel() string        { return "moderate" }
func (m *AWSGraphModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSGraphModule) Description() string {
	return "Collects AWS IAM data (GAAD, resources, policies), evaluates permissions, " +
		"and detects privilege escalation paths. Outputs JSON by default; use --neo4j-uri " +
		"to populate graph database with relationships."
}

func (m *AWSGraphModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
	}
}

func (m *AWSGraphModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Organizations::Account",
	}
}

func (m *AWSGraphModule) Parameters() any {
	return &m.GraphConfig
}

func (m *AWSGraphModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	m.log = cfg.Log

	if err := m.collectInputs(); err != nil {
		return fmt.Errorf("collecting inputs: %w", err)
	}

	if err := m.analyzeIAMPermissions(); err != nil {
		return fmt.Errorf("analyzing IAM permissions: %w", err)
	}

	m.emitOutputs(out)
	return nil
}

func (m *AWSGraphModule) collectInputs() error {
	policyCollector := resourcepolicies.New(m.AWSCommonRecon)
	regions := m.Regions

	var eg errgroup.Group
	m.collectAccountAuthorizationDetails(&eg, m.GraphConfig)
	m.collectResourcesWithPolicies(&eg, m.GraphConfig, policyCollector, regions)
	m.collectEC2Instances(&eg, m.GraphConfig)
	m.collectCloudFormationStacks(&eg, m.GraphConfig)
	m.collectBatchJobDefinitions(&eg, m.GraphConfig)
	m.collectCodeInterpreters(&eg, m.GraphConfig)
	if err := eg.Wait(); err != nil {
		return err
	}

	// EC2 instances carry no resource policy, so they are collected separately from
	// the policy-bearing types. Merge them into the resource set the analyzer sees
	// so instance-scoped privesc actions (ec2:ReplaceIamInstanceProfileAssociation)
	// can resolve against a concrete instance ARN.
	m.ec2Instances.Range(func(key string, r output.AWSResource) bool {
		m.resourcesWithPolicies.Set(key, r)
		return true
	})

	// CloudFormation stacks carry no resource policy either; merge them in so the
	// resource_service_role enricher can link a stack to its service role (RoleARN)
	// and the cloudformation_changeset privesc method re-points at that role.
	m.cfnStacks.Range(func(key string, r output.AWSResource) bool {
		m.resourcesWithPolicies.Set(key, r)
		return true
	})

	// Batch job definitions carry no resource policy; merge them in so the
	// resource_service_role enricher can link a job definition to its JobRoleArn /
	// ExecutionRoleArn and the batch_submit_job privesc method re-points at that role.
	m.batchJobDefs.Range(func(key string, r output.AWSResource) bool {
		m.resourcesWithPolicies.Set(key, r)
		return true
	})

	// Bedrock AgentCore code interpreters carry no resource policy; merge them in so the
	// resource_service_role enricher can link an interpreter to its ExecutionRoleArn and
	// the bedrock_access_code_interpreter privesc method re-points at that role.
	m.codeInterpreters.Range(func(key string, r output.AWSResource) bool {
		m.resourcesWithPolicies.Set(key, r)
		return true
	})

	return nil
}

func (m *AWSGraphModule) collectAccountAuthorizationDetails(eg *errgroup.Group, c GraphConfig) {
	eg.Go(func() error {
		m.log.Info("collecting account authorization details")
		g := gaad.New(c.AWSReconBase)
		gaadData, err := g.Get()
		if err != nil {
			return fmt.Errorf("collecting GAAD: %w", err)
		}
		m.log.Success("GAAD collected (account: %s, users: %d, roles: %d, groups: %d)",
			gaadData.AccountID, gaadData.Users.Len(), gaadData.Roles.Len(), gaadData.Groups.Len())
		m.gaadData = gaadData
		return nil
	})
}

func (m *AWSGraphModule) collectResourcesWithPolicies(eg *errgroup.Group, c GraphConfig, collector *resourcepolicies.ResourcePolicyCollector, resolvedRegions []string) {
	eg.Go(func() error {
		m.log.Info("enumerating cloud resources and collecting policies (%d types, %d regions)",
			len(collector.SupportedResourceTypes()), len(resolvedRegions))

		lister := enumeration.NewEnumerator(c.AWSCommonRecon)
		defer func() { _ = lister.Close() }()
		resourceTypes, err := resolveRequestedResourceTypes(c.ResourceType, collector.SupportedResourceTypes())
		if err != nil {
			return fmt.Errorf("resolving resource types: %w", err)
		}

		resourceTypePipeline := pipeline.From(resourceTypes...)
		listed := pipeline.New[output.AWSResource]()
		pipeline.Pipe(resourceTypePipeline, lister.List, listed, &pipeline.PipeOpts{
			Progress: m.log.ProgressFunc("listing resources"),
		})

		collected := pipeline.New[output.AWSResource]()
		pipeline.Pipe(listed, collector.Collect, collected)

		results := store.NewMap[output.AWSResource]()
		for r := range collected.Range() {
			key := r.ARN
			if key == "" {
				key = r.ResourceID
			}
			results.Set(key, r)
		}
		if err := collected.Wait(); err != nil {
			return fmt.Errorf("collecting resources with policies: %w", err)
		}

		m.log.Success("resources with policies collected (%d)", results.Len())
		m.resourcesWithPolicies = results
		return nil
	})
}

func (m *AWSGraphModule) collectEC2Instances(eg *errgroup.Group, c GraphConfig) {
	eg.Go(func() error {
		m.log.Info("enumerating EC2 instances")

		provider := enumeration.NewAWSConfigProvider(c.AWSCommonRecon)
		skipReport := enumeration.NewSkipReport()
		defer skipReport.LogSummary()
		instanceEnum := enumeration.NewEC2InstanceEnumerator(c.AWSCommonRecon, provider, skipReport)

		collected := pipeline.New[output.AWSResource]()
		var enumErr error
		go func() {
			defer collected.Close()
			enumErr = instanceEnum.EnumerateAll(collected)
		}()

		results := store.NewMap[output.AWSResource]()
		for r := range collected.Range() {
			results.Set(r.ARN, r)
		}
		if enumErr != nil {
			return fmt.Errorf("enumerating EC2 instances: %w", enumErr)
		}

		m.log.Success("EC2 instances collected (%d)", results.Len())
		m.ec2Instances = results
		return nil
	})
}

func (m *AWSGraphModule) collectCloudFormationStacks(eg *errgroup.Group, c GraphConfig) {
	eg.Go(func() error {
		m.log.Info("enumerating CloudFormation stacks")

		provider := enumeration.NewAWSConfigProvider(c.AWSCommonRecon)
		skipReport := enumeration.NewSkipReport()
		defer skipReport.LogSummary()
		stackEnum := enumeration.NewCloudFormationStackEnumerator(c.AWSCommonRecon, provider, skipReport)

		collected := pipeline.New[output.AWSResource]()
		var enumErr error
		go func() {
			defer collected.Close()
			enumErr = stackEnum.EnumerateAll(collected)
		}()

		results := store.NewMap[output.AWSResource]()
		for r := range collected.Range() {
			results.Set(r.ARN, r)
		}
		if enumErr != nil {
			return fmt.Errorf("enumerating CloudFormation stacks: %w", enumErr)
		}

		m.log.Success("CloudFormation stacks collected (%d)", results.Len())
		m.cfnStacks = results
		return nil
	})
}

func (m *AWSGraphModule) collectBatchJobDefinitions(eg *errgroup.Group, c GraphConfig) {
	eg.Go(func() error {
		m.log.Info("enumerating Batch job definitions")

		provider := enumeration.NewAWSConfigProvider(c.AWSCommonRecon)
		skipReport := enumeration.NewSkipReport()
		defer skipReport.LogSummary()
		jobDefEnum := enumeration.NewBatchJobDefinitionEnumerator(c.AWSCommonRecon, provider, skipReport)

		collected := pipeline.New[output.AWSResource]()
		var enumErr error
		go func() {
			defer collected.Close()
			enumErr = jobDefEnum.EnumerateAll(collected)
		}()

		results := store.NewMap[output.AWSResource]()
		for r := range collected.Range() {
			results.Set(r.ARN, r)
		}
		if enumErr != nil {
			return fmt.Errorf("enumerating Batch job definitions: %w", enumErr)
		}

		m.log.Success("Batch job definitions collected (%d)", results.Len())
		m.batchJobDefs = results
		return nil
	})
}

func (m *AWSGraphModule) collectCodeInterpreters(eg *errgroup.Group, c GraphConfig) {
	eg.Go(func() error {
		m.log.Info("enumerating Bedrock AgentCore code interpreters")

		provider := enumeration.NewAWSConfigProvider(c.AWSCommonRecon)
		skipReport := enumeration.NewSkipReport()
		defer skipReport.LogSummary()
		ciEnum := enumeration.NewBedrockCodeInterpreterEnumerator(c.AWSCommonRecon, provider, skipReport)

		collected := pipeline.New[output.AWSResource]()
		var enumErr error
		go func() {
			defer collected.Close()
			enumErr = ciEnum.EnumerateAll(collected)
		}()

		results := store.NewMap[output.AWSResource]()
		for r := range collected.Range() {
			results.Set(r.ARN, r)
		}
		if enumErr != nil {
			return fmt.Errorf("enumerating Bedrock code interpreters: %w", enumErr)
		}

		m.log.Success("Bedrock code interpreters collected (%d)", results.Len())
		m.codeInterpreters = results
		return nil
	})
}

func (m *AWSGraphModule) analyzeIAMPermissions() error {
	m.log.Info("analyzing IAM permissions")
	analyzer := gaadpkg.NewGaadAnalyzer()
	relationships, err := analyzer.Analyze(m.gaadData, m.OrgPolicies, m.resourcesWithPolicies)
	if err != nil {
		return fmt.Errorf("analyzing permissions: %w", err)
	}

	m.log.Success("IAM analysis complete (%d relationships)", relationships.Len())
	m.relationships = relationships
	return nil
}

func (m *AWSGraphModule) emitOutputs(out *pipeline.P[model.AurelianModel]) {
	gaadpkg.EmitGAADEntities(m.gaadData, m.gaadData.AccountID, func(i output.AWSIAMResource) {
		out.Send(i)
	})

	m.resourcesWithPolicies.Range(func(_ string, r output.AWSResource) bool {
		out.Send(r)
		return true
	})

	m.relationships.Range(func(_ string, r output.AWSIAMRelationship) bool {
		out.Send(r)
		return true
	})
}
