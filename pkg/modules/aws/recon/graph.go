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
	cfnStackSets          store.Map[output.AWSResource]
	batchJobDefs          store.Map[output.AWSResource]
	codeInterpreters      store.Map[output.AWSResource]
	codeBuildProjects     store.Map[output.AWSResource]
	glueJobs              store.Map[output.AWSResource]
	glueDevEndpoints      store.Map[output.AWSResource]
	appRunnerServices     store.Map[output.AWSResource]
	ecsTaskDefinitions    store.Map[output.AWSResource]
	ecsClusters           store.Map[output.AWSResource]
	sfnStateMachines      store.Map[output.AWSResource]
	sageMakerNotebooks    store.Map[output.AWSResource]
	lambdaFunctions       store.Map[output.AWSResource]
	launchTemplates       store.Map[output.AWSResource]
	identityPools         store.Map[output.AWSResource]
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

	// One AWSConfigProvider and one SkipReport are shared across every resource
	// enumerator below AND the resource-policy lister (via NewEnumeratorWithProvider).
	// Both are concurrency-safe (the provider guards its config cache with an
	// RWMutex+Once, the SkipReport its op slice with a mutex), so the parallel
	// enumerators can write the same instances without extra locking. This reuses a
	// single SDK config cache and yields ONE aggregated skip summary (logged below via
	// defer) instead of one per collector.
	provider := enumeration.NewAWSConfigProvider(m.AWSCommonRecon)
	skipReport := enumeration.NewSkipReport()
	// Log the aggregated summary on every exit path (including an early error return)
	// so the operator always sees which (region, service) pairs were skipped, matching
	// the prior per-collector defer behavior.
	defer skipReport.LogSummary()

	var eg errgroup.Group
	m.collectAccountAuthorizationDetails(&eg, m.GraphConfig)
	m.collectResourcesWithPolicies(&eg, m.GraphConfig, policyCollector, regions, provider, skipReport)
	m.collectEC2Instances(&eg, m.GraphConfig, provider, skipReport)
	m.collectCloudFormationStacks(&eg, m.GraphConfig, provider, skipReport)
	m.collectCloudFormationStackSets(&eg, m.GraphConfig, provider, skipReport)
	m.collectBatchJobDefinitions(&eg, m.GraphConfig, provider, skipReport)
	m.collectCodeInterpreters(&eg, m.GraphConfig, provider, skipReport)
	m.collectCodeBuildProjects(&eg, m.GraphConfig, provider, skipReport)
	m.collectGlueJobs(&eg, m.GraphConfig, provider, skipReport)
	m.collectGlueDevEndpoints(&eg, m.GraphConfig, provider, skipReport)
	m.collectAppRunnerServices(&eg, m.GraphConfig, provider, skipReport)
	m.collectECSTaskDefinitions(&eg, m.GraphConfig, provider, skipReport)
	m.collectECSClusters(&eg, m.GraphConfig, provider, skipReport)
	m.collectSFNStateMachines(&eg, m.GraphConfig, provider, skipReport)
	m.collectSageMakerNotebookInstances(&eg, m.GraphConfig, provider, skipReport)
	m.collectLambdaFunctions(&eg, m.GraphConfig, provider, skipReport)
	m.collectLaunchTemplates(&eg, m.GraphConfig, provider, skipReport)
	m.collectIdentityPools(&eg, m.GraphConfig, provider, skipReport)
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

	// These existing-compute resource types carry no resource policy; merge them in so the
	// resource_service_role enricher can link each to the service role it runs as (the role
	// ARN(s) captured in the resource's Properties) and the matching privesc method re-points
	// its CAN_PRIVESC edge at that role.
	//
	// Launch templates and Cognito identity pools also carry no resource policy: a launch
	// template links to the role its instances run as via an instance profile
	// (set_launch_template_role.yaml), and an identity pool links to its bound auth/unauth
	// role(s) (resource_service_role.yaml). Their privesc methods
	// (ec2_launch_template_version existing-template branch, cognito_set_identity_pool_roles)
	// re-point CAN_PRIVESC at those roles.
	//
	// ECS clusters are the exception: they carry NO IAM role and so emit NO HAS_ROLE edge.
	// They are merged here purely so the cluster node EXISTS as an IAM-evaluation candidate.
	// An attacker policy that scopes ecs:ExecuteCommand to a cluster ARN only yields a base
	// ECS_EXECUTECOMMAND edge when the evaluator can match that grant against a concrete
	// cluster resource; the ecs_execute_command privesc method then reaches the target via the
	// task definition's HAS_ROLE.
	for _, collected := range []store.Map[output.AWSResource]{
		m.cfnStackSets,
		m.codeBuildProjects,
		m.glueJobs,
		m.glueDevEndpoints,
		m.appRunnerServices,
		m.ecsTaskDefinitions,
		m.ecsClusters,
		m.sfnStateMachines,
		m.sageMakerNotebooks,
		m.launchTemplates,
		m.identityPools,
	} {
		collected.Range(func(key string, r output.AWSResource) bool {
			m.resourcesWithPolicies.Set(key, r)
			return true
		})
	}

	// Lambda functions are collected independently of any resource policy so plain
	// functions (no function policy) still get a node + HAS_ROLE for the
	// lambda:UpdateFunctionCode / AddPermission takeover methods. The resource-policy
	// collector already merged any policy-BEARING functions into resourcesWithPolicies,
	// so only add a function the policy collector did NOT see — never clobber a
	// policy-bearing entry (which carries ResourcePolicy) with a policy-less one.
	m.lambdaFunctions.Range(func(key string, r output.AWSResource) bool {
		if _, ok := m.resourcesWithPolicies.Get(key); !ok {
			m.resourcesWithPolicies.Set(key, r)
		}
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

func (m *AWSGraphModule) collectResourcesWithPolicies(eg *errgroup.Group, c GraphConfig, collector *resourcepolicies.ResourcePolicyCollector, resolvedRegions []string, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	eg.Go(func() error {
		m.log.Info("enumerating cloud resources and collecting policies (%d types, %d regions)",
			len(collector.SupportedResourceTypes()), len(resolvedRegions))

		// Share the run-wide provider and SkipReport so the lister's skipped ops fold
		// into the single aggregated summary collectInputs logs (the lister's Close
		// no longer logs its own summary when the report is shared; it still writes
		// the detail file).
		lister := enumeration.NewEnumeratorWithProvider(c.AWSCommonRecon, provider, skipReport)
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

// enumerateAller is the shared entry point of every resource enumerator the graph
// module drains (EC2, CloudFormation stacks/stack sets, Batch, Bedrock code
// interpreters, CodeBuild, Glue, App Runner, ECS, Step Functions, SageMaker). It lets
// collectResources drive any of them through one resilient drain.
type enumerateAller interface {
	EnumerateAll(out *pipeline.P[output.AWSResource]) error
}

// collectResources drains a single enumerator's EnumerateAll into a store keyed by ARN,
// reporting progress under label and storing the result into dst. It encapsulates the
// resilient enumerate-and-drain pattern shared by every resource collector below (each
// enumerator is per-region/per-resource resilient internally — a denied or unsupported
// region is skipped, never fatal). The shared provider and skipReport are threaded in
// from collectInputs so all collectors reuse one SDK config cache and one aggregated
// skip summary.
func (m *AWSGraphModule) collectResources(eg *errgroup.Group, c GraphConfig, label string, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport, newEnum func(plugin.AWSCommonRecon, *enumeration.AWSConfigProvider, *enumeration.SkipReport) enumerateAller, dst *store.Map[output.AWSResource]) {
	eg.Go(func() error {
		m.log.Info("enumerating %s", label)

		enum := newEnum(c.AWSCommonRecon, provider, skipReport)

		collected := pipeline.New[output.AWSResource]()
		var enumErr error
		go func() {
			defer collected.Close()
			enumErr = enum.EnumerateAll(collected)
		}()

		results := store.NewMap[output.AWSResource]()
		for r := range collected.Range() {
			results.Set(r.ARN, r)
		}
		if enumErr != nil {
			return fmt.Errorf("enumerating %s: %w", label, enumErr)
		}

		m.log.Success("%s collected (%d)", label, results.Len())
		*dst = results
		return nil
	})
}

func (m *AWSGraphModule) collectEC2Instances(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "EC2 instances", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewEC2InstanceEnumerator(o, p, s)
	}, &m.ec2Instances)
}

func (m *AWSGraphModule) collectCloudFormationStacks(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "CloudFormation stacks", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewCloudFormationStackEnumerator(o, p, s)
	}, &m.cfnStacks)
}

func (m *AWSGraphModule) collectBatchJobDefinitions(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "Batch job definitions", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewBatchJobDefinitionEnumerator(o, p, s)
	}, &m.batchJobDefs)
}

func (m *AWSGraphModule) collectCodeInterpreters(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "Bedrock AgentCore code interpreters", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewBedrockCodeInterpreterEnumerator(o, p, s)
	}, &m.codeInterpreters)
}

func (m *AWSGraphModule) collectCloudFormationStackSets(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "CloudFormation stack sets", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewCloudFormationStackSetEnumerator(o, p, s)
	}, &m.cfnStackSets)
}

func (m *AWSGraphModule) collectCodeBuildProjects(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "CodeBuild projects", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewCodeBuildProjectEnumerator(o, p, s)
	}, &m.codeBuildProjects)
}

func (m *AWSGraphModule) collectGlueJobs(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "Glue jobs", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewGlueJobEnumerator(o, p, s)
	}, &m.glueJobs)
}

func (m *AWSGraphModule) collectGlueDevEndpoints(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "Glue dev endpoints", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewGlueDevEndpointEnumerator(o, p, s)
	}, &m.glueDevEndpoints)
}

func (m *AWSGraphModule) collectAppRunnerServices(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "App Runner services", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewAppRunnerServiceEnumerator(o, p, s)
	}, &m.appRunnerServices)
}

func (m *AWSGraphModule) collectECSTaskDefinitions(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "ECS task definitions", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewECSTaskDefinitionEnumerator(o, p, s)
	}, &m.ecsTaskDefinitions)
}

func (m *AWSGraphModule) collectECSClusters(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "ECS clusters", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewECSClusterEnumerator(o, p, s)
	}, &m.ecsClusters)
}

func (m *AWSGraphModule) collectSFNStateMachines(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "Step Functions state machines", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewSFNStateMachineEnumerator(o, p, s)
	}, &m.sfnStateMachines)
}

func (m *AWSGraphModule) collectSageMakerNotebookInstances(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "SageMaker notebook instances", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewSageMakerNotebookInstanceEnumerator(o, p, s)
	}, &m.sageMakerNotebooks)
}

func (m *AWSGraphModule) collectLambdaFunctions(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "Lambda functions", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewLambdaFunctionEnumerator(o, p, s)
	}, &m.lambdaFunctions)
}

func (m *AWSGraphModule) collectLaunchTemplates(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "EC2 launch templates", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewEC2LaunchTemplateEnumerator(o, p, s)
	}, &m.launchTemplates)
}

func (m *AWSGraphModule) collectIdentityPools(eg *errgroup.Group, c GraphConfig, provider *enumeration.AWSConfigProvider, skipReport *enumeration.SkipReport) {
	m.collectResources(eg, c, "Cognito identity pools", provider, skipReport, func(o plugin.AWSCommonRecon, p *enumeration.AWSConfigProvider, s *enumeration.SkipReport) enumerateAller {
		return enumeration.NewCognitoIdentityPoolEnumerator(o, p, s)
	}, &m.identityPools)
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

	// Emit collected resources as AWSIAMResource (with empty IAM fields). The live neo4j
	// load path (plugin.GraphFormatter.Format) type-switches results into nodes only on
	// `case output.AWSIAMResource`; a plain output.AWSResource does NOT match that case
	// (Go type switches are exact, not embedded-aware), so every collected compute
	// resource — AppRunner/Batch/Bedrock and the rest, each carrying its role ARN in
	// Properties — was silently dropped before CreateNodes, leaving resource_service_role /
	// resource_to_role with no node to attach a HAS_ROLE edge to. Wrapping here keeps the
	// JSON output identical (omitempty IAM fields) while ensuring the nodes load.
	m.resourcesWithPolicies.Range(func(_ string, r output.AWSResource) bool {
		out.Send(output.FromAWSResource(r))
		return true
	})

	m.relationships.Range(func(_ string, r output.AWSIAMRelationship) bool {
		out.Send(r)
		return true
	})
}
