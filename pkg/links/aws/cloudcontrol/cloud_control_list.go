package cloudcontrol

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type AWSCloudControl struct {
	*base.AwsReconLink
	semaphores          map[string]chan struct{}
	wg                  sync.WaitGroup
	cloudControlClients map[string]*cloudcontrol.Client
}

func (a *AWSCloudControl) Metadata() *cfg.Metadata {
	return &cfg.Metadata{Name: "AWS CloudControl"}
}

func (a *AWSCloudControl) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	params = append(params, options.AwsRegions(), options.AwsResourceType())

	return params
}

func NewAWSCloudControl(configs ...cfg.Config) chain.Link {
	cc := &AWSCloudControl{
		wg: sync.WaitGroup{},
	}
	cc.AwsReconLink = base.NewAwsReconLink(cc, configs...)

	return cc
}

func (a *AWSCloudControl) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		return err
	}

	a.initializeClients()
	a.initializeSemaphores()
	return nil
}

func (a *AWSCloudControl) initializeSemaphores() {
	a.semaphores = make(map[string]chan struct{})
	for _, region := range a.Regions {
		a.semaphores[region] = make(chan struct{}, 5)
	}
}

func (a *AWSCloudControl) initializeClients() error {
	a.cloudControlClients = make(map[string]*cloudcontrol.Client)

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			return fmt.Errorf("failed to create AWS config: %w", err)
		}

		a.cloudControlClients[region] = cloudcontrol.NewFromConfig(config)
	}

	return nil
}

func (a *AWSCloudControl) Process(resourceType model.CloudResourceType) error {
	for _, region := range a.Regions {
		if a.isGlobalService(resourceType.String(), region) {
			slog.Debug("Skipping global service", "type", resourceType, "region", region)
			continue
		}

		a.wg.Add(1)
		go a.listResourcesInRegion(resourceType.String(), region)
	}

	a.wg.Wait()
	slog.Debug("cloudcontrol complete")
	return nil
}

func (a *AWSCloudControl) isGlobalService(resourceType, region string) bool {
	return helpers.IsGlobalService(resourceType) && region != "us-east-1"
}

func (a *AWSCloudControl) listResourcesInRegion(resourceType, region string) {
	defer a.wg.Done()

	message.Info("Listing %s resources in %s (profile: %s)", resourceType, region, a.Profile)
	slog.Debug("Listing resources in region", "type", resourceType, "region", region, "profile", a.Profile)

	config, err := a.GetConfigWithRuntimeArgs(region)

	if err != nil {
		slog.Error("Failed to create AWS config", "error", err)
		return
	}

	accountId, err := helpers.GetAccountId(config)
	if err != nil {
		slog.Error("Failed to get account ID", "error", err, "region", region)
		return
	}

	cc := a.cloudControlClients[region]

	paginator := cloudcontrol.NewListResourcesPaginator(cc, &cloudcontrol.ListResourcesInput{
		TypeName:   &resourceType,
		MaxResults: aws.Int32(100),
	})

	for paginator.HasMorePages() {
		res, err := paginator.NextPage(a.Context())

		if err != nil {
			err, shouldBreak := a.processError(resourceType, region, err)
			if err != nil {
				slog.Error("Failed to list resources", "error", err)
				return
			}

			if shouldBreak {
				break
			}
		}

		for _, resource := range res.ResourceDescriptions {
			erd := a.resourceDescriptionToERD(resource, resourceType, accountId, region)
			a.sendResource(region, erd)
		}

	}
}

func (a *AWSCloudControl) processError(resourceType, region string, err error) (error, bool) {
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "TypeNotFoundException"):
		return fmt.Errorf("%s is not available in region %s", resourceType, region), true

	case strings.Contains(errMsg, "is not authorized to perform") || strings.Contains(errMsg, "AccessDeniedException"):
		return fmt.Errorf("access denied to list resources of type %s in region %s: %s", resourceType, region, errMsg), true

	case strings.Contains(errMsg, "UnsupportedActionException"):
		return fmt.Errorf("the type %s is not supported in region %s", resourceType, region), true

	case strings.Contains(errMsg, "ThrottlingException"):
		// Log throttling but don't terminate - let AWS SDK retry with backoff
		return fmt.Errorf("rate limited: %s", errMsg), false

	default:
		return fmt.Errorf("failed to ListResources of type %s in region %s: %w", resourceType, region, err), false
	}
}

func (a *AWSCloudControl) resourceDescriptionToERD(resource cctypes.ResourceDescription, rType, accountId, region string) *types.EnrichedResourceDescription {
	var erdRegion string
	if helpers.IsGlobalService(rType) {
		erdRegion = ""
	} else {
		erdRegion = region
	}

	erd := types.NewEnrichedResourceDescription(
		*resource.Identifier,
		rType,
		erdRegion,
		accountId,
		*resource.Properties,
	)

	return &erd

}

func (a *AWSCloudControl) sendResource(region string, resource *types.EnrichedResourceDescription) {
	sem := a.semaphores[region]
	sem <- struct{}{}

	defer func() { <-sem }()

	a.Send(resource)
}

func (a *AWSCloudControl) Complete() error {
	a.wg.Wait()
	return nil
}

func (a *AWSCloudControl) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.CloudResourceType("AWS::AccessAnalyzer::Analyzer"),
		model.CloudResourceType("AWS::ACMPCA::CertificateAuthority"),
		model.CloudResourceType("AWS::Amplify::App"),
		model.CloudResourceType("AWS::ApiGateway::ApiKey"),
		model.CloudResourceType("AWS::ApiGateway::ClientCertificate"),
		model.CloudResourceType("AWS::ApiGateway::DomainName"),
		model.AWSGateway,
		model.CloudResourceType("AWS::ApiGateway::UsagePlan"),
		model.CloudResourceType("AWS::ApiGateway::VpcLink"),
		model.CloudResourceType("AWS::ApiGatewayV2::Api"),
		model.CloudResourceType("AWS::ApiGatewayV2::DomainName"),
		model.CloudResourceType("AWS::ApiGatewayV2::VpcLink"),
		model.CloudResourceType("AWS::AppConfig::Application"),
		model.CloudResourceType("AWS::AppConfig::DeploymentStrategy"),
		model.CloudResourceType("AWS::AppConfig::Extension"),
		model.CloudResourceType("AWS::AppConfig::ExtensionAssociation"),
		model.CloudResourceType("AWS::AppFlow::Connector"),
		model.CloudResourceType("AWS::AppFlow::ConnectorProfile"),
		model.CloudResourceType("AWS::AppFlow::Flow"),
		model.CloudResourceType("AWS::AppIntegrations::Application"),
		model.CloudResourceType("AWS::AppIntegrations::DataIntegration"),
		model.CloudResourceType("AWS::AppIntegrations::EventIntegration"),
		model.CloudResourceType("AWS::ApplicationInsights::Application"),
		model.CloudResourceType("AWS::ApplicationSignals::ServiceLevelObjective"),
		model.CloudResourceType("AWS::AppRunner::AutoScalingConfiguration"),
		model.CloudResourceType("AWS::AppRunner::ObservabilityConfiguration"),
		model.CloudResourceType("AWS::AppRunner::Service"),
		model.CloudResourceType("AWS::AppRunner::VpcConnector"),
		model.CloudResourceType("AWS::AppRunner::VpcIngressConnection"),
		model.CloudResourceType("AWS::AppStream::AppBlockBuilder"),
		model.CloudResourceType("AWS::AppSync::Api"),
		model.CloudResourceType("AWS::AppSync::DomainName"),
		model.CloudResourceType("AWS::AppTest::TestCase"),
		model.CloudResourceType("AWS::APS::Scraper"),
		model.CloudResourceType("AWS::APS::Workspace"),
		model.CloudResourceType("AWS::ARCZonalShift::AutoshiftObserverNotificationStatus"),
		model.CloudResourceType("AWS::ARCZonalShift::ZonalAutoshiftConfiguration"),
		model.CloudResourceType("AWS::Athena::CapacityReservation"),
		model.CloudResourceType("AWS::Athena::DataCatalog"),
		model.CloudResourceType("AWS::Athena::NamedQuery"),
		model.CloudResourceType("AWS::Athena::WorkGroup"),
		model.CloudResourceType("AWS::AutoScaling::AutoScalingGroup"),
		model.CloudResourceType("AWS::AutoScaling::LaunchConfiguration"),
		model.CloudResourceType("AWS::AutoScaling::ScalingPolicy"),
		model.CloudResourceType("AWS::AutoScaling::ScheduledAction"),
		model.CloudResourceType("AWS::B2BI::Capability"),
		model.CloudResourceType("AWS::B2BI::Partnership"),
		model.CloudResourceType("AWS::B2BI::Profile"),
		model.CloudResourceType("AWS::B2BI::Transformer"),
		model.CloudResourceType("AWS::Backup::BackupPlan"),
		model.CloudResourceType("AWS::Backup::BackupSelection"),
		model.CloudResourceType("AWS::Backup::BackupVault"),
		model.CloudResourceType("AWS::Backup::Framework"),
		model.CloudResourceType("AWS::Backup::LogicallyAirGappedBackupVault"),
		model.CloudResourceType("AWS::Backup::ReportPlan"),
		model.CloudResourceType("AWS::Backup::RestoreTestingPlan"),
		model.CloudResourceType("AWS::Backup::RestoreTestingSelection"),
		model.CloudResourceType("AWS::BackupGateway::Hypervisor"),
		model.CloudResourceType("AWS::Batch::ComputeEnvironment"),
		model.CloudResourceType("AWS::Batch::JobQueue"),
		model.CloudResourceType("AWS::Batch::SchedulingPolicy"),
		model.CloudResourceType("AWS::BCMDataExports::Export"),
		model.CloudResourceType("AWS::Bedrock::Agent"),
		model.CloudResourceType("AWS::Bedrock::ApplicationInferenceProfile"),
		model.CloudResourceType("AWS::Bedrock::Flow"),
		model.CloudResourceType("AWS::Bedrock::Guardrail"),
		model.CloudResourceType("AWS::Bedrock::KnowledgeBase"),
		model.CloudResourceType("AWS::Bedrock::Prompt"),
		model.CloudResourceType("AWS::Budgets::BudgetsAction"),
		model.CloudResourceType("AWS::Cassandra::Keyspace"),
		model.CloudResourceType("AWS::Cassandra::Table"),
		model.CloudResourceType("AWS::CE::AnomalyMonitor"),
		model.CloudResourceType("AWS::CE::AnomalySubscription"),
		model.CloudResourceType("AWS::Chatbot::MicrosoftTeamsChannelConfiguration"),
		model.CloudResourceType("AWS::Chatbot::SlackChannelConfiguration"),
		model.CloudResourceType("AWS::CleanRooms::Collaboration"),
		model.CloudResourceType("AWS::CleanRooms::ConfiguredTable"),
		model.CloudResourceType("AWS::CleanRooms::Membership"),
		model.CloudResourceType("AWS::CleanRoomsML::TrainingDataset"),
		model.CloudResourceType("AWS::CloudFormation::GuardHook"),
		model.CloudResourceType("AWS::CloudFormation::HookDefaultVersion"),
		model.CloudResourceType("AWS::CloudFormation::HookTypeConfig"),
		model.CloudResourceType("AWS::CloudFormation::HookVersion"),
		model.CloudResourceType("AWS::CloudFormation::LambdaHook"),
		model.CloudResourceType("AWS::CloudFormation::ModuleDefaultVersion"),
		model.CloudResourceType("AWS::CloudFormation::PublicTypeVersion"),
		model.AWSCloudFormationStack,
		model.CloudResourceType("AWS::CloudFormation::StackSet"),
		model.CloudResourceType("AWS::CloudFormation::TypeActivation"),
		model.CloudResourceType("AWS::CloudFront::CachePolicy"),
		model.CloudResourceType("AWS::CloudFront::CloudFrontOriginAccessIdentity"),
		model.CloudResourceType("AWS::CloudFront::ContinuousDeploymentPolicy"),
		model.CloudResourceType("AWS::CloudFront::Distribution"),
		model.CloudResourceType("AWS::CloudFront::Function"),
		model.CloudResourceType("AWS::CloudFront::KeyGroup"),
		model.CloudResourceType("AWS::CloudFront::KeyValueStore"),
		model.CloudResourceType("AWS::CloudFront::OriginAccessControl"),
		model.CloudResourceType("AWS::CloudFront::OriginRequestPolicy"),
		model.CloudResourceType("AWS::CloudFront::PublicKey"),
		model.CloudResourceType("AWS::CloudFront::RealtimeLogConfig"),
		model.CloudResourceType("AWS::CloudFront::ResponseHeadersPolicy"),
		model.CloudResourceType("AWS::CloudTrail::Channel"),
		model.CloudResourceType("AWS::CloudTrail::EventDataStore"),
		model.CloudResourceType("AWS::CloudTrail::Trail"),
		model.CloudResourceType("AWS::CloudWatch::Alarm"),
		model.CloudResourceType("AWS::CloudWatch::CompositeAlarm"),
		model.CloudResourceType("AWS::CloudWatch::Dashboard"),
		model.CloudResourceType("AWS::CloudWatch::MetricStream"),
		model.CloudResourceType("AWS::CodeArtifact::Domain"),
		model.CloudResourceType("AWS::CodeArtifact::Repository"),
		model.CloudResourceType("AWS::CodeBuild::Fleet"),
		model.CloudResourceType("AWS::CodeConnections::Connection"),
		model.CloudResourceType("AWS::CodeDeploy::Application"),
		model.CloudResourceType("AWS::CodeDeploy::DeploymentConfig"),
		model.CloudResourceType("AWS::CodeGuruProfiler::ProfilingGroup"),
		model.CloudResourceType("AWS::CodeGuruReviewer::RepositoryAssociation"),
		model.CloudResourceType("AWS::CodePipeline::CustomActionType"),
		model.CloudResourceType("AWS::CodePipeline::Pipeline"),
		model.CloudResourceType("AWS::CodeStarConnections::Connection"),
		model.CloudResourceType("AWS::CodeStarConnections::RepositoryLink"),
		model.CloudResourceType("AWS::CodeStarConnections::SyncConfiguration"),
		model.CloudResourceType("AWS::CodeStarNotifications::NotificationRule"),
		model.CloudResourceType("AWS::Cognito::IdentityPool"),
		model.CloudResourceType("AWS::Cognito::UserPool"),
		model.CloudResourceType("AWS::Comprehend::DocumentClassifier"),
		model.CloudResourceType("AWS::Comprehend::Flywheel"),
		model.CloudResourceType("AWS::Config::AggregationAuthorization"),
		model.CloudResourceType("AWS::Config::ConfigRule"),
		model.CloudResourceType("AWS::Config::ConfigurationAggregator"),
		model.CloudResourceType("AWS::Config::ConformancePack"),
		model.CloudResourceType("AWS::Config::OrganizationConformancePack"),
		model.CloudResourceType("AWS::Config::StoredQuery"),
		model.CloudResourceType("AWS::Connect::Instance"),
		model.CloudResourceType("AWS::Connect::TrafficDistributionGroup"),
		model.CloudResourceType("AWS::ConnectCampaigns::Campaign"),
		model.CloudResourceType("AWS::ControlTower::LandingZone"),
		model.CloudResourceType("AWS::CUR::ReportDefinition"),
		model.CloudResourceType("AWS::DataBrew::Dataset"),
		model.CloudResourceType("AWS::DataBrew::Job"),
		model.CloudResourceType("AWS::DataBrew::Project"),
		model.CloudResourceType("AWS::DataBrew::Recipe"),
		model.CloudResourceType("AWS::DataBrew::Ruleset"),
		model.CloudResourceType("AWS::DataBrew::Schedule"),
		model.CloudResourceType("AWS::DataSync::Agent"),
		model.CloudResourceType("AWS::DataSync::LocationAzureBlob"),
		model.CloudResourceType("AWS::DataSync::LocationEFS"),
		model.CloudResourceType("AWS::DataSync::LocationFSxLustre"),
		model.CloudResourceType("AWS::DataSync::LocationFSxONTAP"),
		model.CloudResourceType("AWS::DataSync::LocationFSxOpenZFS"),
		model.CloudResourceType("AWS::DataSync::LocationFSxWindows"),
		model.CloudResourceType("AWS::DataSync::LocationHDFS"),
		model.CloudResourceType("AWS::DataSync::LocationNFS"),
		model.CloudResourceType("AWS::DataSync::LocationObjectStorage"),
		model.CloudResourceType("AWS::DataSync::LocationS3"),
		model.CloudResourceType("AWS::DataSync::LocationSMB"),
		model.CloudResourceType("AWS::DataSync::StorageSystem"),
		model.CloudResourceType("AWS::DataSync::Task"),
		model.CloudResourceType("AWS::DataZone::Domain"),
		model.CloudResourceType("AWS::Deadline::Farm"),
		model.CloudResourceType("AWS::Deadline::LicenseEndpoint"),
		model.CloudResourceType("AWS::Deadline::Monitor"),
		model.CloudResourceType("AWS::Detective::Graph"),
		model.CloudResourceType("AWS::Detective::MemberInvitation"),
		model.CloudResourceType("AWS::DeviceFarm::InstanceProfile"),
		model.CloudResourceType("AWS::DeviceFarm::Project"),
		model.CloudResourceType("AWS::DeviceFarm::TestGridProject"),
		model.CloudResourceType("AWS::DevOpsGuru::LogAnomalyDetectionIntegration"),
		model.CloudResourceType("AWS::DevOpsGuru::NotificationChannel"),
		model.CloudResourceType("AWS::DevOpsGuru::ResourceCollection"),
		model.CloudResourceType("AWS::DMS::DataMigration"),
		model.CloudResourceType("AWS::DMS::DataProvider"),
		model.CloudResourceType("AWS::DMS::InstanceProfile"),
		model.CloudResourceType("AWS::DMS::MigrationProject"),
		model.CloudResourceType("AWS::DMS::ReplicationConfig"),
		model.CloudResourceType("AWS::DocDBElastic::Cluster"),
		model.CloudResourceType("AWS::DynamoDB::GlobalTable"),
		model.CloudResourceType("AWS::DynamoDB::Table"),
		model.CloudResourceType("AWS::EC2::CapacityReservation"),
		model.CloudResourceType("AWS::EC2::CapacityReservationFleet"),
		model.CloudResourceType("AWS::EC2::CarrierGateway"),
		model.CloudResourceType("AWS::EC2::CustomerGateway"),
		model.CloudResourceType("AWS::EC2::DHCPOptions"),
		model.CloudResourceType("AWS::EC2::EC2Fleet"),
		model.CloudResourceType("AWS::EC2::EgressOnlyInternetGateway"),
		model.CloudResourceType("AWS::EC2::EIP"),
		model.CloudResourceType("AWS::EC2::EIPAssociation"),
		model.CloudResourceType("AWS::EC2::FlowLog"),
		model.CloudResourceType("AWS::EC2::Host"),
		model.AWSEC2Instance,
		model.CloudResourceType("AWS::EC2::InstanceConnectEndpoint"),
		model.CloudResourceType("AWS::EC2::InternetGateway"),
		model.CloudResourceType("AWS::EC2::IPAM"),
		model.CloudResourceType("AWS::EC2::IPAMPool"),
		model.CloudResourceType("AWS::EC2::IPAMResourceDiscovery"),
		model.CloudResourceType("AWS::EC2::IPAMResourceDiscoveryAssociation"),
		model.CloudResourceType("AWS::EC2::IPAMScope"),
		model.CloudResourceType("AWS::EC2::KeyPair"),
		model.CloudResourceType("AWS::EC2::LaunchTemplate"),
		model.CloudResourceType("AWS::EC2::LocalGatewayRoute"),
		model.CloudResourceType("AWS::EC2::LocalGatewayRouteTable"),
		model.CloudResourceType("AWS::EC2::LocalGatewayRouteTableVirtualInterfaceGroupAssociation"),
		model.CloudResourceType("AWS::EC2::LocalGatewayRouteTableVPCAssociation"),
		model.CloudResourceType("AWS::EC2::NatGateway"),
		model.CloudResourceType("AWS::EC2::NetworkAcl"),
		model.CloudResourceType("AWS::EC2::NetworkInsightsAccessScope"),
		model.CloudResourceType("AWS::EC2::NetworkInsightsAccessScopeAnalysis"),
		model.CloudResourceType("AWS::EC2::NetworkInsightsAnalysis"),
		model.CloudResourceType("AWS::EC2::NetworkInsightsPath"),
		model.CloudResourceType("AWS::EC2::NetworkInterface"),
		model.CloudResourceType("AWS::EC2::NetworkInterfaceAttachment"),
		model.CloudResourceType("AWS::EC2::NetworkPerformanceMetricSubscription"),
		model.CloudResourceType("AWS::EC2::PlacementGroup"),
		model.CloudResourceType("AWS::EC2::PrefixList"),
		model.CloudResourceType("AWS::EC2::RouteTable"),
		model.CloudResourceType("AWS::EC2::SecurityGroup"),
		model.CloudResourceType("AWS::EC2::SecurityGroupEgress"),
		model.CloudResourceType("AWS::EC2::SecurityGroupIngress"),
		model.CloudResourceType("AWS::EC2::SecurityGroupVpcAssociation"),
		model.CloudResourceType("AWS::EC2::SnapshotBlockPublicAccess"),
		model.CloudResourceType("AWS::EC2::SpotFleet"),
		model.CloudResourceType("AWS::EC2::Subnet"),
		model.CloudResourceType("AWS::EC2::SubnetCidrBlock"),
		model.CloudResourceType("AWS::EC2::SubnetNetworkAclAssociation"),
		model.CloudResourceType("AWS::EC2::SubnetRouteTableAssociation"),
		model.CloudResourceType("AWS::EC2::TransitGateway"),
		model.CloudResourceType("AWS::EC2::TransitGatewayAttachment"),
		model.CloudResourceType("AWS::EC2::TransitGatewayConnect"),
		model.CloudResourceType("AWS::EC2::TransitGatewayMulticastDomain"),
		model.CloudResourceType("AWS::EC2::TransitGatewayPeeringAttachment"),
		model.CloudResourceType("AWS::EC2::TransitGatewayRouteTable"),
		model.CloudResourceType("AWS::EC2::TransitGatewayVpcAttachment"),
		model.CloudResourceType("AWS::EC2::VerifiedAccessEndpoint"),
		model.CloudResourceType("AWS::EC2::VerifiedAccessGroup"),
		model.CloudResourceType("AWS::EC2::VerifiedAccessInstance"),
		model.CloudResourceType("AWS::EC2::VerifiedAccessTrustProvider"),
		model.CloudResourceType("AWS::EC2::Volume"),
		model.CloudResourceType("AWS::EC2::VolumeAttachment"),
		model.CloudResourceType("AWS::EC2::VPC"),
		model.CloudResourceType("AWS::EC2::VPCDHCPOptionsAssociation"),
		model.CloudResourceType("AWS::EC2::VPCEndpoint"),
		model.CloudResourceType("AWS::EC2::VPCEndpointConnectionNotification"),
		model.CloudResourceType("AWS::EC2::VPCEndpointService"),
		model.CloudResourceType("AWS::EC2::VPCEndpointServicePermissions"),
		model.CloudResourceType("AWS::EC2::VPCGatewayAttachment"),
		model.CloudResourceType("AWS::EC2::VPCPeeringConnection"),
		model.CloudResourceType("AWS::EC2::VPNConnection"),
		model.CloudResourceType("AWS::EC2::VPNConnectionRoute"),
		model.CloudResourceType("AWS::EC2::VPNGateway"),
		model.AWSEcrPublicRepository,
		model.CloudResourceType("AWS::ECR::PullThroughCacheRule"),
		model.CloudResourceType("AWS::ECR::RegistryPolicy"),
		model.CloudResourceType("AWS::ECR::ReplicationConfiguration"),
		model.AWSEcrRepository,
		model.CloudResourceType("AWS::ECR::RepositoryCreationTemplate"),
		model.CloudResourceType("AWS::ECS::CapacityProvider"),
		model.CloudResourceType("AWS::ECS::Cluster"),
		model.CloudResourceType("AWS::ECS::ClusterCapacityProviderAssociations"),
		model.CloudResourceType("AWS::ECS::Service"),
		model.CloudResourceType("AWS::ECS::TaskDefinition"),
		model.CloudResourceType("AWS::EFS::AccessPoint"),
		model.CloudResourceType("AWS::EFS::FileSystem"),
		model.CloudResourceType("AWS::EKS::Cluster"),
		model.CloudResourceType("AWS::ElastiCache::GlobalReplicationGroup"),
		model.CloudResourceType("AWS::ElastiCache::ParameterGroup"),
		model.CloudResourceType("AWS::ElastiCache::ServerlessCache"),
		model.CloudResourceType("AWS::ElastiCache::SubnetGroup"),
		model.CloudResourceType("AWS::ElastiCache::User"),
		model.CloudResourceType("AWS::ElastiCache::UserGroup"),
		model.CloudResourceType("AWS::ElasticBeanstalk::Application"),
		model.CloudResourceType("AWS::ElasticBeanstalk::ApplicationVersion"),
		model.CloudResourceType("AWS::ElasticBeanstalk::ConfigurationTemplate"),
		model.CloudResourceType("AWS::ElasticBeanstalk::Environment"),
		model.CloudResourceType("AWS::ElasticLoadBalancingV2::LoadBalancer"),
		model.CloudResourceType("AWS::ElasticLoadBalancingV2::TargetGroup"),
		model.CloudResourceType("AWS::ElasticLoadBalancingV2::TrustStore"),
		model.CloudResourceType("AWS::EMR::SecurityConfiguration"),
		model.CloudResourceType("AWS::EMR::Studio"),
		model.CloudResourceType("AWS::EMR::StudioSessionMapping"),
		model.CloudResourceType("AWS::EMR::WALWorkspace"),
		model.CloudResourceType("AWS::EMRContainers::VirtualCluster"),
		model.CloudResourceType("AWS::EMRServerless::Application"),
		model.CloudResourceType("AWS::EntityResolution::IdMappingWorkflow"),
		model.CloudResourceType("AWS::EntityResolution::IdNamespace"),
		model.CloudResourceType("AWS::EntityResolution::MatchingWorkflow"),
		model.CloudResourceType("AWS::EntityResolution::SchemaMapping"),
		model.CloudResourceType("AWS::Events::ApiDestination"),
		model.CloudResourceType("AWS::Events::Archive"),
		model.CloudResourceType("AWS::Events::Connection"),
		model.CloudResourceType("AWS::Events::Endpoint"),
		model.CloudResourceType("AWS::Events::EventBus"),
		model.CloudResourceType("AWS::Events::Rule"),
		model.CloudResourceType("AWS::EventSchemas::Discoverer"),
		model.CloudResourceType("AWS::EventSchemas::Registry"),
		model.CloudResourceType("AWS::FinSpace::Environment"),
		model.CloudResourceType("AWS::FIS::ExperimentTemplate"),
		model.CloudResourceType("AWS::Forecast::Dataset"),
		model.CloudResourceType("AWS::Forecast::DatasetGroup"),
		model.CloudResourceType("AWS::FraudDetector::Detector"),
		model.CloudResourceType("AWS::FraudDetector::EntityType"),
		model.CloudResourceType("AWS::FraudDetector::EventType"),
		model.CloudResourceType("AWS::FraudDetector::Label"),
		model.CloudResourceType("AWS::FraudDetector::List"),
		model.CloudResourceType("AWS::FraudDetector::Outcome"),
		model.CloudResourceType("AWS::FraudDetector::Variable"),
		model.CloudResourceType("AWS::FSx::DataRepositoryAssociation"),
		model.CloudResourceType("AWS::GameLift::Alias"),
		model.CloudResourceType("AWS::GameLift::Build"),
		model.CloudResourceType("AWS::GameLift::ContainerFleet"),
		model.CloudResourceType("AWS::GameLift::ContainerGroupDefinition"),
		model.CloudResourceType("AWS::GameLift::Fleet"),
		model.CloudResourceType("AWS::GameLift::GameServerGroup"),
		model.CloudResourceType("AWS::GameLift::GameSessionQueue"),
		model.CloudResourceType("AWS::GameLift::Location"),
		model.CloudResourceType("AWS::GameLift::Script"),
		model.CloudResourceType("AWS::GlobalAccelerator::Accelerator"),
		model.CloudResourceType("AWS::GlobalAccelerator::CrossAccountAttachment"),
		model.CloudResourceType("AWS::Glue::Crawler"),
		model.CloudResourceType("AWS::Glue::Database"),
		model.CloudResourceType("AWS::Glue::Job"),
		model.CloudResourceType("AWS::Glue::Registry"),
		model.CloudResourceType("AWS::Glue::Schema"),
		model.CloudResourceType("AWS::Glue::Trigger"),
		model.CloudResourceType("AWS::Glue::UsageProfile"),
		model.CloudResourceType("AWS::Grafana::Workspace"),
		model.CloudResourceType("AWS::GreengrassV2::Deployment"),
		model.CloudResourceType("AWS::GroundStation::Config"),
		model.CloudResourceType("AWS::GroundStation::DataflowEndpointGroup"),
		model.CloudResourceType("AWS::GroundStation::MissionProfile"),
		model.CloudResourceType("AWS::GuardDuty::Detector"),
		model.CloudResourceType("AWS::GuardDuty::MalwareProtectionPlan"),
		model.CloudResourceType("AWS::HealthImaging::Datastore"),
		model.CloudResourceType("AWS::HealthLake::FHIRDatastore"),
		model.AWSGroup,
		model.CloudResourceType("AWS::IAM::InstanceProfile"),
		model.CloudResourceType("AWS::IAM::ManagedPolicy"),
		model.CloudResourceType("AWS::IAM::OIDCProvider"),
		model.AWSRole,
		model.CloudResourceType("AWS::IAM::SAMLProvider"),
		model.CloudResourceType("AWS::IAM::ServerCertificate"),
		model.AWSUser,
		model.CloudResourceType("AWS::IAM::VirtualMFADevice"),
		model.CloudResourceType("AWS::ImageBuilder::ContainerRecipe"),
		model.CloudResourceType("AWS::ImageBuilder::DistributionConfiguration"),
		model.CloudResourceType("AWS::ImageBuilder::ImagePipeline"),
		model.CloudResourceType("AWS::ImageBuilder::ImageRecipe"),
		model.CloudResourceType("AWS::ImageBuilder::InfrastructureConfiguration"),
		model.CloudResourceType("AWS::ImageBuilder::LifecyclePolicy"),
		model.CloudResourceType("AWS::Inspector::AssessmentTarget"),
		model.CloudResourceType("AWS::Inspector::AssessmentTemplate"),
		model.CloudResourceType("AWS::InspectorV2::Filter"),
		model.CloudResourceType("AWS::InternetMonitor::Monitor"),
		model.CloudResourceType("AWS::IoT::AccountAuditConfiguration"),
		model.CloudResourceType("AWS::IoT::Authorizer"),
		model.CloudResourceType("AWS::IoT::BillingGroup"),
		model.CloudResourceType("AWS::IoT::CACertificate"),
		model.CloudResourceType("AWS::IoT::Certificate"),
		model.CloudResourceType("AWS::IoT::CertificateProvider"),
		model.CloudResourceType("AWS::IoT::CustomMetric"),
		model.CloudResourceType("AWS::IoT::Dimension"),
		model.CloudResourceType("AWS::IoT::DomainConfiguration"),
		model.CloudResourceType("AWS::IoT::FleetMetric"),
		model.CloudResourceType("AWS::IoT::JobTemplate"),
		model.CloudResourceType("AWS::IoT::Logging"),
		model.CloudResourceType("AWS::IoT::MitigationAction"),
		model.CloudResourceType("AWS::IoT::Policy"),
		model.CloudResourceType("AWS::IoT::ProvisioningTemplate"),
		model.CloudResourceType("AWS::IoT::ResourceSpecificLogging"),
		model.CloudResourceType("AWS::IoT::RoleAlias"),
		model.CloudResourceType("AWS::IoT::ScheduledAudit"),
		model.CloudResourceType("AWS::IoT::SecurityProfile"),
		model.CloudResourceType("AWS::IoT::SoftwarePackage"),
		model.CloudResourceType("AWS::IoT::Thing"),
		model.CloudResourceType("AWS::IoT::ThingGroup"),
		model.CloudResourceType("AWS::IoT::TopicRule"),
		model.CloudResourceType("AWS::IoT::TopicRuleDestination"),
		model.CloudResourceType("AWS::IoTAnalytics::Channel"),
		model.CloudResourceType("AWS::IoTAnalytics::Dataset"),
		model.CloudResourceType("AWS::IoTAnalytics::Datastore"),
		model.CloudResourceType("AWS::IoTAnalytics::Pipeline"),
		model.CloudResourceType("AWS::IoTCoreDeviceAdvisor::SuiteDefinition"),
		model.CloudResourceType("AWS::IoTEvents::AlarmModel"),
		model.CloudResourceType("AWS::IoTEvents::DetectorModel"),
		model.CloudResourceType("AWS::IoTEvents::Input"),
		model.CloudResourceType("AWS::IoTFleetWise::Campaign"),
		model.CloudResourceType("AWS::IoTFleetWise::DecoderManifest"),
		model.CloudResourceType("AWS::IoTFleetWise::Fleet"),
		model.CloudResourceType("AWS::IoTFleetWise::ModelManifest"),
		model.CloudResourceType("AWS::IoTFleetWise::SignalCatalog"),
		model.CloudResourceType("AWS::IoTFleetWise::Vehicle"),
		model.CloudResourceType("AWS::IoTSiteWise::Asset"),
		model.CloudResourceType("AWS::IoTSiteWise::AssetModel"),
		model.CloudResourceType("AWS::IoTSiteWise::Gateway"),
		model.CloudResourceType("AWS::IoTSiteWise::Portal"),
		model.CloudResourceType("AWS::IoTTwinMaker::Workspace"),
		model.CloudResourceType("AWS::IoTWireless::Destination"),
		model.CloudResourceType("AWS::IoTWireless::DeviceProfile"),
		model.CloudResourceType("AWS::IoTWireless::FuotaTask"),
		model.CloudResourceType("AWS::IoTWireless::MulticastGroup"),
		model.CloudResourceType("AWS::IoTWireless::NetworkAnalyzerConfiguration"),
		model.CloudResourceType("AWS::IoTWireless::PartnerAccount"),
		model.CloudResourceType("AWS::IoTWireless::ServiceProfile"),
		model.CloudResourceType("AWS::IoTWireless::TaskDefinition"),
		model.CloudResourceType("AWS::IoTWireless::WirelessDevice"),
		model.CloudResourceType("AWS::IoTWireless::WirelessDeviceImportTask"),
		model.CloudResourceType("AWS::IoTWireless::WirelessGateway"),
		model.CloudResourceType("AWS::IVS::Channel"),
		model.CloudResourceType("AWS::IVS::EncoderConfiguration"),
		model.CloudResourceType("AWS::IVS::PlaybackKeyPair"),
		model.CloudResourceType("AWS::IVS::PlaybackRestrictionPolicy"),
		model.CloudResourceType("AWS::IVS::PublicKey"),
		model.CloudResourceType("AWS::IVS::RecordingConfiguration"),
		model.CloudResourceType("AWS::IVS::Stage"),
		model.CloudResourceType("AWS::IVS::StorageConfiguration"),
		model.CloudResourceType("AWS::IVSChat::LoggingConfiguration"),
		model.CloudResourceType("AWS::IVSChat::Room"),
		model.CloudResourceType("AWS::KafkaConnect::Connector"),
		model.CloudResourceType("AWS::KafkaConnect::CustomPlugin"),
		model.CloudResourceType("AWS::KafkaConnect::WorkerConfiguration"),
		model.CloudResourceType("AWS::Kendra::Index"),
		model.CloudResourceType("AWS::KendraRanking::ExecutionPlan"),
		model.CloudResourceType("AWS::Kinesis::Stream"),
		model.CloudResourceType("AWS::KinesisAnalyticsV2::Application"),
		model.CloudResourceType("AWS::KinesisFirehose::DeliveryStream"),
		model.CloudResourceType("AWS::KMS::Alias"),
		model.CloudResourceType("AWS::KMS::Key"),
		model.CloudResourceType("AWS::KMS::ReplicaKey"),
		model.CloudResourceType("AWS::LakeFormation::DataCellsFilter"),
		model.CloudResourceType("AWS::LakeFormation::Tag"),
		model.CloudResourceType("AWS::Lambda::CodeSigningConfig"),
		model.CloudResourceType("AWS::Lambda::EventSourceMapping"),
		model.AWSLambdaFunction,
		model.CloudResourceType("AWS::LaunchWizard::Deployment"),
		model.CloudResourceType("AWS::Lex::Bot"),
		model.CloudResourceType("AWS::Lightsail::Alarm"),
		model.CloudResourceType("AWS::Lightsail::Bucket"),
		model.CloudResourceType("AWS::Lightsail::Certificate"),
		model.CloudResourceType("AWS::Lightsail::Container"),
		model.CloudResourceType("AWS::Lightsail::Database"),
		model.CloudResourceType("AWS::Lightsail::Disk"),
		model.CloudResourceType("AWS::Lightsail::Distribution"),
		model.CloudResourceType("AWS::Lightsail::Instance"),
		model.CloudResourceType("AWS::Lightsail::LoadBalancer"),
		model.CloudResourceType("AWS::Lightsail::StaticIp"),
		model.CloudResourceType("AWS::Location::APIKey"),
		model.CloudResourceType("AWS::Location::GeofenceCollection"),
		model.CloudResourceType("AWS::Location::Map"),
		model.CloudResourceType("AWS::Location::PlaceIndex"),
		model.CloudResourceType("AWS::Location::RouteCalculator"),
		model.CloudResourceType("AWS::Location::Tracker"),
		model.CloudResourceType("AWS::Logs::Delivery"),
		model.CloudResourceType("AWS::Logs::DeliveryDestination"),
		model.CloudResourceType("AWS::Logs::DeliverySource"),
		model.CloudResourceType("AWS::Logs::Destination"),
		model.CloudResourceType("AWS::Logs::LogAnomalyDetector"),
		model.CloudResourceType("AWS::Logs::LogGroup"),
		model.CloudResourceType("AWS::Logs::MetricFilter"),
		model.CloudResourceType("AWS::Logs::QueryDefinition"),
		model.CloudResourceType("AWS::Logs::ResourcePolicy"),
		model.CloudResourceType("AWS::LookoutEquipment::InferenceScheduler"),
		model.CloudResourceType("AWS::LookoutMetrics::Alert"),
		model.CloudResourceType("AWS::LookoutMetrics::AnomalyDetector"),
		model.CloudResourceType("AWS::LookoutVision::Project"),
		model.CloudResourceType("AWS::M2::Application"),
		model.CloudResourceType("AWS::M2::Environment"),
		model.CloudResourceType("AWS::Macie::Session"),
		model.CloudResourceType("AWS::ManagedBlockchain::Accessor"),
		model.CloudResourceType("AWS::MediaConnect::Bridge"),
		model.CloudResourceType("AWS::MediaConnect::Flow"),
		model.CloudResourceType("AWS::MediaConnect::Gateway"),
		model.CloudResourceType("AWS::MediaLive::CloudWatchAlarmTemplate"),
		model.CloudResourceType("AWS::MediaLive::CloudWatchAlarmTemplateGroup"),
		model.CloudResourceType("AWS::MediaLive::EventBridgeRuleTemplate"),
		model.CloudResourceType("AWS::MediaLive::EventBridgeRuleTemplateGroup"),
		model.CloudResourceType("AWS::MediaLive::Multiplex"),
		model.CloudResourceType("AWS::MediaLive::SignalMap"),
		model.CloudResourceType("AWS::MediaPackage::Channel"),
		model.CloudResourceType("AWS::MediaPackage::OriginEndpoint"),
		model.CloudResourceType("AWS::MediaPackage::PackagingGroup"),
		model.CloudResourceType("AWS::MediaPackageV2::ChannelGroup"),
		model.CloudResourceType("AWS::MediaTailor::Channel"),
		model.CloudResourceType("AWS::MediaTailor::PlaybackConfiguration"),
		model.CloudResourceType("AWS::MediaTailor::SourceLocation"),
		model.CloudResourceType("AWS::MemoryDB::ACL"),
		model.CloudResourceType("AWS::MemoryDB::Cluster"),
		model.CloudResourceType("AWS::MemoryDB::ParameterGroup"),
		model.CloudResourceType("AWS::MemoryDB::SubnetGroup"),
		model.CloudResourceType("AWS::MemoryDB::User"),
		model.CloudResourceType("AWS::MSK::Cluster"),
		model.CloudResourceType("AWS::MSK::Configuration"),
		model.CloudResourceType("AWS::MSK::Replicator"),
		model.CloudResourceType("AWS::MSK::ServerlessCluster"),
		model.CloudResourceType("AWS::MSK::VpcConnection"),
		model.CloudResourceType("AWS::MWAA::Environment"),
		model.CloudResourceType("AWS::Neptune::DBCluster"),
		model.CloudResourceType("AWS::NeptuneGraph::Graph"),
		model.CloudResourceType("AWS::NetworkFirewall::Firewall"),
		model.CloudResourceType("AWS::NetworkFirewall::FirewallPolicy"),
		model.CloudResourceType("AWS::NetworkFirewall::RuleGroup"),
		model.CloudResourceType("AWS::NetworkFirewall::TLSInspectionConfiguration"),
		model.CloudResourceType("AWS::NetworkManager::ConnectAttachment"),
		model.CloudResourceType("AWS::NetworkManager::ConnectPeer"),
		model.CloudResourceType("AWS::NetworkManager::CoreNetwork"),
		model.CloudResourceType("AWS::NetworkManager::GlobalNetwork"),
		model.CloudResourceType("AWS::NetworkManager::SiteToSiteVpnAttachment"),
		model.CloudResourceType("AWS::NetworkManager::TransitGatewayPeering"),
		model.CloudResourceType("AWS::NetworkManager::TransitGatewayRouteTableAttachment"),
		model.CloudResourceType("AWS::NetworkManager::VpcAttachment"),
		model.CloudResourceType("AWS::Oam::Link"),
		model.CloudResourceType("AWS::Oam::Sink"),
		model.CloudResourceType("AWS::Omics::AnnotationStore"),
		model.CloudResourceType("AWS::Omics::ReferenceStore"),
		model.CloudResourceType("AWS::Omics::RunGroup"),
		model.CloudResourceType("AWS::Omics::SequenceStore"),
		model.CloudResourceType("AWS::Omics::VariantStore"),
		model.CloudResourceType("AWS::Omics::Workflow"),
		model.CloudResourceType("AWS::OpenSearchServerless::Collection"),
		model.CloudResourceType("AWS::OpenSearchServerless::VpcEndpoint"),
		model.CloudResourceType("AWS::OpenSearchService::Application"),
		model.CloudResourceType("AWS::Organizations::Organization"),
		model.CloudResourceType("AWS::OSIS::Pipeline"),
		model.CloudResourceType("AWS::Panorama::ApplicationInstance"),
		model.CloudResourceType("AWS::Panorama::Package"),
		model.CloudResourceType("AWS::PaymentCryptography::Alias"),
		model.CloudResourceType("AWS::PaymentCryptography::Key"),
		model.CloudResourceType("AWS::PCAConnectorAD::Connector"),
		model.CloudResourceType("AWS::PCAConnectorAD::DirectoryRegistration"),
		model.CloudResourceType("AWS::PCAConnectorSCEP::Connector"),
		model.CloudResourceType("AWS::Personalize::Dataset"),
		model.CloudResourceType("AWS::Personalize::DatasetGroup"),
		model.CloudResourceType("AWS::Personalize::Schema"),
		model.CloudResourceType("AWS::Personalize::Solution"),
		model.CloudResourceType("AWS::Pinpoint::InAppTemplate"),
		model.CloudResourceType("AWS::Pipes::Pipe"),
		model.CloudResourceType("AWS::Proton::EnvironmentAccountConnection"),
		model.CloudResourceType("AWS::Proton::EnvironmentTemplate"),
		model.CloudResourceType("AWS::Proton::ServiceTemplate"),
		model.CloudResourceType("AWS::QBusiness::Application"),
		model.CloudResourceType("AWS::RAM::Permission"),
		model.CloudResourceType("AWS::RDS::CustomDBEngineVersion"),
		model.CloudResourceType("AWS::RDS::DBCluster"),
		model.CloudResourceType("AWS::RDS::DBClusterParameterGroup"),
		model.AWSRDSInstance,
		model.CloudResourceType("AWS::RDS::DBParameterGroup"),
		model.CloudResourceType("AWS::RDS::DBProxy"),
		model.CloudResourceType("AWS::RDS::DBProxyEndpoint"),
		model.CloudResourceType("AWS::RDS::DBShardGroup"),
		model.CloudResourceType("AWS::RDS::DBSubnetGroup"),
		model.CloudResourceType("AWS::RDS::EventSubscription"),
		model.CloudResourceType("AWS::RDS::GlobalCluster"),
		model.CloudResourceType("AWS::RDS::Integration"),
		model.CloudResourceType("AWS::RDS::OptionGroup"),
		model.CloudResourceType("AWS::Redshift::Cluster"),
		model.CloudResourceType("AWS::Redshift::ClusterParameterGroup"),
		model.CloudResourceType("AWS::Redshift::ClusterSubnetGroup"),
		model.CloudResourceType("AWS::Redshift::EndpointAccess"),
		model.CloudResourceType("AWS::Redshift::EndpointAuthorization"),
		model.CloudResourceType("AWS::Redshift::EventSubscription"),
		model.CloudResourceType("AWS::Redshift::Integration"),
		model.CloudResourceType("AWS::Redshift::ScheduledAction"),
		model.CloudResourceType("AWS::RedshiftServerless::Namespace"),
		model.CloudResourceType("AWS::RedshiftServerless::Workgroup"),
		model.CloudResourceType("AWS::RefactorSpaces::Environment"),
		model.CloudResourceType("AWS::Rekognition::Collection"),
		model.CloudResourceType("AWS::Rekognition::Project"),
		model.CloudResourceType("AWS::Rekognition::StreamProcessor"),
		model.CloudResourceType("AWS::ResilienceHub::App"),
		model.CloudResourceType("AWS::ResilienceHub::ResiliencyPolicy"),
		model.CloudResourceType("AWS::ResourceExplorer2::Index"),
		model.CloudResourceType("AWS::ResourceExplorer2::View"),
		model.CloudResourceType("AWS::ResourceGroups::Group"),
		model.CloudResourceType("AWS::RoboMaker::RobotApplication"),
		model.CloudResourceType("AWS::RoboMaker::SimulationApplication"),
		model.CloudResourceType("AWS::RolesAnywhere::CRL"),
		model.CloudResourceType("AWS::RolesAnywhere::Profile"),
		model.CloudResourceType("AWS::RolesAnywhere::TrustAnchor"),
		model.CloudResourceType("AWS::Route53::CidrCollection"),
		model.CloudResourceType("AWS::Route53::DNSSEC"),
		model.CloudResourceType("AWS::Route53::HealthCheck"),
		model.CloudResourceType("AWS::Route53::HostedZone"),
		model.CloudResourceType("AWS::Route53::KeySigningKey"),
		model.CloudResourceType("AWS::Route53Profiles::Profile"),
		model.CloudResourceType("AWS::Route53Profiles::ProfileAssociation"),
		model.CloudResourceType("AWS::Route53RecoveryControl::Cluster"),
		model.CloudResourceType("AWS::Route53RecoveryControl::ControlPanel"),
		model.CloudResourceType("AWS::Route53RecoveryReadiness::Cell"),
		model.CloudResourceType("AWS::Route53RecoveryReadiness::ReadinessCheck"),
		model.CloudResourceType("AWS::Route53RecoveryReadiness::RecoveryGroup"),
		model.CloudResourceType("AWS::Route53RecoveryReadiness::ResourceSet"),
		model.CloudResourceType("AWS::Route53Resolver::FirewallDomainList"),
		model.CloudResourceType("AWS::Route53Resolver::FirewallRuleGroup"),
		model.CloudResourceType("AWS::Route53Resolver::FirewallRuleGroupAssociation"),
		model.CloudResourceType("AWS::Route53Resolver::OutpostResolver"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverConfig"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverDNSSECConfig"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverQueryLoggingConfig"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverRule"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverRuleAssociation"),
		model.CloudResourceType("AWS::RUM::AppMonitor"),
		model.CloudResourceType("AWS::S3::AccessGrantsInstance"),
		model.CloudResourceType("AWS::S3::AccessPoint"),
		model.AWSS3Bucket,
		model.CloudResourceType("AWS::S3::BucketPolicy"),
		model.CloudResourceType("AWS::S3::MultiRegionAccessPoint"),
		model.CloudResourceType("AWS::S3::StorageLens"),
		model.CloudResourceType("AWS::S3::StorageLensGroup"),
		model.CloudResourceType("AWS::S3Express::BucketPolicy"),
		model.CloudResourceType("AWS::S3Express::DirectoryBucket"),
		model.CloudResourceType("AWS::S3ObjectLambda::AccessPoint"),
		model.CloudResourceType("AWS::S3Outposts::Endpoint"),
		model.CloudResourceType("AWS::SageMaker::App"),
		model.CloudResourceType("AWS::SageMaker::AppImageConfig"),
		model.CloudResourceType("AWS::SageMaker::Cluster"),
		model.CloudResourceType("AWS::SageMaker::DataQualityJobDefinition"),
		model.CloudResourceType("AWS::SageMaker::Domain"),
		model.CloudResourceType("AWS::SageMaker::FeatureGroup"),
		model.CloudResourceType("AWS::SageMaker::Image"),
		model.CloudResourceType("AWS::SageMaker::InferenceComponent"),
		model.CloudResourceType("AWS::SageMaker::InferenceExperiment"),
		model.CloudResourceType("AWS::SageMaker::MlflowTrackingServer"),
		model.CloudResourceType("AWS::SageMaker::ModelBiasJobDefinition"),
		model.CloudResourceType("AWS::SageMaker::ModelCard"),
		model.CloudResourceType("AWS::SageMaker::ModelExplainabilityJobDefinition"),
		model.CloudResourceType("AWS::SageMaker::ModelPackage"),
		model.CloudResourceType("AWS::SageMaker::ModelPackageGroup"),
		model.CloudResourceType("AWS::SageMaker::ModelQualityJobDefinition"),
		model.CloudResourceType("AWS::SageMaker::MonitoringSchedule"),
		model.CloudResourceType("AWS::SageMaker::Pipeline"),
		model.CloudResourceType("AWS::SageMaker::Project"),
		model.CloudResourceType("AWS::SageMaker::Space"),
		model.CloudResourceType("AWS::SageMaker::StudioLifecycleConfig"),
		model.CloudResourceType("AWS::SageMaker::UserProfile"),
		model.CloudResourceType("AWS::Scheduler::Schedule"),
		model.CloudResourceType("AWS::Scheduler::ScheduleGroup"),
		model.CloudResourceType("AWS::SecretsManager::ResourcePolicy"),
		model.CloudResourceType("AWS::SecretsManager::RotationSchedule"),
		model.CloudResourceType("AWS::SecretsManager::Secret"),
		model.CloudResourceType("AWS::SecretsManager::SecretTargetAttachment"),
		model.CloudResourceType("AWS::SecurityHub::Hub"),
		model.CloudResourceType("AWS::ServiceCatalog::ServiceAction"),
		model.CloudResourceType("AWS::ServiceCatalogAppRegistry::Application"),
		model.CloudResourceType("AWS::ServiceCatalogAppRegistry::AttributeGroup"),
		model.CloudResourceType("AWS::SES::ConfigurationSet"),
		model.CloudResourceType("AWS::SES::ContactList"),
		model.CloudResourceType("AWS::SES::DedicatedIpPool"),
		model.CloudResourceType("AWS::SES::EmailIdentity"),
		model.CloudResourceType("AWS::SES::MailManagerAddonInstance"),
		model.CloudResourceType("AWS::SES::MailManagerAddonSubscription"),
		model.CloudResourceType("AWS::SES::MailManagerArchive"),
		model.CloudResourceType("AWS::SES::MailManagerIngressPoint"),
		model.CloudResourceType("AWS::SES::MailManagerRelay"),
		model.CloudResourceType("AWS::SES::MailManagerRuleSet"),
		model.CloudResourceType("AWS::SES::MailManagerTrafficPolicy"),
		model.CloudResourceType("AWS::SES::Template"),
		model.CloudResourceType("AWS::Signer::SigningProfile"),
		model.CloudResourceType("AWS::SimSpaceWeaver::Simulation"),
		model.CloudResourceType("AWS::SNS::Subscription"),
		model.AWSSNSTopic,
		model.AWSSQSQueue,
		model.CloudResourceType("AWS::SSM::Association"),
		model.CloudResourceType("AWS::SSM::Document"),
		model.CloudResourceType("AWS::SSM::Parameter"),
		model.CloudResourceType("AWS::SSM::PatchBaseline"),
		model.CloudResourceType("AWS::SSM::ResourceDataSync"),
		model.CloudResourceType("AWS::SSM::ResourcePolicy"),
		model.CloudResourceType("AWS::SSMContacts::Contact"),
		model.CloudResourceType("AWS::SSMIncidents::ReplicationSet"),
		model.CloudResourceType("AWS::SSMIncidents::ResponsePlan"),
		model.CloudResourceType("AWS::SSMQuickSetup::ConfigurationManager"),
		model.CloudResourceType("AWS::SSO::Instance"),
		model.CloudResourceType("AWS::StepFunctions::Activity"),
		model.CloudResourceType("AWS::StepFunctions::StateMachine"),
		model.CloudResourceType("AWS::SupportApp::AccountAlias"),
		model.CloudResourceType("AWS::SupportApp::SlackChannelConfiguration"),
		model.CloudResourceType("AWS::SupportApp::SlackWorkspaceConfiguration"),
		model.CloudResourceType("AWS::Synthetics::Canary"),
		model.CloudResourceType("AWS::Synthetics::Group"),
		model.CloudResourceType("AWS::SystemsManagerSAP::Application"),
		model.CloudResourceType("AWS::Timestream::Database"),
		model.CloudResourceType("AWS::Timestream::InfluxDBInstance"),
		model.CloudResourceType("AWS::Timestream::ScheduledQuery"),
		model.CloudResourceType("AWS::Timestream::Table"),
		model.CloudResourceType("AWS::Transfer::Certificate"),
		model.CloudResourceType("AWS::Transfer::Connector"),
		model.CloudResourceType("AWS::Transfer::Profile"),
		model.CloudResourceType("AWS::Transfer::Server"),
		model.CloudResourceType("AWS::Transfer::Workflow"),
		model.CloudResourceType("AWS::VerifiedPermissions::PolicyStore"),
		model.CloudResourceType("AWS::VoiceID::Domain"),
		model.CloudResourceType("AWS::VpcLattice::Service"),
		model.CloudResourceType("AWS::VpcLattice::ServiceNetwork"),
		model.CloudResourceType("AWS::VpcLattice::TargetGroup"),
		model.CloudResourceType("AWS::WAFv2::LoggingConfiguration"),
		model.CloudResourceType("AWS::Wisdom::Assistant"),
		model.CloudResourceType("AWS::Wisdom::KnowledgeBase"),
		model.CloudResourceType("AWS::WorkSpaces::WorkspacesPool"),
		model.CloudResourceType("AWS::WorkSpacesThinClient::Environment"),
		model.CloudResourceType("AWS::WorkSpacesWeb::BrowserSettings"),
		model.CloudResourceType("AWS::WorkSpacesWeb::IpAccessSettings"),
		model.CloudResourceType("AWS::WorkSpacesWeb::NetworkSettings"),
		model.CloudResourceType("AWS::WorkSpacesWeb::Portal"),
		model.CloudResourceType("AWS::WorkSpacesWeb::TrustStore"),
		model.CloudResourceType("AWS::WorkSpacesWeb::UserAccessLoggingSettings"),
		model.CloudResourceType("AWS::WorkSpacesWeb::UserSettings"),
		model.CloudResourceType("AWS::XRay::Group"),
		model.CloudResourceType("AWS::XRay::ResourcePolicy"),
		model.CloudResourceType("AWS::XRay::SamplingRule"),
	}
}
