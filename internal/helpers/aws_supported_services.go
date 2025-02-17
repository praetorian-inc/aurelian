package helpers

func IsSupportedTypeInRegion(region, rtype string) bool {
	if unsupportedTypesInRegions[rtype] == nil {
		return true
	}
	for _, unsupportedRegion := range unsupportedTypesInRegions[rtype] {
		if region == unsupportedRegion {
			return false
		}
	}
	return true
}

var unsupportedTypesInRegions = map[string][]string{
	// Existing entries
	"AWS::ApiGateway::DomainName":           {"ap-northeast-3"},
	"AWS::ApiGatewayV2::VpcLink":            {"ap-northeast-3"},
	"AWS::CodePipeline::CustomActionType":   {"ap-northeast-3"},
	"AWS::GameLift::Alias":                  {"ap-northeast-3", "eu-north-1", "eu-west-3"},
	"AWS::GameLift::Build":                  {"ap-northeast-3", "eu-north-1", "eu-west-3"},
	"AWS::GameLift::Fleet":                  {"ap-northeast-3", "eu-north-1", "eu-west-3"},
	"AWS::IoT::Certificate":                 {"ap-northeast-3"},
	"AWS::IoT::Policy":                      {"ap-northeast-3"},
	"AWS::IoT::Thing":                       {"ap-northeast-3"},
	"AWS::IoT::TopicRule":                   {"ap-northeast-3"},
	"AWS::RoboMaker::RobotApplication":      {"ap-northeast-2", "ap-south-1", "ap-southeast-2"},
	"AWS::RoboMaker::SimulationApplication": {"ap-northeast-2", "ap-south-1", "ap-southeast-2"},

	// New entries from provided list
	"AWS::APS::Scraper":                     {"ap-northeast-3", "ca-central-1"},
	"AWS::APS::Workspace":                   {"ap-northeast-3", "ca-central-1"},
	"AWS::AppFlow::Connector":               {"ap-northeast-3", "eu-north-1"},
	"AWS::AppFlow::ConnectorProfile":        {"ap-northeast-3", "eu-north-1"},
	"AWS::AppFlow::Flow":                    {"ap-northeast-3", "eu-north-1"},
	"AWS::AppRunner::Service":               {"ap-northeast-2", "ap-northeast-3", "ca-central-1", "eu-north-1", "sa-east-1"},
	"AWS::AppRunner::VpcConnector":          {"ap-northeast-2", "ap-northeast-3", "ca-central-1", "eu-north-1", "sa-east-1"},
	"AWS::Athena::CapacityReservation":      {"ap-northeast-2", "ap-northeast-3", "ap-south-1", "ca-central-1", "eu-central-1", "eu-west-2", "eu-west-3"},
	"AWS::Bedrock::Agent":                   {"ap-northeast-3", "eu-north-1"},
	"AWS::CodeArtifact::Domain":             {"ap-northeast-2", "ap-northeast-3", "ca-central-1", "sa-east-1"},
	"AWS::CodeArtifact::Repository":         {"ap-northeast-2", "ap-northeast-3", "ca-central-1", "sa-east-1"},
	"AWS::CodeGuruProfiler::ProfilingGroup": {"ap-northeast-2", "ap-northeast-3", "ap-south-1", "ca-central-1", "eu-west-3", "sa-east-1"},
	"AWS::Comprehend::DocumentClassifier":   {"ap-northeast-3", "eu-north-1", "eu-west-3", "sa-east-1"},
	"AWS::Comprehend::Flywheel":             {"ap-northeast-3", "eu-north-1", "eu-west-3", "sa-east-1"},
	"AWS::Connect::Instance":                {"ap-northeast-3", "ap-south-1", "eu-north-1", "eu-west-1", "eu-west-3", "sa-east-1"},
	"AWS::DataBrew::Dataset":                {"ap-northeast-3"},
	"AWS::EC2::CarrierGateway":              {"ap-northeast-3", "ap-south-1", "ap-southeast-1", "eu-north-1", "sa-east-1"},
	"AWS::EC2::VerifiedAccessEndpoint":      {"ap-northeast-3", "eu-west-3"},
	"AWS::EMR::WALWorkspace":                {"ap-northeast-3", "ca-central-1", "eu-west-2", "eu-west-3"},
	"AWS::IoTAnalytics::Channel":            {"ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ca-central-1", "eu-north-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::IoTAnalytics::Dataset":            {"ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ca-central-1", "eu-north-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::IoTEvents::AlarmModel":            {"ap-northeast-3", "eu-north-1", "eu-west-3", "sa-east-1"},
	"AWS::IoTEvents::DetectorModel":         {"ap-northeast-3", "eu-north-1", "eu-west-3", "sa-east-1"},
	"AWS::IoTSiteWise::Asset":               {"ap-northeast-3", "eu-north-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::IoTSiteWise::AssetModel":          {"ap-northeast-3", "eu-north-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::IoTTwinMaker::Workspace":          {"ap-northeast-3", "ca-central-1", "eu-north-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::IVS::Channel":                     {"ap-northeast-3", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "eu-north-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::KafkaConnect::Connector":          {"ap-northeast-3"},
	"AWS::Kendra::Index":                    {"ap-northeast-2", "ap-northeast-3", "eu-central-1", "eu-north-1", "eu-west-3", "sa-east-1"},
	"AWS::Lambda::CodeSigningConfig":        {"ap-northeast-3"},
	"AWS::Lex::Bot":                         {"ap-northeast-3", "ap-south-1", "eu-north-1", "eu-west-3", "sa-east-1"},
	"AWS::Lightsail::Alarm":                 {"ap-northeast-3", "sa-east-1"},
	"AWS::Location::Map":                    {"ap-northeast-2", "ap-northeast-3", "eu-west-3"},
	"AWS::Location::PlaceIndex":             {"ap-northeast-2", "ap-northeast-3", "eu-west-3"},
	"AWS::Location::Tracker":                {"ap-northeast-2", "ap-northeast-3", "eu-west-3"},
	"AWS::MemoryDB::Cluster":                {"ap-northeast-3", "eu-west-3"},
	"AWS::MSK::ServerlessCluster":           {"ap-northeast-3", "sa-east-1"},
	"AWS::OpenSearchServerless::Collection": {"ap-northeast-3"},
	"AWS::OpenSearchService::Application":   {"ap-northeast-2", "ap-northeast-3", "eu-north-1"},
	"AWS::Personalize::Dataset":             {"ap-northeast-3", "eu-north-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::Personalize::DatasetGroup":        {"ap-northeast-3", "eu-north-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::RDS::CustomDBEngineVersion":       {"eu-west-3"},
	"AWS::RedshiftServerless::Namespace":    {"ap-northeast-3"},
	"AWS::RedshiftServerless::Workgroup":    {"ap-northeast-3"},
	"AWS::Rekognition::Collection":          {"ap-northeast-3", "eu-north-1", "eu-west-3", "sa-east-1"},
	"AWS::SageMaker::Cluster":               {"ap-northeast-2", "ap-northeast-3", "ca-central-1", "eu-west-3"},
	"AWS::SimSpaceWeaver::Simulation":       {"ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ca-central-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::Timestream::Database":             {"ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ca-central-1", "eu-north-1", "eu-west-2", "eu-west-3", "sa-east-1"},
	"AWS::VoiceID::Domain":                  {"ap-northeast-2", "ap-northeast-3", "ap-south-1", "eu-north-1", "eu-west-1", "eu-west-3", "sa-east-1"},
	"AWS::WorkSpaces::WorkspacesPool":       {"ap-northeast-3", "eu-north-1", "eu-west-3"},
}
