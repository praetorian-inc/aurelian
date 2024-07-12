package helpers

var serviceMap = map[string][]string{
	"AWS Key Management Service":                {"AWS::KMS::Key", "AWS::KMS::Alias", "AWS::KMS::ReplicaKey"},
	"AWS Secrets Manager":                       {"AWS::SecretsManager::Secret"},
	"Amazon Relational Database Service":        {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::RDS::DBProxyEndpoint", "AWS::RDS::DBProxy", "AWS::RDS::DBProxyTargetGroup", "AWS::RDS::DBProxyTarget", "AWS::RDS::DBClusterParameterGroup", "AWS::RDS::DBParameterGroup", "AWS::RDS::GlobalCluster", "AWS::RDS::Integration", "AWS::RDS::OptionGroup"},
	"Amazon Elastic Compute Cloud - Compute":    {"AWS::EC2::Instance", "AWS::EC2::Host", "AWS::EC2::ElasticGpu", "AWS::EC2::ElasticInferenceAccelerator", "AWS::EC2::SpotFleet", "AWS::EC2::SpotInstanceRequest", "AWS::EC2::SpotInstance", "AWS::EC2::DedicatedHost", "AWS::EC2::CapacityReservation"},
	"Amazon Elastic Block Store":                {"AWS::EBS::Volume", "AWS::EBS::Snapshot"},
	"Amazon Elastic File System":                {"AWS::EFS::FileSystem"},
	"Amazon Simple Storage Service":             {"AWS::S3::Bucket"},
	"Amazon Route 53":                           {"AWS::Route53::HostedZone", "AWS::Route53::RecordSet"},
	"Amazon Simple Notification Service":        {"AWS::SNS::Topic"},
	"Amazon Simple Queue Service":               {"AWS::SQS::Queue"},
	"Amazon Simple Email Service":               {"AWS::SES::Email"},
	"Amazon API Gateway":                        {"AWS::ApiGateway::RestApi"},
	"Amazon CloudWatch":                         {"AWS::CloudWatch::Alarm"},
	"Amazon DynamoDB":                           {"AWS::DynamoDB::Table"},
	"Amazon Elastic MapReduce":                  {"AWS::EMR::Cluster"},
	"Amazon Redshift":                           {"AWS::Redshift::Cluster"},
	"Amazon Elastic Load Balancing":             {"AWS::ElasticLoadBalancingV2::LoadBalancer"},
	"Amazon Elastic Container Service":          {"AWS::ECS::Cluster", "AWS::ECS::Service", "AWS::ECS::TaskDefinition"},
	"Amazon Elastic Kubernetes Service":         {"AWS::EKS::Cluster"},
	"Amazon Step Functions":                     {"AWS::StepFunctions::StateMachine"},
	"Amazon Simple Workflow Service":            {"AWS::SWF::Domain"},
	"Amazon Managed Streaming for Apache Kafka": {"AWS::MSK::Cluster"},
	"Amazon CloudFront":                         {"AWS::CloudFront::Distribution", "AWS::CloudFront::Function"},
	"Amazon Comprehend":                         {"AWS::Comprehend::DocumentClassifier", "AWS::Comprehend::Flywheel"},
	"AWS Config":                                {"AWS::Config::ConfigRule", "AWS::Config::StoredQuery", "AWS::Config::ConfigRuleAggregator", "AWS::Config::AggregationAuthorization"},
	"Amazon ElastiCache":                        {"AWS::ElastiCache::CacheCluster", "AWS::ElastiCache::ServerlessCache", "AWS::ElastiCache::User", "AWS::ElastiCache::SubnetGroup"},
	"Amazon Glacier":                            {}, //{"AWS::Glacier::Vault"},
	"Amazon Kinesis":                            {"AWS::Kinesis::Stream"},
	"Amazon Kinesis Firehose":                   {"AWS::KinesisFirehose::DeliveryStream"},
}

// ResolveService returns the service identifier based on the service friendly name
func ResolveCostExplorerService(friendlyName string) ([]string, bool) {
	serviceID, ok := serviceMap[friendlyName]
	return serviceID, ok
}
